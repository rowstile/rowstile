package dev.rowstile.conformance

import dev.rowstile.ConnectionProblem
import dev.rowstile.DatabaseError
import io.ktor.server.application.ApplicationStarted
import io.ktor.server.testing.TestApplication
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import java.sql.DriverManager
import java.sql.SQLException
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/** Check 13: the app doesn't start on a connection where the database would filter nothing. */
class StartupTest {
    /** Starts the app on [settings]: what it threw, if it didn't start; [served] says whether it did. */
    private fun start(settings: Settings, served: MutableList<String>): Throwable? {
        val app = TestApplication {
            application {
                monitor.subscribe(ApplicationStarted) { served.add("served") }
                conformance(settings)
            }
        }
        return try {
            runBlocking { app.start() }
            null
        } catch (e: Throwable) {
            e
        } finally {
            runBlocking { app.stop() }
        }
    }

    private inline fun <reified T : Throwable> cause(e: Throwable?): T =
        generateSequence(e) { it.cause }.filterIsInstance<T>().firstOrNull()
            ?: throw AssertionError("no ${T::class.simpleName} in $e", e)

    @Test
    @DisplayName("13: the app refuses to start on a connection that skips row-level security")
    fun refusesTheOwner() {
        val served = mutableListOf<String>()
        val owner = Conformance.settings.copy(appUrl = Conformance.WORKER.url())
        val problem = cause<ConnectionProblem>(start(owner, served))
        assertTrue(problem.message!!.contains("an owner skips row-level security"), problem.message)
        assertTrue(problem.problems().all { it.contains("conf_owner") }, problem.problems().toString())
        assertEquals(listOf(), served)
        // and on the app role's connection it starts
        assertEquals(null, start(Conformance.settings, served))
        assertEquals(listOf("served"), served)
    }

    @Test
    @DisplayName("13: ... nor on a database without the policy, which can't be asked")
    fun refusesNoPolicy() {
        val empty = "conf_empty_w" + System.getProperty("rowstile.worker", "0")
        val postgres = Conformance.TESTS.replaceFirst("/conf_tests?", "/postgres?")
        DriverManager.getConnection(postgres).use { conn ->
            conn.createStatement().use {
                it.execute("DROP DATABASE IF EXISTS $empty")
                it.execute("CREATE DATABASE $empty")
            }
        }
        try {
            // its owner migrates nothing (an empty folder), and the app role connects to it
            val url = Conformance.TESTS.replaceFirst("/conf_tests?", "/$empty?")
            val app = url.replace("user=conf_owner&password=owner", "user=conf_app&password=app")
            val error = cause<DatabaseError>(start(Settings(app, url, migrations = "filesystem:target/none"), mutableListOf()))
            assertIs<SQLException>(error.cause)
            assertTrue(error.message!!.contains("schema \"authz\" does not exist"), error.message)
        } finally {
            DriverManager.getConnection(postgres).use { conn ->
                conn.createStatement().use { it.execute("DROP DATABASE IF EXISTS $empty WITH (FORCE)") }
            }
        }
    }
}
