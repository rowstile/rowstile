package dev.rowstile.conformance

import dev.rowstile.Authz
import dev.rowstile.Principal
import dev.rowstile.kotlin.calls
import dev.rowstile.kotlin.transaction
import kotlinx.coroutines.runBlocking
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import org.postgresql.ds.PGSimpleDataSource
import java.net.URLClassLoader
import java.nio.file.Files
import java.nio.file.Path
import java.sql.DriverManager
import kotlin.io.path.copyToRecursively
import kotlin.io.path.listDirectoryEntries
import kotlin.io.path.name
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Check 14: a policy change ships as the next migration, and the app's code works with the names the policy then
 * makes. On a database of its own, copied from the migrated test database.
 */
class PolicyChangeTest {
    private val db = "conf_tests_w" + System.getProperty("rowstile.worker", "0") + "_14"

    private fun url(name: String): String = Conformance.TESTS.replaceFirst("/conf_tests?", "/$name?")

    private fun sql(name: String, statement: String) {
        DriverManager.getConnection(url(name)).use { conn -> conn.createStatement().use { it.execute(statement) } }
    }

    @OptIn(kotlin.io.path.ExperimentalPathApi::class)
    @Test
    @DisplayName("14: after a policy change and a new migration, the app works with the new generated names")
    fun policyChange(@TempDir tmp: Path) {
        val work = tmp.resolve("app")
        for (part in listOf("db", "rowstile.toml", "src/main/resources/db/migration")) {
            Files.createDirectories(work.resolve(part).parent)
            GeneratedNamesTest.HERE.resolve(part).copyToRecursively(work.resolve(part), followLinks = false)
        }
        // the new names in a package of their own, beside the app's (which the tests' classes hold)
        val toml = work.resolve("rowstile.toml")
        toml.writeText(
            toml.readText().replace("src/main/java/dev/rowstile/conformance/AuthzNames.java", "src/main/java/check/AuthzNames.java"),
        )
        val policy = work.resolve("db/policy.authz")
        policy.writeText(policy.readText().replace("  can read = recipient\n", "  can read = recipient\n  can reply = recipient\n"))
        sql("postgres", "DROP DATABASE IF EXISTS $db WITH (FORCE)")
        sql("postgres", "CREATE DATABASE $db TEMPLATE conf_tests")
        try {
            val message = DriverManager.getConnection(url(db)).use { owner ->
                owner.createStatement().use { st ->
                    st.execute("INSERT INTO app.users VALUES (1, 'ann'), (2, 'bo')") // ann sends bo a message
                    st.executeQuery("INSERT INTO app.inbox (sender_id, recipient_id, body) VALUES (1, 2, 'hi') RETURNING id")
                        .use { it.next(); it.getLong(1) }
                }
            }
            // the next migration is numbered after the folder's last (Flyway's V<n>__)
            val migrations = work.resolve("src/main/resources/db/migration")
            val last = migrations.listDirectoryEntries("V*__*.sql").maxOf { it.name.substring(1, it.name.indexOf("__")).toInt() }
            val said = Kotlinc.rowstile(work, "migrate")
            assertTrue(said.contains("wrote src/main/resources/db/migration/V${last + 1}__authz_"), said)
            // Flyway migrates it, the way the app's start-up does
            Flyway.configure().dataSource(url(db), null, null).locations("filesystem:$migrations").load().migrate()
            Kotlinc.rowstile(work, "client")
            // the app's code, with the names the policy now makes: it names reply, and the database answers it
            val use = """
                package check

                import dev.rowstile.Authz
                import check.AuthzNames.MessagePermission

                class Reply : (Authz, Long) -> List<Boolean> {
                    override fun invoke(authz: Authz, message: Long): List<Boolean> =
                        listOf(authz.can(MessagePermission.REPLY, message), authz.can(MessagePermission.READ, message))
                }
            """.trimIndent()
            val names = Files.createDirectories(tmp.resolve("names"))
            val java = Kotlinc.java(names, work.resolve("src/main/java/check/AuthzNames.java"))
            assertTrue(java.ok, java.text)
            val out = Files.createDirectories(tmp.resolve("classes"))
            val kotlin = Kotlinc.kotlin(out, Kotlinc.write(out.resolve("check/Reply.kt"), use), more = listOf(names))
            assertTrue(kotlin.ok, kotlin.text)
            val app = PGSimpleDataSource().apply {
                setURL(url(db).replaceFirst("user=conf_owner&password=owner", "user=conf_app&password=app"))
            }
            URLClassLoader(arrayOf(out.toUri().toURL(), names.toUri().toURL()), javaClass.classLoader).use { loader ->
                @Suppress("UNCHECKED_CAST")
                val reply = loader.loadClass("check.Reply").getDeclaredConstructor().newInstance() as (Authz, Long) -> List<Boolean>
                runBlocking {
                    // bo, to whom it is sent, may reply; ann, who sent it, may not even read it
                    val said2 = listOf(
                        app.transaction(Principal.user(2)) { reply(calls, message) },
                        app.transaction(Principal.user(1)) { reply(calls, message) },
                    )
                    assertEquals(listOf(listOf(true, true), listOf(false, false)), said2)
                    // the names from before the change don't know reply: the SDK says to write them again
                    val stale = assertFailsWith<IllegalStateException> {
                        app.transaction(Principal.user(2)) { calls.perms(AuthzNames.MESSAGE, message) }
                    }
                    assertTrue(stale.message!!.contains("write the names again"), stale.message)
                }
            }
        } finally {
            sql("postgres", "DROP DATABASE IF EXISTS $db WITH (FORCE)")
        }
    }
}
