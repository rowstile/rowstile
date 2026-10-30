package dev.rowstile.conformance

import com.zaxxer.hikari.HikariDataSource
import dev.rowstile.conformance.Conformance.NOTES
import dev.rowstile.kotlin.errorCode
import io.ktor.server.testing.TestApplication
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import java.sql.SQLException
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** Check 4: the app with a pool of one connection (HikariCP's), which every request takes in turn. */
class PoolOfOneTest {
    @Test
    @DisplayName("4: with a pool of one connection, a request as ann, then one as bo: bo never sees ann's rows")
    fun poolOfOne() = runBlocking {
        Conformance.seed()
        lateinit var pool: HikariDataSource
        val app = TestApplication { application { pool = conformance(Conformance.settings.copy(poolSize = 1)) } }
        app.start()
        try {
            assertEquals(NOTES["1"], app.send("GET", "/notes", "1").ids())
            assertEquals(NOTES["2"], app.send("GET", "/notes", "2").ids())
            assertEquals(NOTES[""], app.send("GET", "/notes", null).ids())
            // a transaction that commits (a folder moved where it is): a rollback undoes even a session's settings
            assertEquals(200, app.send("PATCH", "/folders/2", "1", """{"parentId": 1}""").status)
            // each request signed in again, so the answers alone can't tell: the pool's one connection, as the last
            // request left it, in a transaction nobody signs in to, holds no one (a sign-in that outlived its
            // transaction would still be ann's here)
            assertEquals(1, pool.maximumPoolSize)
            pool.connection.use { conn ->
                conn.autoCommit = false
                conn.createStatement().use { st ->
                    val left = st.executeQuery("SELECT current_setting('authz.user_id', true)").use {
                        it.next()
                        it.getString(1)
                    }
                    assertTrue(left.isNullOrEmpty(), left)
                    val e = assertFailsWith<SQLException> { st.executeQuery("SELECT count(*) FROM app.notes") }
                    assertEquals("AZ701", e.errorCode()) // rowstile help AZ701
                }
                conn.rollback()
            }
        } finally {
            app.stop()
        }
    }
}
