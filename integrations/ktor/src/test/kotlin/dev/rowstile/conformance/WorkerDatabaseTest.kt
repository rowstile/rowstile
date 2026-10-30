package dev.rowstile.conformance

import dev.rowstile.Principal
import dev.rowstile.kotlin.transaction
import dev.rowstile.testing.WorkerDatabase
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.postgresql.ds.PGSimpleDataSource
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Check 12: each test JVM has a database of its own, copied from the migrated one, with the policy. */
class WorkerDatabaseTest {
    private fun projects(appUrl: String, who: Long): List<Long> = runBlocking {
        PGSimpleDataSource().apply { setURL(appUrl) }.transaction(Principal.user(who)) {
            createStatement().use { st ->
                st.executeQuery("SELECT id FROM app.projects ORDER BY id").use { rs ->
                    generateSequence { if (rs.next()) rs.getLong(1) else null }.toList()
                }
            }
        }
    }

    @Test
    @DisplayName("12: the framework's test database has the policy: a copy of the migrated one for each test JVM")
    fun perWorker() {
        // this JVM's (Surefire's fork number: two JVMs, two copies)
        val worker = System.getProperty("rowstile.worker")
        assertTrue(worker.matches(Regex("[12]")), worker)
        assertEquals(worker, WorkerDatabase.workerId())
        assertTrue(Conformance.WORKER.url().contains("/conf_tests_w$worker?"), Conformance.WORKER.url())
        assertTrue(Conformance.WORKER.appUrl().contains("/conf_tests_w$worker?user=conf_app"), Conformance.WORKER.appUrl())
        // the copy has the policy: the app's role reads under row-level security, as each user
        Conformance.seed()
        assertEquals(listOf(1L, 3L), projects(Conformance.WORKER.appUrl(), 1))
        assertEquals(listOf(2L, 3L), projects(Conformance.WORKER.appUrl(), 2))
    }
}
