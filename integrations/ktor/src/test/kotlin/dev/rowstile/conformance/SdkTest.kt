package dev.rowstile.conformance

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import dev.rowstile.DatabaseError
import dev.rowstile.NotFound
import dev.rowstile.Principal
import dev.rowstile.Refused
import dev.rowstile.conformance.Conformance.WORKER
import dev.rowstile.conformance.Conformance.seed
import dev.rowstile.kotlin.ActingAs
import dev.rowstile.kotlin.actingFor
import dev.rowstile.kotlin.calls
import dev.rowstile.kotlin.errorCode
import dev.rowstile.kotlin.exposed.calls
import dev.rowstile.kotlin.exposed.expect
import dev.rowstile.kotlin.exposed.signIn
import dev.rowstile.kotlin.exposed.suspendTransaction
import dev.rowstile.kotlin.exposed.transaction
import dev.rowstile.kotlin.ktor.Rowstile
import dev.rowstile.kotlin.problem
import dev.rowstile.kotlin.refusal
import dev.rowstile.kotlin.testing.assertNotFound
import dev.rowstile.kotlin.testing.assertRefused
import dev.rowstile.kotlin.transaction
import io.ktor.server.application.install
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.server.testing.TestApplication
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.jetbrains.exposed.v1.core.eq
import org.jetbrains.exposed.v1.jdbc.Database
import org.jetbrains.exposed.v1.jdbc.JdbcTransaction
import org.jetbrains.exposed.v1.core.DatabaseConfig
import org.jetbrains.exposed.v1.jdbc.insert
import org.jetbrains.exposed.v1.jdbc.selectAll
import org.jetbrains.exposed.v1.jdbc.transactions.TransactionManager
import org.jetbrains.exposed.v1.jdbc.update
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.postgresql.ds.PGSimpleDataSource
import java.sql.SQLException
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/** The Kotlin SDK's own calls: over JDBC, in Exposed's transactions, its test helpers, and how it reads the answers. */
class SdkTest {
    private val app = PGSimpleDataSource().apply { setURL(WORKER.appUrl()) }
    private val db = Database.connect(app)

    @BeforeEach
    fun rows() = seed()

    private fun count(sql: String): suspend java.sql.Connection.() -> Long = {
        createStatement().use { st -> st.executeQuery(sql).use { it.next(); it.getLong(1) } }
    }

    @Test
    @DisplayName("a transaction signs in, commits what its block did, and rolls back what fails")
    fun transactions() = runBlocking {
        val pool = HikariDataSource(HikariConfig().apply {
            jdbcUrl = WORKER.appUrl()
            maximumPoolSize = 1
        })
        pool.use {
            assertEquals(1, pool.transaction(Principal.user(3)) {
                createStatement().use { it.executeUpdate("UPDATE app.notes SET body = 'better idea' WHERE id = 4") }
            })
            assertEquals(1L, pool.transaction(Principal.user(3), count("SELECT count(*) FROM app.notes WHERE body = 'better idea'")))
            // what fails is rolled back: the update, then a refusal
            val refused = assertFailsWith<Refused> {
                pool.transaction(Principal.user(3)) {
                    createStatement().use { it.executeUpdate("UPDATE app.notes SET body = 'gone' WHERE id = 4") }
                    calls.expect(createStatement().use { it.executeUpdate("UPDATE app.notes SET body = 'x' WHERE id = 1") },
                        "app.notes", "update", 1)
                }
            }
            assertEquals("permission denied: user 3 may not update row 1 of app.notes", refused.message)
            assertEquals(0L, pool.transaction(Principal.user(3), count("SELECT count(*) FROM app.notes WHERE body = 'gone'")))
            // a database error, the driver's: DatabaseError, which reads as any other
            val error = assertFailsWith<DatabaseError> { pool.transaction(Principal.NOBODY, count("SELECT nothing")) }
            assertEquals("42703", error.cause!!.sqlState)
            assertNull(error.problem())
            // inside, the code acts for who the transaction is signed in as; and the pool's one connection is left as
            // it was found, in auto-commit mode
            assertEquals(Principal.user(2), pool.transaction(Principal.user(2)) {
                delay(1) // wherever it resumes
                actingFor()
            })
            pool.connection.use { assertTrue(it.autoCommit) }
        }
        // a pool whose connections aren't in auto-commit mode (HikariCP's autoCommit = false): the same, and left so
        HikariDataSource(HikariConfig().apply {
            jdbcUrl = WORKER.appUrl()
            maximumPoolSize = 1
            isAutoCommit = false
        }).use { pool ->
            assertEquals(2L, pool.transaction(Principal.user(2), count("SELECT count(*) FROM app.projects")))
            pool.connection.use { assertFalse(it.autoCommit) }
        }
        // a pool that can't connect: DatabaseError too
        val nowhere = PGSimpleDataSource().apply { setURL("jdbc:postgresql://localhost:1/x?connectTimeout=1") }
        assertTrue(assertFailsWith<DatabaseError> { nowhere.transaction(Principal.NOBODY) { 1 } }.cause is SQLException)
    }

    @Test
    @DisplayName("Exposed's transactions, signed in: blocking, suspended, and the sign-in on its own")
    fun exposed() {
        assertEquals(listOf(1L, 3L), transaction(Principal.user(1), db) {
            Projects.selectAll().orderBy(Projects.id).map { it[Projects.id].value }
        })
        assertEquals(listOf("edit", "view"), transaction(Principal.user(2), db) {
            calls.perms(AuthzNames.NOTE, 2).map { it.permission() }
        })
        // on Exposed's default database, as an app with one has it
        TransactionManager.defaultDatabase = db
        assertEquals(2L, transaction(Principal.user(2)) { Projects.selectAll().count() })
        assertEquals(2L, runBlocking { suspendTransaction(Principal.user(2)) { Projects.selectAll().count() } })
        // in a transaction of Exposed's own, signed in by hand (nobody: only the public project)
        assertEquals(1L, org.jetbrains.exposed.v1.jdbc.transactions.transaction(db) {
            signIn(Principal.NOBODY)
            Projects.selectAll().count()
        })
        // a database without the policy can't sign in: DatabaseError, with the database's words
        val bare = Database.connect(PGSimpleDataSource().apply { setURL(Conformance.TESTS.replaceFirst("/conf_tests?", "/postgres?")) })
        val e = assertFailsWith<DatabaseError> { transaction(Principal.NOBODY, bare) { 1 } }
        assertTrue(e.message!!.contains("schema \"authz\" does not exist"), e.message)
    }

    /** Who the database transaction is signed in as, asked of the database. */
    private fun JdbcTransaction.signedIn(): String? =
        exec("SELECT current_setting('authz.user_id', true)") { rs -> rs.takeIf { it.next() }?.getString(1) }

    @Test
    @DisplayName("a transaction inside another: as the same principal it runs, as another it is refused before it runs")
    fun nested() {
        for (each in listOf(db, Database.connect(app, databaseConfig = DatabaseConfig { useNestedTransactions = true }))) {
            // the same user: the inner block runs in the outer transaction, and the outer is still that user's after
            val same = transaction(Principal.user(1), each) {
                val inner = transaction(Principal.user(1), each) { Projects.selectAll().count() }
                listOf(inner, Projects.selectAll().count(), signedIn())
            }
            assertEquals(listOf(2L, 2L, "1"), same)
            // someone else: refused before the block runs, and the outer transaction goes on as its user
            val ran = mutableListOf<String>()
            val other = transaction(Principal.user(1), each) {
                val refused = assertFailsWith<IllegalStateException> {
                    transaction(Principal.of("service", 1), each) { ran.add("inner") }
                }
                Notes.update({ Notes.id eq 1 }) { it[body] = "still ann's" }
                listOf(refused.message, signedIn(), Projects.selectAll().count())
            }
            assertEquals(listOf<String>(), ran)
            assertTrue(other[0].toString().contains("signed in as 1 already"), other[0].toString())
            assertTrue(other[0].toString().contains("service:1's work can't run inside it"), other[0].toString())
            assertEquals(listOf("1", 2L), other.drop(1))
            assertEquals(1L, transaction(Principal.user(1), each) { Notes.selectAll().where { Notes.body eq "still ann's" }.count() })
        }
        // the same with suspendTransaction, and inside a transaction signed in by hand
        runBlocking {
            assertEquals(Principal.user(2), suspendTransaction(Principal.user(2), db) {
                suspendTransaction(Principal.user(2), db) { actingFor() }
            })
            val refused = suspendTransaction(Principal.user(2), db) {
                assertFailsWith<IllegalStateException> { suspendTransaction(Principal.NOBODY, db) { 1 } }
                signedIn()
            }
            assertEquals("2", refused)
        }
        assertFailsWith<IllegalStateException> {
            org.jetbrains.exposed.v1.jdbc.transactions.transaction(db) {
                signIn(Principal.user(3))
                transaction(Principal.user(1), db) { 1 }
            }
        }
        // a pool's transaction inside an Exposed one takes a connection of its own: a transaction apart, as its user
        assertEquals(listOf("2", "3"), transaction(Principal.user(3), db) {
            val apart = runBlocking { app.transaction(Principal.user(2)) { calls.list(AuthzNames.ProjectPermission.EDIT) } }
            apart + signedIn().orEmpty()
        })
    }

    @Test
    @DisplayName("the test helpers: a refusal by its rule, a row that isn't there, and what isn't either")
    fun helpers() = runBlocking {
        // a refusal thrown by expect, and one the database raised (Exposed's error around it)
        val update = assertRefused("update") {
            transaction(Principal.user(3), db) { calls.expect(Notes.update({ Notes.id eq 1 }) { it[body] = "x" }, Notes, "update", 1) }
        }
        assertEquals("app.notes", update.table())
        val insert = assertRefused {
            suspendTransaction(Principal.user(2), db) {
                Notes.insert {
                    it[projectId] = 3
                    it[authorId] = 2
                    it[body] = "hi"
                }
            }
        }
        assertEquals("insert", insert.command())
        // the wrong rule, nothing refused, and an error that is no refusal: said so, or thrown as it was
        val wrong = assertFailsWith<AssertionError> { assertRefused("delete") { throw update } }
        assertTrue(wrong.message!!.contains("expected the delete rule to refuse it, but the update rule did"), wrong.message)
        assertSame(update, wrong.cause)
        assertFailsWith<AssertionError> { assertRefused {} }
        val other = IllegalStateException("no")
        assertSame(other, assertFailsWith<IllegalStateException> { assertRefused { throw other } })
        // a row that isn't there for this user
        val gone = assertNotFound {
            transaction(Principal.user(2), db) { calls.expect(Notes.update({ Notes.id eq 1 }) { it[body] = "x" }, Notes, "update", 1) }
        }
        assertEquals("app.notes 1 not found", gone.message)
        assertFailsWith<AssertionError> { assertNotFound {} }
        assertSame(other, assertFailsWith<IllegalStateException> { assertNotFound { throw other } })
    }

    @Test
    @DisplayName("errors read as rowstile's answers, or as nothing: Kotlin's nulls for Java's Optional")
    fun errors() {
        val plain = IllegalStateException("no")
        assertEquals(listOf(null, null, null), listOf(plain.problem(), plain.refusal(), plain.errorCode()))
        val notFound = NotFound("app.notes", 7)
        assertEquals(404, notFound.problem()!!.status())
        val refused = assertFailsWith<Exception> {
            transaction(Principal.user(2), db) {
                Notes.insert {
                    it[projectId] = 3
                    it[authorId] = 2
                    it[body] = "hi"
                }
            }
        }
        assertEquals(listOf("insert", "AZ709"), listOf(refused.refusal()!!.command(), refused.errorCode()))
    }

    @Test
    @DisplayName("Ktor: who a request is, from Authentication's principal; another kind is the app's to say")
    fun ktor() = runBlocking {
        // the plugin without the app's connections: nothing to check at start-up, and each call as the app says
        val bare = TestApplication {
            application {
                install(Rowstile) { principal = { call -> Principal.user(call.request.headers["x-who"]) } }
                routing { get("/who") { call.respondText(actingFor().toString()) } }
            }
        }
        bare.start()
        try {
            assertEquals("7", bare.send("GET", "/who", null, headers = mapOf("x-who" to "7")).text)
            assertEquals("nobody", bare.send("GET", "/who", null).text)
        } finally {
            bare.stop()
        }
        // the conformance app's: a principal the default can't read is the app's mistake, a 500 that says what to do
        val r = Conformance.app().send("GET", "/notes", "unknown")
        assertEquals(500, r.status, r.text)
        assertTrue(r.text("message")!!.contains("rowstile can't tell who a kotlin.String is"), r.text)
        // outside a request, and outside any ActingAs: nobody; inside one, its principal
        assertEquals(Principal.NOBODY, actingFor())
        assertEquals(Principal.of("service", 2), withContext(ActingAs(Principal.of("service", 2))) { actingFor() })
        assertEquals(ActingAs.Key, ActingAs(Principal.NOBODY).key)
    }
}
