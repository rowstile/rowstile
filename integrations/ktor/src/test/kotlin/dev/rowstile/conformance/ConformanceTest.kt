package dev.rowstile.conformance

import dev.rowstile.Errors
import dev.rowstile.Principal
import dev.rowstile.conformance.Conformance.NOTES
import dev.rowstile.conformance.Conformance.WORKER
import dev.rowstile.conformance.Conformance.owner
import dev.rowstile.conformance.Conformance.seed
import dev.rowstile.kotlin.ActingAs
import dev.rowstile.kotlin.actingFor
import dev.rowstile.kotlin.errorCode
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import org.jetbrains.exposed.v1.jdbc.Database
import org.jetbrains.exposed.v1.jdbc.selectAll
import org.jetbrains.exposed.v1.jdbc.transactions.transaction
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.postgresql.ds.PGSimpleDataSource
import org.postgresql.util.PSQLException
import java.sql.DriverManager
import java.util.concurrent.Executors
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.coroutines.asCoroutineDispatcher

/**
 * The conformance suite (integrations/README.md): the same checks for every stack. This is Ktor (Authentication,
 * ContentNegotiation, StatusPages), Exposed over HikariCP, Flyway. test.sh does check 11 (a fresh database: migrate,
 * the policy's tests, then Flyway's own validate shows no change) before these run.
 */
class ConformanceTest {
    @BeforeEach
    fun rows() = seed()

    @Test
    @DisplayName("1: signed in, a list shows only the user's rows")
    fun lists() {
        for (user in listOf("1", "2", "3")) {
            assertEquals(NOTES[user], call("GET", "/notes", user).ids(), user)
        }
    }

    @Test
    @DisplayName("2: signed out on purpose, only what anyone may see")
    fun signedOut() {
        assertEquals(NOTES[""], call("GET", "/notes", null).ids())
        assertEquals(listOf(3L), call("GET", "/projects", null).ids())
    }

    @Test
    @DisplayName("3: not signed in: the not-signed-in error (AZ701), naming act_as")
    fun notSignedIn() {
        DriverManager.getConnection(WORKER.appUrl()).use { conn ->
            conn.autoCommit = false
            val e = assertFailsWith<PSQLException> {
                conn.createStatement().use { it.executeQuery("SELECT count(*) FROM app.notes") }
            }
            assertEquals("28000", e.sqlState)
            val hint = e.serverErrorMessage!!.hint!!
            assertTrue(hint.contains("act_as"), hint)
            assertEquals("AZ701", e.errorCode()) // rowstile help AZ701
            assertTrue(Errors.notSignedIn(e))
        }
        // Exposed's own transaction, which nobody signs in: the same error
        val db = Database.connect(PGSimpleDataSource().apply { setURL(WORKER.appUrl()) })
        val e = assertFailsWith<Exception> { transaction(db) { maxAttempts = 1; dev.rowstile.conformance.Projects.selectAll().count() } }
        assertEquals("AZ701", e.errorCode())
    }

    @Test
    @DisplayName("5: concurrent requests never mix users")
    fun concurrent() {
        val users = List(10) { listOf("1", "2", "3", "") }.flatten()
        val replies = runBlocking {
            val app = Conformance.app()
            users.map { u -> async { app.send("GET", "/notes", u.ifEmpty { null }) } }.awaitAll()
        }
        users.zip(replies).forEach { (u, r) -> assertEquals(NOTES[u], r.ids(), u) }
    }

    @Test
    @DisplayName("6: a refused insert: 403 with the problem body naming the rule")
    fun refusedInsert() {
        val r = call("POST", "/notes", "2", """{"projectId": 3, "body": "hi"}""")
        assertEquals(403, r.status, r.text)
        assertEquals("application/problem+json", r.type)
        assertEquals("app.notes", r.text("table"), r.text)
        assertEquals("insert", r.text("command"), r.text)
        assertEquals("AZ709", r.text("code"), r.text) // rowstile help AZ709
        assertTrue(r.text("detail")!!.contains("user 2 may not insert this row into app.notes"), r.text)
        assertTrue(r.obj()["why"]!!.jsonArray.any { it.jsonPrimitive.content.contains("project.edit") }, r.text)
    }

    @Test
    @DisplayName("7: an update of a hidden row: 404; of a visible row the user may not edit: 403, with the reason")
    fun hiddenAndRefused() {
        val hidden = call("PATCH", "/notes/1", "2", """{"body": "x"}""")
        val refused = call("PATCH", "/notes/1", "3", """{"body": "x"}""")
        val mine = call("PATCH", "/notes/4", "3", """{"body": "better idea"}""")
        val gone = call("DELETE", "/notes/2", "1")
        val no = call("DELETE", "/notes/1", "3")
        assertProblem(hidden, "not-found", "Not Found", 404, "app.notes 1 not found", null)
        assertEquals(403, refused.status, refused.text)
        assertEquals("update", refused.text("command"), refused.text)
        assertTrue(refused.obj()["why"]!!.jsonArray.any { it.jsonPrimitive.content.contains("edit") }, refused.text)
        // worded as the database words a refused insert: who, the command, the row, the table
        assertEquals("permission denied: user 3 may not update row 1 of app.notes", refused.text("detail"))
        assertEquals(200, mine.status, mine.text)
        assertProblem(gone, "not-found", "Not Found", 404, "app.notes 2 not found", null)
        assertEquals(403, no.status, no.text)
        assertEquals("delete", no.text("command"), no.text)
        assertEquals("permission denied: user 3 may not delete row 1 of app.notes", no.text("detail"))
        assertEquals(listOf(1L, 3L, 4L), call("GET", "/notes", "1").ids()) // nothing deleted
    }

    @Test
    @DisplayName("8: insert, then read back, works when the select rule allows it, and is explained when not")
    fun insertReadBack() {
        val ok = call("POST", "/notes", "1", """{"projectId": 1, "body": "new"}""")
        val unreadable = call("POST", "/inbox", "1", """{"recipientId": 2, "body": "hi bo"}""")
        val quiet = call("POST", "/inbox/quietly", "1", """{"recipientId": 2, "body": "hi bo"}""")
        assertEquals(201, ok.status, ok.text)
        assertTrue(ok.obj()["id"]!!.jsonPrimitive.long > 100, ok.text)
        assertEquals(403, unreadable.status, unreadable.text)
        assertEquals("select", unreadable.text("command"), unreadable.text)
        assertTrue(unreadable.text("detail")!!.contains("may not see the row as written"), unreadable.text)
        assertEquals(202, quiet.status, quiet.text)
    }

    /** A key of ann's, made as she; [scopes] limits it. Its id, and the key itself. */
    private fun key(name: String, scopes: String): Pair<Long, String> =
        owner().use { conn ->
            conn.autoCommit = false
            conn.createStatement().use { st ->
                st.execute("SELECT authz.act_as('user', '1')")
                val made = st.executeQuery("SELECT authz.create_api_key('$name', '$scopes')").use { it.next(); it.getString(1) }
                conn.commit()
                st.executeQuery("SELECT max(id) FROM authz.api_keys WHERE user_id = '1'").use { it.next(); it.getLong(1) to made }
            }
        }

    @Test
    @DisplayName("16: a call the database turns down that is no refusal: not there (AZ708) 404, a wrong argument (AZ710) 400")
    fun notThereAndWrongArgument() {
        val (key, _) = key("ci", "")
        val page = call("GET", "/projects/page?limit=1", "1")
        val negative = call("GET", "/projects/page?limit=-1", "1")
        val cursor = call("GET", "/projects/page?limit=1&after=x", "1")
        val others = call("DELETE", "/keys/$key", "2") // bo's key it isn't
        val revoked = call("DELETE", "/keys/$key", "1")
        val again = call("DELETE", "/keys/$key", "1") // revoked: there is none now
        assertEquals("[\"1\"]", page.text)
        assertProblem(negative, "bad-argument", "Bad Request", 400, "the page size must not be negative (got -1)", "AZ710")
        assertProblem(cursor, "bad-argument", "Bad Request", 400, "the page cursor 'x' is not a project id", "AZ710")
        assertEquals(204, revoked.status, revoked.text)
        // no refusal: for this user the key isn't there (bo's own keys don't hold it; ann's no longer do)
        for (r in listOf(others, again)) {
            assertProblem(r, "not-found", "Not Found", 404, "no API key $key of yours", "AZ708")
        }
    }

    @Test
    @DisplayName("16: and the other codes, each as its page says: 401, 409, a refusal 403; the app's mistakes a 500")
    fun eachCode() {
        val (_, readOnly) = key("ro", "read") // a key of ann's that may only read
        val nobody = call("POST", "/keys", null, """{"name": "k"}""")
        val asks = call("POST", "/projects/1/requests", null, """{"relation": "member", "reason": "the review"}""")
        val badKey = call("POST", "/keys", "1", """{"name": "k"}""", mapOf("x-api-key" to "ak_nope"))
        val scoped = call("POST", "/keys", "1", """{"name": "k"}""", mapOf("x-api-key" to readOnly))
        val made = call("POST", "/keys", "1", """{"name": "k"}""")
        val notShared = call("GET", "/projects/1/shares", "2")
        val inside = call("PATCH", "/folders/1", "1", """{"parentId": 2}""")
        val stays = call("PATCH", "/folders/2", "1", """{"parentId": 1}""")
        val service = call("POST", "/keys", "service:1", """{"name": "mine"}""") // a key for itself
        assertEquals(201, made.status, made.text)
        assertTrue(made.text("key")!!.startsWith("ak_"), made.text)
        assertEquals(200, stays.status, stays.text)
        assertProblem(nobody, "not-signed-in", "Unauthorized", 401, "sign in to create an API key", "AZ714")
        assertProblem(asks, "not-signed-in", "Unauthorized", 401, "sign in first", "AZ714")
        assertProblem(badKey, "not-signed-in", "Unauthorized", 401, "invalid API key", "AZ703")
        assertProblem(inside, "conflict", "Conflict", 409, "folder 1 cannot be moved inside itself", "AZ713")
        // refusals, by the database's own code: 403, naming no rule
        for ((r, words, code) in listOf(
            Triple(scoped, "this session is read-only", "AZ704"),
            Triple(notShared, "you cannot see the shares of project 1", "AZ705"),
        )) {
            assertEquals(403, r.status, r.text)
            assertEquals("https://rowstile.dev/problems/refused", r.text("type"), r.text)
            assertEquals(code, r.text("code"), r.text)
            assertTrue(r.text("detail")!!.startsWith(words), r.text)
            assertEquals(listOf(null, null), listOf(r.text("table"), r.text("command")), r.text)
        }
        // a call that is for users, made by a service (rowstile help AZ715): a refusal too, 403
        assertProblem(
            service, "refused", "Forbidden", 403,
            "authz.create_api_key for oneself is for users, not services (service 1 is signed in)", "AZ715",
        )
        assertEquals(0, service.obj()["why"]!!.jsonArray.size, service.text)
        // the app's mistakes stay errors: a share the policy doesn't declare, a name not in the policy, who is
        // signed in changed by hand
        val errors = mapOf(
            "the policy does not allow sharing project.member with a user [AZ706]" to
                call("POST", "/projects/1/requests", "2", """{"relation": "member", "reason": "the review"}"""),
            "the policy gives service no manage_keys permission, so nobody manages its keys [AZ707]" to
                call("POST", "/keys", "1", """{"name": "k", "principalType": "service", "principalId": "1"}"""),
            "who is signed in was changed after signing in [AZ702]" to call("GET", "/notes/as/2", "1"),
        )
        errors.forEach { (words, r) ->
            assertEquals(500, r.status, r.text)
            val message = r.text("message")!!
            val said = words.substringBefore(" [")
            val code = words.substringAfter("[").removeSuffix("]")
            assertTrue(message.contains(said) && message.contains("rowstile help $code"), message)
        }
    }

    @Test
    @DisplayName("10: a background job signs in as a service principal")
    fun job() {
        val db = Database.connect(PGSimpleDataSource().apply { setURL(WORKER.appUrl()) })
        val seen = runBlocking { withContext(ActingAs(Principal.user(3))) { digest(db) } } // whatever started it
        assertEquals(Principal.of("service", 1), seen.who)
        assertEquals(2, seen.projects) // project 1 (it is added to) and the public one
        // a job on a worker's one thread acts for its principal there, and for nobody after it
        Executors.newSingleThreadExecutor().use { pool ->
            val worker = pool.asCoroutineDispatcher()
            runBlocking {
                assertEquals(2, withContext(worker) { digest(db) }.projects)
                assertEquals(Principal.NOBODY, withContext(worker) { actingFor() })
            }
            assertEquals(Principal.NOBODY, pool.submit<Principal> { actingFor() }.get())
        }
    }
}
