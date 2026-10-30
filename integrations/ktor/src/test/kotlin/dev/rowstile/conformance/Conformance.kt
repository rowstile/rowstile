package dev.rowstile.conformance

import dev.rowstile.testing.WorkerDatabase
import io.ktor.client.request.header
import io.ktor.client.request.request
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpMethod
import io.ktor.http.contentType
import io.ktor.server.testing.TestApplication
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import java.sql.Connection
import java.sql.DriverManager
import kotlin.test.assertEquals

/**
 * What the checks share: this JVM's own database (check 12), copied once from the migrated test database, with the
 * same few rows for every test; and the app, started once on it, which takes requests as a user or a service, the way
 * a browser sends them.
 */
object Conformance {
    /** The migrated test database (test.sh's conf_tests), as the owner; and the app role's URL. */
    val TESTS: String = System.getenv("ROWSTILE_TESTS_URL")
    val APP: String = System.getenv("ROWSTILE_APP_URL")

    /** This JVM's copy of it, made once (check 12). */
    val WORKER: WorkerDatabase = WorkerDatabase.copy(TESTS, null, null, APP, true)

    /** The notes each may see ("": nobody). */
    val NOTES: Map<String, List<Long>> =
        mapOf("1" to listOf(1L, 3L, 4L), "2" to listOf(2L, 3L), "3" to listOf(1L, 3L, 4L), "" to listOf(3L))

    val settings: Settings get() = Settings(WORKER.appUrl(), WORKER.url())

    /** The app, on this JVM's database, started once. */
    private val app: TestApplication by lazy {
        TestApplication { application { conformance(settings) } }.also { runBlocking { it.start() } }
    }

    fun app(): TestApplication = app

    fun owner(): Connection = DriverManager.getConnection(WORKER.url())

    /** As the owner, in a transaction of its own. */
    fun sql(vararg statements: String) {
        owner().use { conn -> conn.createStatement().use { st -> statements.forEach { st.execute(it) } } }
    }

    /**
     * The same few rows for every test: ann (1) owns project 1 (cy is a member, service 1 reads it) and the public
     * project 3; bo (2) owns project 2. Ann's folder 1 has folder 2 inside it.
     */
    fun seed() {
        sql(
            "TRUNCATE app.folders, app.inbox, app.notes, app.members, app.project_services, app.projects," +
                " app.services, app.users CASCADE",
            "INSERT INTO app.users VALUES (1, 'ann'), (2, 'bo'), (3, 'cy')",
            "INSERT INTO app.services VALUES (1, 'digest')",
            "INSERT INTO app.projects VALUES (1, 1, 'Plans', false), (2, 2, 'Bo''s', false), (3, 1, 'Open', true)",
            "INSERT INTO app.members VALUES (1, 3)",
            "INSERT INTO app.project_services VALUES (1, 1)",
            "INSERT INTO app.notes (id, project_id, author_id, body) VALUES (1, 1, 1, 'plan'), (2, 2, 2, 'mine')," +
                " (3, 3, 1, 'hello'), (4, 1, 3, 'idea')",
            "SELECT setval(pg_get_serial_sequence('app.notes', 'id'), 100)",
            "INSERT INTO app.folders VALUES (1, NULL, 1, 'top'), (2, 1, 1, 'inside')",
        )
    }
}

/** An answer: its status, its content type, and its body (JSON, if it is). */
data class Reply(val status: Int, val type: String, val text: String) {
    fun json(): JsonElement = Json.parseToJsonElement(text)

    fun obj(): JsonObject = json().jsonObject

    fun ids(): List<Long> = json().jsonArray.map { it.jsonPrimitive.long }

    /** A member of the body, as text: null when it is JSON's null or isn't there. */
    fun text(name: String): String? = obj()[name]?.jsonPrimitive?.takeIf { it.isString }?.content
}

/** A request to [app]: [who] is a user's id, `service:1` a service, or null for nobody; [body] is JSON. */
suspend fun TestApplication.send(
    method: String,
    path: String,
    who: String?,
    body: String? = null,
    headers: Map<String, String> = mapOf(),
): Reply {
    val r = client.request(path) {
        this.method = HttpMethod.parse(method)
        when {
            who == null -> {}
            who.startsWith("service:") -> header("x-service", who.removePrefix("service:"))
            else -> header("x-user", who)
        }
        headers.forEach { (k, v) -> header(k, v) }
        if (body != null) {
            contentType(ContentType.Application.Json)
            setBody(body)
        }
    }
    return Reply(r.status.value, r.headers["content-type"].orEmpty(), r.bodyAsText())
}

fun call(method: String, path: String, who: String?, body: String? = null, headers: Map<String, String> = mapOf()): Reply =
    runBlocking { Conformance.app().send(method, path, who, body, headers) }

/** A problem body, as the SDKs send it: its type, title, status, detail and code. */
fun assertProblem(r: Reply, kind: String, title: String, status: Int, detail: String, code: String?) {
    assertEquals(status, r.status, r.text)
    assertEquals("application/problem+json", r.type, r.text)
    assertEquals("https://rowstile.dev/problems/$kind", r.text("type"), r.text)
    assertEquals(title, r.text("title"), r.text)
    assertEquals(status.toLong(), r.obj()["status"]!!.jsonPrimitive.long, r.text)
    assertEquals(detail, r.text("detail"), r.text)
    assertEquals(code, r.text("code"), r.text)
}
