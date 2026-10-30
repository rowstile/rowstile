package dev.rowstile.conformance

import dev.rowstile.conformance.AuthzNames.PROJECT
import dev.rowstile.conformance.AuthzNames.ProjectPermission
import dev.rowstile.kotlin.actingFor
import dev.rowstile.kotlin.exposed.calls
import dev.rowstile.kotlin.exposed.suspendTransaction
import io.ktor.http.HttpStatusCode
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.delete
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import kotlinx.serialization.Serializable
import org.jetbrains.exposed.v1.core.IColumnType
import org.jetbrains.exposed.v1.core.LongColumnType
import org.jetbrains.exposed.v1.core.TextColumnType
import org.jetbrains.exposed.v1.jdbc.Database
import org.jetbrains.exposed.v1.jdbc.JdbcTransaction
import org.jetbrains.exposed.v1.jdbc.selectAll

@Serializable
data class NewKey(val name: String, val principalType: String? = null, val principalId: String? = null)

@Serializable
data class Ask(val relation: String, val reason: String)

/** A call of the runtime's, in SQL: its first column, as text. */
fun JdbcTransaction.sql(text: String, vararg args: Pair<IColumnType<*>, Any?>): String? =
    exec(text, args.toList()) { rs -> rs.takeIf { it.next() }?.getString(1) }

/** Projects, by permission, and the runtime's calls in SQL: API keys, shares, access requests. */
fun Route.projects(db: Database) {
    get("/projects") {
        val ids = suspendTransaction(actingFor(), db) {
            Projects.selectAll().orderBy(Projects.id).map { it[Projects.id].value }
        }
        call.respond(ids)
    }

    get("/projects/editable") {
        call.respond(suspendTransaction(actingFor(), db) { calls.list(ProjectPermission.EDIT).map(String::toLong) })
    }

    get("/projects/buttons") {
        val buttons = suspendTransaction(actingFor(), db) {
            val ids = Projects.selectAll().map { it[Projects.id].value }
            calls.permsOf(PROJECT, ids).mapValues { (_, perms) -> perms.map { it.permission() } }
        }
        call.respond(buttons)
    }

    get("/projects/page") {
        val limit = call.request.queryParameters["limit"]!!.toInt()
        val after = call.request.queryParameters["after"]
        // the projects the user may see, a page at a time: the database says when the size or the cursor is wrong
        call.respond(suspendTransaction(actingFor(), db) { calls.list(ProjectPermission.VIEW, after, limit) })
    }

    delete("/keys/{id}") {
        val id = call.parameters["id"]!!.toLong()
        // one of the user's API keys: someone else's, or one that isn't there, is 404
        suspendTransaction(actingFor(), db) { sql("SELECT 1 FROM authz.revoke_api_key(?)", LongColumnType() to id) }
        call.respond(HttpStatusCode.NoContent)
    }

    post("/keys") {
        val k = call.receive<NewKey>()
        val key = call.request.headers["x-api-key"]
        // an API key, for the user or a principal whose keys they manage; a request that brings a key (x-api-key)
        // signs in with it first, in the same transaction: the database says who may make which
        val made = suspendTransaction(actingFor(), db) {
            if (key != null) sql("SELECT 1 FROM authz.login_key(?)", TextColumnType() to key)
            sql(
                "SELECT authz.create_api_key(?, '', NULL, CAST(? AS text), CAST(? AS text))",
                TextColumnType() to k.name,
                TextColumnType() to k.principalType,
                TextColumnType() to k.principalId,
            )
        }
        call.respond(HttpStatusCode.Created, mapOf("key" to made))
    }

    get("/projects/{id}/shares") {
        val id = call.parameters["id"]!!
        val shares = suspendTransaction(actingFor(), db) {
            sql("SELECT string_agg(subject_id, ',') FROM authz.list_shares('project', ?)", TextColumnType() to id)
        }
        call.respond(shares.orEmpty().split(',').filter(String::isNotEmpty))
    }

    post("/projects/{id}/requests") {
        val id = call.parameters["id"]!!
        val a = call.receive<Ask>()
        // access asked for: the policy shares no relation of a project, so this is the app's mistake (a 500), once
        // the database knows who asks
        val made = suspendTransaction(actingFor(), db) {
            sql(
                "SELECT authz.request_access('project', ?, ?, ?)",
                TextColumnType() to id,
                TextColumnType() to a.relation,
                TextColumnType() to a.reason,
            )
        }
        call.respond(HttpStatusCode.Created, mapOf("id" to made?.toLong()))
    }
}
