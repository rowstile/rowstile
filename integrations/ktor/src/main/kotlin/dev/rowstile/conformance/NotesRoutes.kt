package dev.rowstile.conformance

import dev.rowstile.kotlin.actingFor
import dev.rowstile.kotlin.exposed.calls
import dev.rowstile.kotlin.exposed.expect
import dev.rowstile.kotlin.exposed.suspendTransaction
import io.ktor.http.HttpStatusCode
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.delete
import io.ktor.server.routing.get
import io.ktor.server.routing.patch
import io.ktor.server.routing.post
import kotlinx.serialization.Serializable
import org.jetbrains.exposed.v1.core.TextColumnType
import org.jetbrains.exposed.v1.core.eq
import org.jetbrains.exposed.v1.jdbc.Database
import org.jetbrains.exposed.v1.jdbc.batchInsert
import org.jetbrains.exposed.v1.jdbc.deleteWhere
import org.jetbrains.exposed.v1.jdbc.insertAndGetId
import org.jetbrains.exposed.v1.jdbc.select
import org.jetbrains.exposed.v1.jdbc.update

@Serializable
data class NewNote(val projectId: Long, val body: String)

@Serializable
data class Body(val body: String)

@Serializable
data class NewMessage(val recipientId: Long, val body: String)

@Serializable
data class Move(val parentId: Long?)

/** The user the request is, as the tables' key (0: nobody). */
fun signedIn(): Long = actingFor().id()?.toLong() ?: 0

/** Notes, the inbox and folders: Exposed's DSL, in transactions signed in as the request's user. */
fun Route.notes(db: Database) {
    get("/notes") {
        val ids = suspendTransaction(actingFor(), db) {
            Notes.select(Notes.id).orderBy(Notes.id).map { it[Notes.id].value }
        }
        call.respond(ids)
    }

    post("/notes") {
        val n = call.receive<NewNote>()
        // the new id is read back (RETURNING): the select rule must let the user see the row
        val id = suspendTransaction(actingFor(), db) {
            Notes.insertAndGetId {
                it[projectId] = n.projectId
                it[authorId] = signedIn()
                it[body] = n.body
            }.value
        }
        call.respond(HttpStatusCode.Created, mapOf("id" to id))
    }

    patch("/notes/{id}") {
        val id = call.parameters["id"]!!.toLong()
        val text = call.receive<Body>().body
        suspendTransaction(actingFor(), db) {
            val changed = Notes.update({ Notes.id eq id }) { it[body] = text }
            calls.expect(changed, Notes, "update", id) // 0 rows: 404, or 403 with the reason
        }
        call.respond(mapOf("id" to id))
    }

    delete("/notes/{id}") {
        val id = call.parameters["id"]!!.toLong()
        suspendTransaction(actingFor(), db) {
            calls.expect(Notes.deleteWhere { Notes.id eq id }, Notes, "delete", id)
        }
        call.respond(HttpStatusCode.NoContent)
    }

    get("/notes/as/{user}") {
        val user = call.parameters["user"]!!
        val ids = suspendTransaction(actingFor(), db) {
            // who is signed in, changed by hand: the database doesn't believe it (the app's bug, a 500)
            exec("SELECT set_config('authz.user_id', ?, true)", listOf(TextColumnType() to user))
            Notes.select(Notes.id).map { it[Notes.id].value }
        }
        call.respond(ids)
    }

    post("/inbox") {
        val m = call.receive<NewMessage>()
        // the new id is read back (RETURNING): only the recipient may read the row
        val id = suspendTransaction(actingFor(), db) {
            Inbox.insertAndGetId {
                it[senderId] = signedIn()
                it[recipientId] = m.recipientId
                it[body] = m.body
            }.value
        }
        call.respond(HttpStatusCode.Created, mapOf("id" to id))
    }

    post("/inbox/quietly") {
        val m = call.receive<NewMessage>()
        suspendTransaction(actingFor(), db) {
            // without reading the row back
            Inbox.batchInsert(listOf(m), shouldReturnGeneratedValues = false) {
                this[Inbox.senderId] = signedIn()
                this[Inbox.recipientId] = it.recipientId
                this[Inbox.body] = it.body
            }
        }
        call.respond(HttpStatusCode.Accepted, mapOf<String, Long>())
    }

    patch("/folders/{id}") {
        val id = call.parameters["id"]!!.toLong()
        val parent = call.receive<Move>().parentId
        suspendTransaction(actingFor(), db) {
            // inside one of its own subfolders: 409, the database's words
            calls.expect(Folders.update({ Folders.id eq id }) { it[parentId] = parent }, Folders, "update", id)
        }
        call.respond(mapOf("id" to id))
    }
}
