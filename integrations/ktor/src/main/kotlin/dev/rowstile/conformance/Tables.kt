package dev.rowstile.conformance

import org.jetbrains.exposed.v1.core.dao.id.LongIdTable

/** The app's tables (V1__schema.sql), as Exposed sees them. The policy says who may see and change which rows. */
object Projects : LongIdTable("app.projects") {
    val ownerId = long("owner_id")
    val name = text("name")
    val public = bool("public")
}

object Notes : LongIdTable("app.notes") {
    val projectId = long("project_id")
    val authorId = long("author_id")
    val body = text("body")
}

object Inbox : LongIdTable("app.inbox") {
    val senderId = long("sender_id")
    val recipientId = long("recipient_id")
    val body = text("body")
}

object Folders : LongIdTable("app.folders") {
    val parentId = long("parent_id").nullable()
    val ownerId = long("owner_id")
    val name = text("name")
}
