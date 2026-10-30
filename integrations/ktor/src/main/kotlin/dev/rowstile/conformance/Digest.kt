package dev.rowstile.conformance

import dev.rowstile.Principal
import dev.rowstile.kotlin.ActingAs
import dev.rowstile.kotlin.actingFor
import dev.rowstile.kotlin.exposed.suspendTransaction
import kotlinx.coroutines.withContext
import org.jetbrains.exposed.v1.jdbc.Database
import org.jetbrains.exposed.v1.jdbc.selectAll

/** What the job saw, and who it acted for. */
data class Seen(val projects: Long, val who: Principal)

/** A background job: it signs in as service 1, whatever request started it. */
suspend fun digest(db: Database): Seen =
    withContext(ActingAs(Principal.of("service", 1))) {
        suspendTransaction(actingFor(), db) { Seen(Projects.selectAll().count(), actingFor()) }
    }
