package dev.rowstile.kotlin.exposed

import dev.rowstile.Authz
import dev.rowstile.DatabaseError
import dev.rowstile.Principal
import dev.rowstile.Rowstile
import dev.rowstile.kotlin.ActingAs
import kotlinx.coroutines.withContext
import org.jetbrains.exposed.v1.core.Table
import org.jetbrains.exposed.v1.jdbc.Database
import org.jetbrains.exposed.v1.jdbc.JdbcTransaction
import java.sql.Connection
import java.sql.SQLException

/** The JDBC connection under the transaction. */
private val JdbcTransaction.jdbc: Connection get() = connection.connection as Connection

/**
 * Signs the Exposed transaction open now in as [who] ([Principal.NOBODY]: nobody), until it ends:
 * `SELECT authz.act_as('user', '42')`, before any other statement. [transaction] and [suspendTransaction] do it for
 * you.
 */
public fun JdbcTransaction.signIn(who: Principal) {
    try {
        Rowstile.signIn(jdbc, who)
    } catch (e: SQLException) {
        throw DatabaseError(e)
    }
}

/** The runtime's calls (`can`, `list`, `expect`, ...) in this transaction, as whoever it is signed in as. */
public val JdbcTransaction.calls: Authz get() = Authz.on(jdbc)

/**
 * Exposed's `transaction`, signed in as [who] first: everything [statement] runs is as them, and the sign-in ends with
 * the transaction. Each attempt Exposed makes (it tries again after a database error) signs in again.
 *
 * ```
 * transaction(Principal.user(42)) { Notes.selectAll().count() }
 * ```
 */
public fun <T> transaction(who: Principal, db: Database? = null, statement: JdbcTransaction.() -> T): T =
    org.jetbrains.exposed.v1.jdbc.transactions.transaction(db) {
        signIn(who)
        statement()
    }

/**
 * Exposed's `suspendTransaction` (what `newSuspendedTransaction` became), signed in as [who] first; inside,
 * `actingFor()` is [who].
 *
 * ```
 * suspendTransaction(actingFor()) { Notes.selectAll().map { it[Notes.id].value } }  // as the request's user
 * ```
 */
public suspend fun <T> suspendTransaction(
    who: Principal,
    db: Database? = null,
    statement: suspend JdbcTransaction.() -> T,
): T =
    withContext(ActingAs(who)) {
        org.jetbrains.exposed.v1.jdbc.transactions.suspendTransaction(db) {
            signIn(who)
            statement()
        }
    }

/**
 * An UPDATE or DELETE's row count, returned if it changed something; else `NotFound` (a 404: the row is hidden, or
 * didn't match) or `Refused` (a 403: the user may not, and why), asked of the database in the same transaction.
 * Row-level security skips the rows a user may not change without an error:
 *
 * ```
 * calls.expect(Notes.update({ Notes.id eq id }) { it[body] = text }, Notes, "update", id)
 * ```
 */
public fun Authz.expect(changed: Int, table: Table, command: String, key: Any): Int =
    expect(changed, table.tableName, command, key)
