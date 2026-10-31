package dev.rowstile.kotlin.exposed

import dev.rowstile.Authz
import dev.rowstile.DatabaseError
import dev.rowstile.Principal
import dev.rowstile.Rowstile
import dev.rowstile.kotlin.ActingAs
import dev.rowstile.kotlin.actingAs
import dev.rowstile.kotlin.checked
import dev.rowstile.kotlin.refuseAnyoneBut
import kotlinx.coroutines.withContext
import org.jetbrains.exposed.v1.core.Key
import org.jetbrains.exposed.v1.core.Table
import org.jetbrains.exposed.v1.core.Transaction
import org.jetbrains.exposed.v1.core.statements.GlobalStatementInterceptor
import org.jetbrains.exposed.v1.core.statements.StatementContext
import org.jetbrains.exposed.v1.jdbc.Database
import org.jetbrains.exposed.v1.jdbc.JdbcTransaction
import java.sql.Connection
import java.sql.SQLException

/** The JDBC connection under the transaction. */
private val JdbcTransaction.jdbc: Connection get() = connection.connection as Connection

/** Who the database transaction is signed in as, kept on its outermost Exposed transaction (a savepoint's outer). */
private val SIGNED = Key<Principal>()

/**
 * The same, when [transaction] or [suspendTransaction] signed it in: then each statement in it is checked
 * ([OnePrincipal]). A transaction signed in by hand ([signIn]) is the app's to keep to one principal.
 */
private val CHECKED = Key<Principal>()

/** The Exposed transaction the database transaction began with: this one, or the one a savepoint is inside. */
private val JdbcTransaction.outermost: JdbcTransaction get() = generateSequence(this) { it.outerTransaction }.last()

/**
 * Signs the database transaction in as [who] if nothing has yet; inside one signed in already (a `transaction` in a
 * `transaction`: Exposed runs it in the outer one, or in a savepoint of it), goes on as it is if that is [who], and
 * refuses before anything runs if it is someone else, since a sign-in lasts the whole database transaction.
 */
private fun JdbcTransaction.enter(who: Principal) {
    when (val signed = outermost.getUserData(SIGNED)) {
        null -> {
            signIn(who)
            outermost.putUserData(CHECKED, who)
        }
        who -> {}
        else -> throw Rowstile.signedInAlready(signed, who)
    }
}

/** Refuses a statement for anyone but whom this transaction is signed in as, if [enter] signed it in. */
private fun JdbcTransaction.check() {
    outermost.getUserData(CHECKED)?.let(::refuseAnyoneBut)
}

/**
 * Before each statement Exposed runs, in any of its transactions (a global interceptor, which Exposed finds by its
 * service file): in one [transaction] or [suspendTransaction] signed in, while the code acts for someone else (an
 * [ActingAs] of another principal's), or for nobody, the statement is refused before it is sent
 * (IllegalStateException, [Rowstile.signedInAlready]), and the transaction is left as it was.
 */
internal class OnePrincipal : GlobalStatementInterceptor {
    override fun beforeExecution(transaction: Transaction, context: StatementContext) {
        (transaction as JdbcTransaction).check()
    }
}

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
    outermost.putUserData(SIGNED, who)
}

/**
 * The runtime's calls (`can`, `list`, `expect`, ...) in this transaction, as whoever it is signed in as. In one
 * [transaction] or [suspendTransaction] signed in, a call while the code acts for someone else is refused before it
 * is sent, as a statement is.
 */
public val JdbcTransaction.calls: Authz get() = Authz.on(jdbc.checked { check() })

/**
 * Exposed's `transaction`, signed in as [who] first: everything [statement] runs is as them, and the sign-in ends with
 * the transaction. Each attempt Exposed makes (it tries again after a database error) signs in again.
 *
 * Inside, `actingFor()` is [who]. A transaction is one principal's: in it, a statement while the code acts for
 * someone else, or for nobody, is refused before it is sent (IllegalStateException), and the transaction is left as
 * it was.
 *
 * Inside another transaction on the same database, Exposed runs it in the outer one (or in a savepoint of it), where
 * a sign-in would last past the block: it signs in only a transaction no one has signed in yet. In one signed in as
 * [who] already, [statement] runs as it is; in one signed in as someone else, it is refused (IllegalStateException)
 * before [statement] runs, and the outer transaction is left as it was.
 *
 * ```
 * transaction(Principal.user(42)) { Notes.selectAll().count() }
 * ```
 */
public fun <T> transaction(who: Principal, db: Database? = null, statement: JdbcTransaction.() -> T): T =
    actingAs(who) {
        org.jetbrains.exposed.v1.jdbc.transactions.transaction(db) {
            enter(who)
            statement()
        }
    }

/**
 * Exposed's `suspendTransaction` (what `newSuspendedTransaction` became), signed in as [who] first; inside,
 * `actingFor()` is [who], and a statement while the code acts for anyone else is refused, as in [transaction].
 * Inside another transaction, as [transaction]: run as it is for [who], refused for anyone else.
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
            enter(who)
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
