package dev.rowstile.kotlin

import dev.rowstile.Authz
import dev.rowstile.DatabaseError
import dev.rowstile.Principal
import dev.rowstile.Rowstile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ThreadContextElement
import kotlinx.coroutines.withContext
import java.sql.Connection
import java.sql.SQLException
import javax.sql.DataSource
import kotlin.coroutines.CoroutineContext

// Who the code running on this thread acts for: set while a coroutine with ActingAs runs here
private val CURRENT = ThreadLocal<ActingAs?>()

/**
 * Who the code in a coroutine acts for, as an element of its context: what [actingFor] answers, in the coroutine and
 * in blocking code it runs (the thread holds it while the coroutine runs there, and drops it when it leaves).
 *
 * ```
 * launch(ActingAs(Principal.of("service", 3))) { suspendTransaction(actingFor()) { ... } }  // a job
 * ```
 *
 * The Ktor plugin gives each request's coroutine one, which asks who the request is when it is first read: after
 * Ktor's Authentication has run.
 */
public class ActingAs internal constructor(private val resolve: () -> Principal) : ThreadContextElement<ActingAs?> {
    /** Acting for [who]. */
    public constructor(who: Principal) : this({ who })

    /** Who. */
    public val principal: Principal get() = resolve()

    /** The key of the element in a coroutine's context. */
    public companion object Key : CoroutineContext.Key<ActingAs>

    override val key: CoroutineContext.Key<ActingAs> get() = Key

    override fun updateThreadContext(context: CoroutineContext): ActingAs? {
        val before = CURRENT.get()
        CURRENT.set(this)
        return before
    }

    override fun restoreThreadContext(context: CoroutineContext, oldState: ActingAs?) {
        CURRENT.set(oldState)
    }
}

/**
 * Who the code running now acts for: the [ActingAs] of the coroutine (the request's user, under the Ktor plugin), or
 * nobody ([Principal.NOBODY]) when nothing says.
 */
public fun actingFor(): Principal = CURRENT.get()?.principal ?: Principal.NOBODY

/**
 * A transaction on a connection of this pool, signed in as [who] (`BEGIN; SELECT authz.act_as(...)`): it commits what
 * [block] did, or rolls it back if [block] throws (or is cancelled). JDBC blocks, so it runs on [Dispatchers.IO], and
 * the block holds the one connection the transaction is on, wherever it resumes; inside, [actingFor] is [who]. A
 * database error is thrown as [DatabaseError].
 *
 * ```
 * val ids = pool.transaction(Principal.user(42)) { prepareStatement("SELECT id FROM app.notes").use { ... } }
 * ```
 */
public suspend fun <T> DataSource.transaction(who: Principal, block: suspend Connection.() -> T): T =
    withContext(Dispatchers.IO + ActingAs(who)) {
        try {
            connection.use { conn ->
                val autoCommit = conn.autoCommit
                conn.autoCommit = false
                try {
                    Rowstile.signIn(conn, who)
                    val result = conn.block()
                    conn.commit()
                    result
                } catch (e: Throwable) {
                    conn.rollback()
                    throw e
                } finally {
                    conn.autoCommit = autoCommit
                }
            }
        } catch (e: SQLException) {
            throw DatabaseError(e)
        }
    }

/** The runtime's calls (`can`, `list`, `expect`, ...) on this connection, in its transaction. */
public val Connection.calls: Authz get() = Authz.on(this)
