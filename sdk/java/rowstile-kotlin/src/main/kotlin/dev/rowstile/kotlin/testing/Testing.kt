package dev.rowstile.kotlin.testing

import dev.rowstile.NotFound
import dev.rowstile.Refused
import dev.rowstile.kotlin.refusal

/**
 * The [block] must be refused by the policy (by the rule for [command], when given: `insert`, `update`, `delete`,
 * `select`): the refusal, else an [AssertionError]. Any other error is thrown again as it is.
 *
 * ```
 * val refused = assertRefused("update") { client.patch("/notes/1") { ... } ... }
 * ```
 */
public suspend fun assertRefused(command: String? = null, block: suspend () -> Unit): Refused {
    val refused =
        try {
            block()
            null
        } catch (e: Throwable) {
            e as? Refused ?: e.refusal() ?: throw e
        } ?: throw AssertionError("expected a refusal, and nothing was refused")
    if (command != null && refused.command() != command) {
        throw AssertionError(
            "expected the $command rule to refuse it, but the ${refused.command()} rule did: ${refused.message}",
            refused,
        )
    }
    return refused
}

/** The [block] must find the row isn't there for this user ([NotFound]): it, else an [AssertionError]. */
public suspend fun assertNotFound(block: suspend () -> Unit): NotFound {
    try {
        block()
    } catch (e: NotFound) {
        return e
    }
    throw AssertionError("expected NotFound, and the row was there")
}
