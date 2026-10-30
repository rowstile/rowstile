package dev.rowstile.kotlin

import dev.rowstile.Errors
import dev.rowstile.Problem
import dev.rowstile.Refused
import kotlin.jvm.optionals.getOrNull

/**
 * The problem body and status for this error, if it is one of rowstile's answers (a refusal 403, a row that isn't
 * there 404, a call the database turned down 401, 400 or 409, as its code's page says); null for anything else: the
 * app's mistakes stay errors, a 500. The Java SDK's `Errors.problem`, for Kotlin.
 */
public fun Throwable.problem(): Problem? = Errors.problem(this).getOrNull()

/** This error as the database's refusal of a write, with the rule and why; null if it is none. */
public fun Throwable.refusal(): Refused? = Errors.refusal(this).getOrNull()

/** rowstile's code for this database error (`AZ709`: `rowstile help AZ709` says what it means); null if none. */
public fun Throwable.errorCode(): String? = Errors.errorCode(this).getOrNull()
