package dev.rowstile.kotlin.ktor

import dev.rowstile.Authz
import dev.rowstile.Principal
import dev.rowstile.Problem
import dev.rowstile.kotlin.ActingAs
import dev.rowstile.kotlin.problem
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.ApplicationCallPipeline
import io.ktor.server.application.ApplicationPlugin
import io.ktor.server.application.Hook
import io.ktor.server.application.createApplicationPlugin
import io.ktor.server.auth.UserIdPrincipal
import io.ktor.server.auth.principal
import io.ktor.server.response.respondText
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import javax.sql.DataSource

/** What the [Rowstile] plugin is told: who a request is, and the app's connections. */
public class RowstileConfig {
    /**
     * Who a request is, asked when its code first reads it (`actingFor()`, as a transaction begins): after Ktor's
     * Authentication. By default the principal Authentication found: a `dev.rowstile.Principal` as it is (a service:
     * `Principal.of("service", 3)`), a `UserIdPrincipal` as the user whose id is its name, and nobody when no one is
     * signed in. Any other principal (a `JWTPrincipal`): say who it is here, `principal = { call -> ... }`.
     */
    public var principal: (ApplicationCall) -> Principal = ::authenticated

    /**
     * The app's connections, if it gives them: the app doesn't start on one that skips row-level security (a
     * superuser, BYPASSRLS, the tables' owner), where the database would filter nothing (`authz.connection_check()`).
     */
    public var dataSource: DataSource? = null
}

private fun authenticated(call: ApplicationCall): Principal =
    when (val found = call.principal<Any>()) {
        null -> Principal.NOBODY
        is Principal -> found
        is UserIdPrincipal -> Principal.user(found.name)
        else -> error(
            "rowstile can't tell who a ${found::class.qualifiedName} is: say so in install(Rowstile) { principal = { call -> ... } }",
        )
    }

/** Each call, its pipeline wrapped: in the request's coroutine context, its errors answered. */
private object Calls : Hook<suspend (ApplicationCall, suspend () -> Unit) -> Unit> {
    override fun install(
        pipeline: ApplicationCallPipeline,
        handler: suspend (ApplicationCall, suspend () -> Unit) -> Unit,
    ) {
        pipeline.intercept(ApplicationCallPipeline.Plugins) { handler(context) { proceed() } }
    }
}

/**
 * rowstile for Ktor (preview). Each request's code acts for whoever the request is (`actingFor()`), so the
 * transactions it begins sign in as them; rowstile's answers become problem details (RFC 9457): a refusal 403 with the
 * rule and the reason, a row the user can't see 404, and a call the database turns down as its code's page says (401,
 * 400, 409), with the database's words. Any other error is left as it is: the app's mistakes stay errors, a 500. With
 * [RowstileConfig.dataSource], the app doesn't start on a connection that skips row-level security.
 *
 * ```
 * install(Rowstile) { dataSource = pool }
 * ```
 */
public val Rowstile: ApplicationPlugin<RowstileConfig> =
    createApplicationPlugin("Rowstile", ::RowstileConfig) {
        val who = pluginConfig.principal
        pluginConfig.dataSource?.connection?.use { Authz.on(it).check() }
        on(Calls) { call, proceed ->
            try {
                withContext(ActingAs { who(call) }) { proceed() }
            } catch (e: Throwable) {
                call.respondProblem(e.problem() ?: throw e)
            }
        }
    }

private fun json(value: Any?): JsonElement =
    when (value) {
        null -> JsonNull
        is List<*> -> JsonArray(value.map(::json))
        else -> JsonPrimitive(value.toString())
    }

/**
 * Answers with [problem], as `application/problem+json`: its type, title, status and detail, and its own members (a
 * refusal's `table`, `command`, `why` and `code`). For an app's own handlers (StatusPages):
 * `call.respondProblem(cause.problem() ?: throw cause)`.
 */
public suspend fun ApplicationCall.respondProblem(problem: Problem) {
    val body =
        mapOf(
            "type" to json(problem.type()),
            "title" to json(problem.title()),
            "status" to JsonPrimitive(problem.status()),
            "detail" to json(problem.detail()),
        ) + problem.members().mapValues { json(it.value) }
    respondText(
        JsonObject(body).toString(),
        ContentType("application", "problem+json"),
        HttpStatusCode.fromValue(problem.status()),
    )
}
