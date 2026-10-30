package dev.rowstile.conformance

import dev.rowstile.Principal
import io.ktor.server.application.Application
import io.ktor.server.auth.UserIdPrincipal
import io.ktor.server.auth.authentication

/**
 * Who a request is. A real app signs people in here: a session, a bearer token (JWT), an API key. The conformance app
 * has no sign-in: its checks name the user in a header (x-user), or a service (x-service: a service's own API calls),
 * which a real app must never believe. So docs/stacks/ktor.md never shows this file.
 */
fun Application.authentication() {
    authentication {
        provider("headers") {
            authenticate { context ->
                val headers = context.call.request.headers
                val service = headers["x-service"]
                val user = headers["x-user"]
                when {
                    service != null -> context.principal(Principal.of("service", service))
                    user == "unknown" -> context.principal(user) // a principal rowstile can't read
                    user != null -> context.principal(UserIdPrincipal(user))
                }
            }
        }
    }
}
