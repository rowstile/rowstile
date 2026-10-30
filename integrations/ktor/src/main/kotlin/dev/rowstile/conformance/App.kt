package dev.rowstile.conformance

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import dev.rowstile.kotlin.ktor.Rowstile
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationStopped
import io.ktor.server.application.install
import io.ktor.server.auth.authenticate
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.plugins.statuspages.StatusPages
import io.ktor.server.response.respond
import io.ktor.server.routing.routing
import org.flywaydb.core.Flyway
import org.jetbrains.exposed.v1.core.DatabaseConfig
import org.jetbrains.exposed.v1.jdbc.Database

/**
 * The conformance app: no permission checks anywhere. rowstile signs each transaction in as the request's user, the
 * database filters reads and refuses writes, and the SDK turns refusals into 403 and hidden rows into 404.
 *
 * @param appUrl the app role's JDBC URL (conf_app, which row-level security applies to)
 * @param ownerUrl the tables' owner's, which Flyway migrates as
 * @param migrations where they are
 */
data class Settings(
    val appUrl: String,
    val ownerUrl: String,
    val poolSize: Int = 5,
    val migrations: String = "classpath:db/migration",
) {
    companion object {
        fun fromEnv(): Settings = Settings(System.getenv("ROWSTILE_APP_URL"), System.getenv("ROWSTILE_OWNER_URL"))
    }
}

fun main() {
    embeddedServer(Netty, port = 8080) { conformance(Settings.fromEnv()) }.start(wait = true)
}

/** The app, on its own pool of connections, which it returns. */
fun Application.conformance(settings: Settings): HikariDataSource {
    // the migrations, the policy among them, as the tables' owner: a connection of its own
    Flyway.configure().dataSource(settings.ownerUrl, null, null).locations(settings.migrations).load().migrate()
    val pool = HikariDataSource(HikariConfig().apply {
        jdbcUrl = settings.appUrl
        maximumPoolSize = settings.poolSize
    })
    monitor.subscribe(ApplicationStopped) { pool.close() }
    // one attempt: Exposed tries a transaction again after any database error, a refusal too
    val db = Database.connect(pool, databaseConfig = DatabaseConfig { defaultMaxAttempts = 1 })
    install(ContentNegotiation) { json() }
    authentication()
    install(Rowstile) { dataSource = pool }
    install(StatusPages) {
        // the app's mistakes, with what they say (a real app logs them, and says less)
        exception<Throwable> { call, cause ->
            call.respond(HttpStatusCode.InternalServerError, mapOf("message" to cause.toString()))
        }
    }
    routing {
        authenticate("headers", optional = true) {
            notes(db)
            projects(db)
        }
    }
    return pool
}
