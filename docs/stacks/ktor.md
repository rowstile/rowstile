# Kotlin: Ktor, Exposed and Flyway

<!-- tested: every line of code below is in integrations/ktor (tests/unit_test.py checks it) -->

**Preview**: the Kotlin module may change in any release, and is not part of 1.0's promises yet.

A Ktor 3 app (Authentication, ContentNegotiation) on Exposed 1 over HikariCP, whose migrations are Flyway's. The
routes check nothing: each request's transactions sign in as its user, the database filters what they read and
refuses what they may not write, and the plugin answers a refusal with 403 and a hidden row with 404, as problem
details.

Everything here comes from [`integrations/ktor`](../../integrations/ktor), the conformance suite: a small app and the checks every supported
stack passes ([`integrations/ktor/test.sh`](../../integrations/ktor/test.sh)). The Kotlin module is built on [the Java SDK](spring.md): its `Authz`,
`Principal`, `Refused` and `NotFound` are the Java SDK's, and Kotlin adds coroutines, Exposed and Ktor.

## Install

Java 21 or newer; the module is built with Kotlin 2.3, as Ktor 3.6 and Exposed 1.6 are. It
(`dev.rowstile:rowstile-kotlin`) brings the Java SDK and kotlinx.coroutines; the app has Ktor (its Authentication
too), kotlinx.serialization's JSON, Exposed and PostgreSQL's driver.

```xml
<dependency>
  <groupId>dev.rowstile</groupId>
  <artifactId>rowstile-kotlin</artifactId>
  <version>${rowstile.version}</version>
</dependency>
```

The artifacts aren't on Maven Central yet: build them from the repository, into your local repository. Gradle reads
them there too, with `mavenLocal()`.

```sh
git clone https://github.com/rowstile/rowstile && cd rowstile/sdk/java && ./mvnw install
pip install --pre rowstile      # the command (or npm install rowstile@next)
rowstile init                   # once your migrations made the tables: a first policy from them, a test file, rowstile.toml
```

The conformance app's `rowstile.toml`, with its own name for the variable that holds the owner's connection. The
policy's names are Java's (`rowstile client java`), which Kotlin reads as its own:

```toml
policy   = "db/policy.authz"
tests    = ["db/tests/*.authz"]
database = "env:ROWSTILE_OWNER_DSN"
[clients]
java = "src/main/java/dev/rowstile/conformance/AuthzNames.java"
[migrations]
tool = "flyway"
dir  = "src/main/resources/db/migration"
```

Kotlin's compiler reads that Java file beside the app's Kotlin, and javac compiles it after (Gradle's Kotlin plugin
does both by itself). With Maven:

```xml
<sourceDirs>
  <sourceDir>src/main/kotlin</sourceDir>
  <sourceDir>src/main/java</sourceDir>
</sourceDirs>
```

Two roles connect. The app connects as the role the policy names (`app role conf_app`), which row-level security
applies to; Flyway migrates as the tables' owner, on a connection of its own:

```kotlin
Flyway.configure().dataSource(settings.ownerUrl, null, null).locations(settings.migrations).load().migrate()
```

The owner must be able to switch to the app role, since the command looks at the data as the app does when it runs
the policy's tests: `GRANT conf_app TO conf_owner`, once (the command says so when it is missing, AZ618).

## Who the request is

The plugin gives each request's code whoever the request is: `actingFor()` reads it. By default that is the
principal Ktor's Authentication found: a `UserIdPrincipal` is the user whose id is its name, a `dev.rowstile.Principal`
is itself (`Principal.of("service", 3)` for a service), and nobody when no one is signed in. Another principal (a
`JWTPrincipal`) is yours to read: `install(Rowstile) { principal = { call -> ... } }`. The plugin asks as the first
transaction begins, after Authentication has run.

```kotlin
install(Rowstile) { dataSource = pool }
```

With the app's `dataSource`, the app doesn't start on a connection that skips row-level security (a superuser,
BYPASSRLS, the tables' owner), where the database would filter nothing.

The conformance app has no sign-in: its checks name the user in a header, which a real app must never believe, so
this page doesn't show its `Auth.kt`.

## Routes

A transaction signs in first: Exposed's `suspendTransaction` (what `newSuspendedTransaction` became) and
`transaction`, with `who` before the database, from `dev.rowstile.kotlin.exposed`. A sign-in lasts the database
transaction, so one inside another (which Exposed runs in the outer one) signs in nothing: as the same principal it
runs as it is, and as anyone else it is refused before it runs. A list is plain Exposed:

```kotlin
get("/notes") {
    val ids = suspendTransaction(actingFor(), db) {
        Notes.select(Notes.id).orderBy(Notes.id).map { it[Notes.id].value }
    }
    call.respond(ids)
}
```

The sign-in lasts the transaction, so a pooled connection never carries one request's user into the next, and
PgBouncer in transaction mode is safe ([Behind a pooler](../operations.md#behind-a-pooler)). A query outside a
transaction signed in fails with the not-signed-in error (AZ701).

Exposed tries a transaction again after any database error, three times by default, a refusal too. Ask for one
attempt:

```kotlin
val db = Database.connect(pool, databaseConfig = DatabaseConfig { defaultMaxAttempts = 1 })
```

An UPDATE or DELETE the rules refuse changes 0 rows without an error. `calls.expect` asks the database why, in the
same transaction: a row the user can't see is 404, one they may not change 403, with the reason.

```kotlin
patch("/notes/{id}") {
    val id = call.parameters["id"]!!.toLong()
    val text = call.receive<Body>().body
    suspendTransaction(actingFor(), db) {
        val changed = Notes.update({ Notes.id eq id }) { it[body] = text }
        calls.expect(changed, Notes, "update", id) // 0 rows: 404, or 403 with the reason
    }
    call.respond(mapOf("id" to id))
}
```

Exposed's DAO throws that count away: an entity's update or delete the rules refuse changes nothing, and says
nothing. Write updates and deletes with the DSL, and `expect` their count.

A refused INSERT is an error already, answered 403 with the rule. An insert that reads the new row back
(`insertAndGetId`, `RETURNING`) also needs the select rule: if the user may insert but not read the row, the 403 names
the select rule.

The answers are problem details (RFC 9457, `application/problem+json`), with the fields the other SDKs send: a
refusal's `table`, `command`, `why` (the reason, a line each) and `code`
(<https://rowstile.dev/problems/refused>). A call the database says names something that isn't there answers 404,
one it says lacks an argument or has a wrong one 400, one that needs someone signed in, or a login it refuses, 401,
and a folder moved into one of its own subfolders 409, each with the database's words. Any other error goes on to
your StatusPages: the app's mistakes stay errors, a 500. For a handler of your own, `call.respondProblem(problem)`
writes one, and `cause.problem()` reads it from an error (null when it is none of rowstile's).

## Lists by permission

`calls` (in an Exposed transaction, or on a JDBC connection) has the runtime's calls, as the transaction's user. They
take the policy's names, so a misspelled type or permission doesn't compile:

```kotlin
import dev.rowstile.conformance.AuthzNames.ProjectPermission
```

```kotlin
// the projects the user may see, a page at a time: the database says when the size or the cursor is wrong
call.respond(suspendTransaction(actingFor(), db) { calls.list(ProjectPermission.VIEW, after, limit) })
```

A list's buttons in one call: `calls.permsOf(PROJECT, ids)`, each id's permissions as `ProjectPermission`s. For the
rest (shares, access requests, API keys), call the `authz.*` function in SQL, with Exposed's `exec`.

## Background jobs

A job acts for a principal of its own (`type service = app.services principal` in the policy), whatever started it.
`ActingAs(who)` is an element of a coroutine's context: `actingFor()` reads it there, and in blocking code the
coroutine runs, and a worker's thread is back to nobody when it leaves.

```kotlin
suspend fun digest(db: Database): Seen =
    withContext(ActingAs(Principal.of("service", 1))) {
        suspendTransaction(actingFor(), db) { Seen(Projects.selectAll().count(), actingFor()) }
    }
```

`launch(ActingAs(who)) { ... }` starts one the same way.

## Migrations

The policy ships as Flyway migrations. `rowstile migrate` writes the next one (only what changed since
`db/policy.lock`), with a script config file beside it that turns Flyway's placeholders off for it; Flyway applies
it with the others at start-up, or with its own commands.

```sh
rowstile migrate                  # after changing the policy: V3__authz_<name>.sql
./mvnw flyway:migrate             # or the app's start-up
rowstile migrate --check          # in CI: exit 1 if a policy change has no migration
```

The app role and what it may do are a migration like the others, written by hand. A role belongs to the whole
server: it is made only where it is missing.

```sql
GRANT USAGE ON SCHEMA app TO conf_app;
GRANT SELECT ON ALL TABLES IN SCHEMA app TO conf_app;
GRANT INSERT, UPDATE, DELETE ON app.notes, app.inbox TO conf_app;
```

While you edit, `rowstile dev` checks, pushes to the development database, runs the tests and rewrites
`AuthzNames.java` on every save. The development database then holds what `dev` pushed: a later migration stops
there with AZ607, "this database already holds what this migration brings". There, mark it applied, or rebuild the
database from the migrations. Production and CI only ever take migrations.

## Tests

The policy's own tests run with `rowstile test`. In JUnit, the Java SDK's `WorkerDatabase.copy` copies the migrated
test database once for each JVM the run forks, so tests that write don't meet each other; Surefire gives each its
number (Gradle's `maxParallelForks` does too):

```xml
<argLine>@{argLine} -Drowstile.worker=${surefire.forkNumber}</argLine>
```

```kotlin
val WORKER: WorkerDatabase = WorkerDatabase.copy(TESTS, null, null, APP, true)
```

Ktor's `testApplication` runs the app on the copy. `assertRefused` and `assertNotFound`
(`dev.rowstile.kotlin.testing`) take a block, and return the refusal (by the rule given) or the `NotFound` it threw:

```kotlin
val update = assertRefused("update") {
```

## Without Ktor or Exposed

Over JDBC alone, a pool's `transaction(who)` runs a block in a transaction signed in, on `Dispatchers.IO`, with the
connection as its receiver:

```kotlin
app.transaction(Principal.user(2)) { reply(calls, message) },
```
