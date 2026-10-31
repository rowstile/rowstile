# rowstile for Kotlin

**Preview**: this module may change in any release, and is not part of 1.0's promises yet.

The Kotlin module of [the Java SDK](../README.md), for Kotlin apps on a rowstile policy: transactions signed in
from coroutines, Exposed's transactions signed in, and a Ktor plugin that signs in each request's transactions and
answers refusals with problem details. It holds no rowstile logic, nor any of the Java SDK's: its `Authz`,
`Principal`, `Refused`, `NotFound` and `Problem` are the Java SDK's, and Kotlin adds the idioms around them. Java 21
or newer; built with Kotlin 2.3, as Ktor 3.6 and Exposed 1.6 are.

Artifact `dev.rowstile:rowstile-kotlin`. Its packages:

- `dev.rowstile.kotlin`: `DataSource.transaction(who) { ... }`, a block in a transaction signed in
  (`BEGIN; SELECT authz.act_as(...)`), on `Dispatchers.IO`, with the connection as its receiver; `ActingAs(who)`, an
  element of a coroutine's context that says whom the code acts for, and `actingFor()`, which reads it (nobody when
  nothing says); `Connection.calls`, the runtime's calls (the Java SDK's `Authz`); and `problem()`, `refusal()` and
  `errorCode()`, which read an error as rowstile's answer, or give null.
- `dev.rowstile.kotlin.exposed`: `transaction(who, db) { ... }` and `suspendTransaction(who, db) { ... }`, Exposed's
  own, signed in first; `JdbcTransaction.signIn(who)` and `JdbcTransaction.calls`; and `calls.expect(count, Table,
  command, key)`, which asks why an UPDATE or DELETE changed nothing (404, or 403 with the reason). A transaction is
  one principal's: in one these signed in, a statement while the code acts for someone else (an `ActingAs` of
  another principal's), or for nobody, is refused before it is sent (`IllegalStateException`), whether it is
  Exposed's, a call of `calls`, or one on `DataSource.transaction`'s connection.
- `dev.rowstile.kotlin.ktor`: the plugin, `install(Rowstile) { dataSource = pool }`. Each request's code acts for
  whoever Ktor's Authentication found (a `UserIdPrincipal`, a `dev.rowstile.Principal`; or say who with `principal =
  { call -> ... }`); rowstile's answers become problem details (RFC 9457): a refusal 403, a row that isn't there 404,
  and each code as its page says (`rowstile help AZ710`); and the app doesn't start on a connection that skips
  row-level security. `call.respondProblem(problem)` is for your own handlers.
- `dev.rowstile.kotlin.testing`: `assertRefused(command) { ... }` and `assertNotFound { ... }`.

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

Ktor, Exposed and kotlinx.serialization are the app's: the module uses the ones it finds. The policy's names come
from `rowstile client java` (`AuthzNames.java`), which Kotlin reads as its own: `calls.can(NotePermission.EDIT, 7)`.

The page for Ktor: [docs/stacks/ktor.md](../../../docs/stacks/ktor.md). Its conformance suite is
`integrations/ktor` (`test.sh`), which builds and installs this module and the Java SDK under it (`./mvnw install`)
the way an app's build gets them, and fails unless its checks run every line and branch here.

Not on Maven Central yet: until it is, `./mvnw install` in `sdk/java` puts it in your local repository.
