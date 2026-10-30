# rowstile for Java

**Preview**: this SDK may change in any release, and is not part of 1.0's promises yet.

The SDK for Java apps on a rowstile policy: every transaction signs in as whoever the request or the job acts for,
refused writes become a 403 with the database's reason, rows the user can't see a 404, and the app refuses to start on
a connection that skips row-level security. It holds no rowstile logic: it calls the `authz.*` functions the policy
made, and translates their answers. Java 21 or newer, PostgreSQL's JDBC driver.

Three artifacts, group `dev.rowstile`:

- `rowstile`: over JDBC alone. `Rowstile.transaction(conn, who, work)` runs `work` in a transaction signed in
  (`BEGIN; SELECT authz.act_as(...)`), `Authz.on(conn)` has the runtime's calls (`can`, `perms`, `permsOf`, `list`,
  `expect`, `check`), and `Errors.problem(e)` reads a database error as rowstile's answer: a refusal 403, a row that
  isn't there 404, and each code as its page says (`rowstile help AZ710`).
- `rowstile-spring-boot-starter`: Spring Boot 4. Every transaction Spring's transaction managers begin (JDBC's and
  JPA's: `@Transactional`, `TransactionTemplate`, Spring Data's repositories) signs in first, as the request's user
  from Spring Security; a refusal answers with problem details (RFC 9457); and the app doesn't start on a connection
  that skips row-level security. A transaction is one principal's: work for someone else that joins one is refused
  (`IllegalStateException`) before anything is sent.
- `rowstile-kotlin`: Kotlin's idioms over `rowstile`. Transactions signed in from coroutines, Exposed's transactions
  signed in, a Ktor plugin, and test helpers: [its README](rowstile-kotlin/README.md), and its page,
  [docs/stacks/ktor.md](../../docs/stacks/ktor.md).

```java
@PatchMapping("/notes/{id}")
@Transactional
Map<String, Long> edit(@PathVariable long id, @RequestBody Body b) {
    Note note = notes.findById(id).orElseThrow(() -> new NotFound("app.notes", id));
    note.setBody(b.body()); // an update the rules may refuse: 403 with the reason, at the commit
    return Map.of("id", id);
}
```

`rowstile client java` writes the policy's names (`AuthzNames.java`), so a misspelled type or permission doesn't
compile: `calls.can(NotePermission.EDIT, 7)`, where `calls` is an `Authz`.

The page for Spring: [docs/stacks/spring.md](../../docs/stacks/spring.md). Its conformance suite is
`integrations/spring` (`test.sh`), which builds and installs this folder (`./mvnw install`) the way an app's build
gets it, and fails unless its checks run every line and branch here.

Not on Maven Central yet: until it is, `./mvnw install` here puts them in your local repository.
