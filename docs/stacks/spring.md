# Spring Boot, JPA and Flyway

<!-- tested: every line of code below is in integrations/spring (tests/unit_test.py checks it) -->

**Preview**: the Java SDK may change in any release, and is not part of 1.0's promises yet.

A Spring Boot 4 app (Spring MVC, Spring Security) on JPA (Hibernate) and `JdbcClient` over HikariCP, whose
migrations are Flyway's. The controllers check nothing: every transaction Spring begins signs in as the request's
user, the database filters what it reads and refuses what it may not write, and the starter answers a refusal with
403 and a hidden row with 404, as problem details.

Everything here comes from [`integrations/spring`](../../integrations/spring), the conformance suite: a small app and the checks every supported
stack passes ([`integrations/spring/test.sh`](../../integrations/spring/test.sh)). Another JVM language or framework on JDBC: the `rowstile` artifact
alone ([below](#jdbc-without-spring)), or [the SQL an app sends](sql.md).

## Install

Java 21 or newer. The starter brings the SDK (`dev.rowstile:rowstile`); the app has Spring Boot's own starters
(`spring-boot-starter-webmvc`, `-security`, `-data-jpa`, `-flyway`) and PostgreSQL's driver.

```xml
<dependency>
  <groupId>dev.rowstile</groupId>
  <artifactId>rowstile-spring-boot-starter</artifactId>
  <version>${rowstile.version}</version>
</dependency>
```

The artifacts aren't on Maven Central yet: build them from the repository, into your local repository.

```sh
git clone https://github.com/rowstile/rowstile && cd rowstile/sdk/java && ./mvnw install
pip install --pre rowstile      # the command (or npm install rowstile@next)
rowstile init                   # once your migrations made the tables: a first policy from them, a test file, rowstile.toml
```

The conformance app's `rowstile.toml`, with its own name for the variable that holds the owner's connection:

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

Two roles connect. The app connects as the role the policy names (`app role conf_app`), which row-level security
applies to; Flyway migrates as the tables' owner, on a connection of its own. Spring Boot gives Flyway its own
when it has its own URL:

```properties
spring.datasource.url=${ROWSTILE_APP_URL}
spring.flyway.url=${ROWSTILE_OWNER_URL}
spring.jpa.hibernate.ddl-auto=validate
spring.jpa.open-in-view=false
```

The owner must be able to switch to the app role, since the command looks at the data as the app does when it runs
the policy's tests: `GRANT conf_app TO conf_owner`, once (the command says so when it is missing, AZ618).

## Who the request is

The starter asks as each transaction begins. With Spring Security, the signed-in principal's name is the user's id
(a session's user, a bearer token's subject): nobody when no one is signed in. An authentication whose principal is
a `dev.rowstile.Principal` says so itself, for a service: `Principal.of("service", 3)`. Without Spring Security, or
for another way, declare a bean of your own: a `PrincipalSource`, whose `principal()` says who the request is.

The conformance app has no sign-in: its checks name the user in a header, which a real app must never believe, so
this page doesn't show its `Auth.java`. Its Spring Security is the stateless API's:

```java
return http.csrf(csrf -> csrf.disable())
        .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(a -> a.anyRequest().permitAll())
```

Every transaction signs in, even as nobody, and the sign-in lasts the transaction: a pooled connection never
carries one request's user into the next, and PgBouncer in transaction mode is safe
([Behind a pooler](../operations.md#behind-a-pooler)). A query outside a transaction is signed in to no one, and
fails with the not-signed-in error (AZ701): run your queries in transactions. Spring Data's repositories have their
own.

## Controllers

A list is plain JPA:

```java
@GetMapping("/notes")
List<Long> list() {
    return notes.findAll().stream().map(Note::getId).sorted().toList();
}
```

An update the rules refuse changes no row, which Hibernate finds when it flushes. The starter flushes before the
commit, asks the database why in the same transaction, and answers 403 with the rule and the reason, or 404 when the
user can't see the row (or 409 when the rules allow the change: the row changed since it was read). An entity's
delete is asked about the same way:

```java
@PatchMapping("/notes/{id}")
@Transactional
Map<String, Long> edit(@PathVariable long id, @RequestBody Body b) {
    Note note = notes.findById(id).orElseThrow(() -> new NotFound("app.notes", id));
    note.setBody(b.body()); // an update the rules may refuse: 403 with the reason, at the commit
    return Map.of("id", id);
}
```

Leave the flush to the commit: a `saveAndFlush` of your own that the rules refuse is Spring's
`ObjectOptimisticLockingFailureException`, which the starter can't tell from a row changed meanwhile.

`JdbcClient` runs in the same transactions, signed in too. An UPDATE or DELETE the rules refuse changes 0 rows
without an error; the `Authz` bean's `expect` asks why:

```java
@DeleteMapping("/notes/{id}")
@ResponseStatus(HttpStatus.NO_CONTENT)
@Transactional
void remove(@PathVariable long id) {
    int deleted = jdbc.sql("DELETE FROM app.notes WHERE id = ?").param(id).update();
    calls.expect(deleted, "app.notes", "delete", id); // 0 rows: 404, or 403 with the reason
}
```

A refused INSERT is an error already, answered 403 with the rule. An insert that reads the new row back (JPA's
`save` reads its id, `RETURNING`) also needs the select rule: if the user may insert but not read the row, the 403
names the select rule.

The answers are problem details (RFC 9457, `application/problem+json`), with the fields the other SDKs send: a
refusal's `table`, `command`, `why` (the reason, a line each) and `code`
(<https://rowstile.dev/problems/refused>). A call the database says names something that isn't there answers 404,
one it says lacks an argument or has a wrong one 400, one that needs someone signed in, or a login it refuses, 401,
and a folder moved into one of its own subfolders 409, each with the database's words. Your own
`@ExceptionHandler`s come first: the starter's advice is the last.

## Lists by permission

`Authz` (a bean; the controllers call it `calls`) has the runtime's calls, in the transaction open now. They take
the policy's names, from `AuthzNames.java` (`rowstile client java`), so a misspelled type or permission doesn't
compile:

```java
@GetMapping("/projects/page")
@Transactional(readOnly = true)
List<String> page(@RequestParam int limit, @RequestParam(required = false) String after) {
    // the projects the user may see, a page at a time: the database says when the size or the cursor is wrong
    return calls.list(ProjectPermission.VIEW, after, limit);
}
```

A list's buttons in one call: `Authz`'s `permsOf(PROJECT, ids)`, each id's permissions as `ProjectPermission`s.
For the rest (shares, access requests, API keys), call the `authz.*` function in SQL, with `JdbcClient`.

## Background jobs

A job acts for a principal of its own (`type service = app.services principal` in the policy), whatever started it:

```java
public Seen run() {
    return Rowstile.actingAs(Principal.of("service", 1), () ->
            new Seen(projects.count(), Rowstile.current().orElseThrow()));
}
```

`Rowstile.job(who, work)` is the same for an executor's task or a `@Scheduled` method's body.

A sign-in lasts the database transaction, so a transaction is one principal's. Work that joins the transaction
open now (a `@Transactional` method, a `TransactionTemplate`, a repository's call, a `NESTED` savepoint) runs as it
is while the code acts for the principal it signed in as. For anyone else, or for no one, it is refused before
anything is sent for it, with an `IllegalStateException`, and the transaction goes on as it was (Spring Data's
repositories hand it on as `InvalidDataAccessApiUsageException`, the refusal its cause). So is each statement on the
transaction's connection while the code acts for someone else: a `JdbcClient` call, an `EntityManager` query, an
`Authz` call. The words are the same in every SDK: `this transaction is signed in as user 1 already, and a sign-in
lasts the database transaction: service 1's work can't run inside it. Run it after, or in a transaction of its own
(another connection)`. Run a job after the request's transaction, or in a transaction of its own: `REQUIRES_NEW`
takes another connection and signs in as the job.

To see work join a transaction, the starter hands out each transaction manager as a subclass of its class, holding
what it holds: inject it as a `PlatformTransactionManager` or by its class (`JpaTransactionManager`). A manager of a
final class is left as it is: work that joins one of its transactions for someone else is refused at its first
statement instead, which fails the transaction it joined. The statements are checked on the connections of the app's
`DataSource` beans, each a subclass of its class too.

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

The policy's own tests run with `rowstile test`. In JUnit, `WorkerDatabase.copy` copies the migrated test database
once for each JVM the run forks, so tests that write don't meet each other; Surefire gives each its number:

```xml
<argLine>@{argLine} -Drowstile.worker=${surefire.forkNumber}</argLine>
```

```java
static final WorkerDatabase WORKER = WorkerDatabase.copy(TESTS, null, null, APP, true);
```

It returns the copy's URL, and the app role's for it (`@DynamicPropertySource` gives them to Spring). The copy needs
nobody connected to the original; where the service keeps a connection (Neon does), it says so and what to use
instead ([Managed Postgres](../managed-postgres.md)).

## JDBC, without Spring

The `rowstile` artifact alone, on any connection: a transaction signed in, the calls on it, and an error read as
rowstile's answer.

```java
return Rowstile.transaction(conn, Principal.user(who), c -> {
```

`Errors.problem(e)` gives the status and the problem body for any error that is rowstile's answer, and nothing for
the app's own mistakes (a share the policy doesn't declare, a name not in the policy), which stay errors.
