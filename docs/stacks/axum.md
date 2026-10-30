# Rust: Axum, sqlx and tokio-postgres

<!-- tested: every line of code below is in integrations/axum (tests/unit_test.py checks it) -->

**Preview.** The Rust SDK may change in any release: it is not part of what 1.0 keeps stable.

An Axum app on [sqlx](https://github.com/launchbadge/sqlx)'s Postgres pool, whose migrations are sqlx's. The
handlers check nothing: each request's transaction signs in as its user, the database filters what it reads and
refuses what it may not write, and the SDK answers a refusal with 403 and a hidden row with 404, as problem details.
An app on tokio-postgres (deadpool, bb8) has the same calls in `rowstile::pg`.

Everything here comes from `integrations/axum`, the conformance suite: a small app and the checks every supported
stack passes (`integrations/axum/test.sh`).

## Install

Rust 1.94 or newer (sqlx 0.9's; the suite runs on 1.99). The crate isn't on crates.io yet: take it from the repository. Its features: `tokio-postgres`
(the default), `sqlx`, `axum` and `testing`.

```sh
cargo add rowstile --git https://github.com/rowstile/rowstile --features sqlx,axum
cargo add rowstile --git https://github.com/rowstile/rowstile --features testing --dev
pip install --pre rowstile      # the command (or npm install rowstile@next, or its image)
rowstile init                   # a first policy from your tables, a test file, rowstile.toml
```

`init` writes `rowstile.toml`; the lines that say where the policy's names go (`[clients]`) and which tool runs the
migrations are yours to add. The conformance app's, with its own name for the variable that holds the owner's
connection:

```toml
policy   = "db/policy.authz"
tests    = ["db/tests/*.authz"]
database = "env:ROWSTILE_OWNER_DSN"
[clients]
rust = "src/authz.rs"
[migrations]
tool = "sqlx"
dir  = "migrations"
```

Two roles connect. The owner of the tables runs the migrations, and the app connects as the role the policy
names (`app role conf_app`), which row-level security applies to.

## Sign in every transaction

The app's state says where the pool is and who a request is (`rowstile::axum::SignIn`): `Principal::user("42")`,
`Principal::of("service", "3")`, or `Principal::Nobody`, who sees only what `anyone` may. `principal` reads the
session or the token from the request; an error from it is the answer (`Error::unauthorized`: 401). Here it is
`session_user`, the app's own: yours reads your session cookie or token. The conformance app has no sign-in, so its
stands in for one, and this page doesn't show it.

```rust
impl SignIn for App {
    fn pool(&self) -> &PgPool {
        &self.pool
    }

    fn principal(&self, request: &Parts) -> Result<Principal, Error> {
        auth::session_user(request)
    }
}
```

A handler takes `rowstile::axum::Tx`, an extractor: a transaction signed in as whoever the request acts for. It is a
connection (`&mut *tx` runs sqlx's queries), and `tx.commit()` commits it; a request that ends without commits
nothing. The sign-in lasts the transaction alone, so pools and PgBouncer in transaction mode are safe. A handler
returns `Result<_, rowstile::Error>`, so `?` answers rowstile's errors as `application/problem+json`, and any other
is logged (`tracing`) and answered 500. A list shows only the user's rows:

```rust
async fn notes(mut tx: Tx) -> Result<Json<Vec<i64>>, Error> {
    let notes = sqlx::query_scalar("SELECT id FROM app.notes ORDER BY id").fetch_all(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(notes))
}
```

A background job acts for a principal of its own, whatever started it (`type service = app.services principal` in
the policy): `rowstile::sqlx::begin` signs in as who it is given.

```rust
pub async fn digest(pool: &PgPool) -> Result<i64, Error> {
    let mut tx = rowstile::sqlx::begin(pool, &Principal::of("service", "1")).await?;
    let count = sqlx::query_scalar("SELECT count(*) FROM app.projects").fetch_one(&mut *tx).await?;
```

On tokio-postgres, `rowstile::pg::begin(&mut client, &who)` begins the transaction, signed in, on a client (a
pooled one derefs to it).

## Refusals

A refused INSERT is the database's error, which `?` turns into `Error::Refused`, with the table, the command, the
rule's reasons (`why`) and the code (`AZ709`): answered 403 with them. An UPDATE or DELETE the rules refuse changes
no row; `rowstile::sqlx::expect` asks the database why, in the same transaction, and gives `Error::NotFound` (the user
can't see the row: 404) or `Error::Refused` (403, with the reason):

```rust
    let changed =
        sqlx::query("UPDATE app.notes SET body = $2 WHERE id = $1").bind(id).bind(e.body).execute(&mut *tx).await?;
    // 0 rows: expect asks the database why, and answers 404 (hidden) or 403 (with the reason)
    rowstile::sqlx::expect(&mut tx, changed.rows_affected(), "app.notes", "update", id).await?;
```

A key of several columns is `rowstile::composite_key(&[Some("1"), Some("2")])`, as Postgres writes it: `(1,2)`.

An insert that reads the new row back (`RETURNING`) also needs the select rule: if the user may insert but not read
the row, the 403 names the select rule.

A call the database turns down that is no refusal is `Error::Call`, with the status its code's page gives and the
database's words: something it names that isn't there (AZ708) 404, a missing or wrong argument (AZ710) 400, a call
that needs someone signed in (AZ714) or a login refused (AZ703) 401, a folder moved into one of its own subfolders
(AZ713) 409. A transaction nobody signed in to is `Error::NotSignedIn` (AZ701), the app's bug, a 500, and so are the
app's other mistakes (`Error::Database`). `err.code()` is rowstile's code of any of them (`rowstile help AZ702` says
what it means), and `err.problem()` the problem body, for another framework.

At start-up, `rowstile::sqlx::check` refuses a connection that skips row-level security (a superuser, BYPASSRLS, the
tables' owner):

```rust
    // a superuser, BYPASSRLS or the tables' owner: the database would filter nothing
    if let Err(e) = rowstile::sqlx::check(&pool).await {
        eprintln!("{e}");
        return ExitCode::FAILURE;
    }
```

## The policy's names

`rowstile client rust` writes the policy's names as a module (`src/authz.rs`, `mod authz;`): a constant for each
type (`NOTE`), and an enum of each type's permissions (`NotePermission::Edit`), implementing `rowstile::Permission`.
`can`, `perms_of` and `list` take only those, so a misspelled name doesn't compile, and neither does a plain string:

```rust
    let buttons = rowstile::sqlx::perms_of::<ProjectPermission>(&mut tx, &projects).await?;
    let listed = rowstile::sqlx::list(&mut tx, ProjectPermission::View, Some(&page)).await?;
```

To filter a query to the objects the user holds a permission on, join `authz.list` in it:

```sql
SELECT p.id FROM app.projects p JOIN authz.list('project', 'edit') x ON x = p.id::text ORDER BY p.id
```

## Migrations

The policy ships as sqlx's migrations: `rowstile migrate` writes the next one (only what changed since
`db/policy.lock`), a simple migration numbered after the folder's last (`0003_authz_...sql` after
`0002_...`), and sqlx runs it with the others, in a transaction. sqlx has no diff of its own; `rowstile migrate
--check` in CI fails if a policy change has no migration.

```sh
rowstile migrate                              # after changing the policy
sqlx migrate run                              # or sqlx::migrate!() in the app
rowstile migrate --check                      # in CI: exit 1 if a policy change has no migration
```

## Tests

`cargo test` runs each test binary (each file in `tests/`) in a process of its own: each binary is a worker.
`rowstile::testing::per_binary` copies the migrated test database once for the binary that calls it, so tests that
write don't meet another binary's. A binary's tests share its copy.

```rust
                let db = rowstile::testing::per_binary(&tests, Some(&app), true).await.expect("a copy");
```

It gives the copy's URL, the owner's, and the app role's for it. The copy needs nobody connected to the original.
`rowstile::testing::refused(result, "update")` and `rowstile::testing::not_found(result)` panic unless `result` is
one.
