# rowstile for Rust

**Preview.** This crate may change in any release; it is not part of what 1.0 keeps stable.

rowstile for Rust apps on [sqlx](https://github.com/launchbadge/sqlx) or
[tokio-postgres](https://github.com/sfackler/rust-postgres): every transaction signs in as whoever the request acts
for, the database filters what it reads and refuses what it may not write, and the crate turns a refusal into
`Error::Refused` (a 403 with the reason) and a hidden row into `Error::NotFound` (a 404). It holds no rowstile logic:
it calls the `authz.*` functions the policy made, and reads their answers.

```sh
cargo add rowstile --features sqlx,axum
```

```rust
let mut tx = rowstile::sqlx::begin(&pool, &rowstile::Principal::user("42")).await?;
let changed = sqlx::query("UPDATE app.notes SET body = $1 WHERE id = $2")
    .bind(body)
    .bind(id)
    .execute(&mut *tx)
    .await? // a refused write: Error::Refused
    .rows_affected();
rowstile::sqlx::expect(&mut tx, changed, "app.notes", "update", id).await?; // none changed: NotFound or Refused
tx.commit().await?;
```

- `sqlx::begin`, `pg::begin`: a transaction signed in (`authz.act_as`), on a sqlx pool or a tokio-postgres client.
  The sign-in lasts the transaction alone, so pools and PgBouncer in transaction mode are safe.
- `expect`: an UPDATE or DELETE that changed no row, asked about: `Error::NotFound` or `Error::Refused`, with the
  reason.
- `Error`: `Refused`, `NotFound`, `Call` (the codes a call can meet, each with its status), `NotSignedIn`,
  `Connection`, `Database`; `code()` is rowstile's code (`rowstile help AZ709`), `problem()` the problem body.
- `check`: at start-up, refuse a connection that skips row-level security.
- `can`, `perms_of`, `list`: take only the policy's names, which `rowstile client rust` writes.
- `axum` (feature `axum`): `Tx`, an extractor that begins each request's transaction signed in as whoever the
  app's state says it is (`SignIn`), and `Error` as a response, `application/problem+json`.
- `testing` (feature `testing`): a copy of the migrated test database for each test binary, and `refused` and
  `not_found` assertions.

Features: `tokio-postgres` (the default), `sqlx`, `axum`, `testing`. The guide:
[Axum](https://rowstile.dev/stacks/axum).
