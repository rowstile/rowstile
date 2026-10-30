//! Help for an app's tests: a copy of the migrated test database for each test binary, and assertions on
//! refusals.
//!
//! `cargo test` runs each test binary (each file in `tests/`, and the crate's own) in a process of its own: each
//! binary is a worker, and gets its own database, named after the one it copies and the binary. The tests of one
//! binary share it.
//!
//! ```no_run
//! # async fn setup() -> Result<(), rowstile::Error> {
//! let tests = std::env::var("TESTS_URL").unwrap(); // the migrated test database, the owner's URL
//! let db = rowstile::testing::per_binary(&tests, Some("postgres://app:app@localhost/x"), true).await?;
//! // db.url, the owner's, and db.app_url, the app role's, for this binary's own copy
//! # Ok(())
//! # }
//! ```

use tokio_postgres::NoTls;

use crate::{Error, NotFound, Refused};

/// A test binary's own database: its URL (the owner's), and the app role's if one was given.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Database {
    /// The owner's URL.
    pub url: String,
    /// The app role's URL, if one was given.
    pub app_url: Option<String>,
}

/// This test binary's name for its database: the binary's own name, as cargo built it (its target's name and a
/// hash: `conformance_0f1e2d3c4b5a6978`), lowercase, a `_` for what Postgres would quote.
#[must_use]
pub fn worker() -> String {
    let exe = std::env::current_exe().ok();
    let name = exe.as_deref().and_then(std::path::Path::file_stem).map_or("rust".into(), |s| s.to_string_lossy());
    name.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '_' }).collect()
}

/// A Postgres URL's parts around its database's name: `postgres://u@h/`, the name, and `?...`.
fn parts(url: &str) -> Option<(&str, &str, &str)> {
    let path = url.find("://")? + 3;
    let slash = path + url[path..].find('/')?;
    let rest = &url[slash + 1..];
    let (name, query) = rest.split_at(rest.find('?').unwrap_or(rest.len()));
    Some((&url[..=slash], name, query)).filter(|(_, name, _)| !name.is_empty())
}

/// The URL with another database's name.
fn with_database(url: &str, name: &str) -> String {
    parts(url).map_or_else(|| url.to_owned(), |(base, _, query)| format!("{base}{name}{query}"))
}

/// An identifier, quoted.
fn ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// Copies the migrated test database `tests_url` names (with the policy) for this test binary, and gives its URL,
/// the same user's, and `app_url`'s for it (if given). The copy is made by a role that may create databases (the
/// owner), while nothing else is connected to the original. A copy an earlier run left is made again, unless
/// `fresh` is false.
///
/// # Errors
///
/// A URL that names no database, the database's errors, and one that says so when something is connected to the
/// original.
pub async fn per_binary(tests_url: &str, app_url: Option<&str>, fresh: bool) -> Result<Database, Error> {
    let template = parts(tests_url)
        .ok_or_else(|| {
            Error::Other(format!("rowstile::testing: {tests_url:?} is not a URL that names a database to copy").into())
        })?
        .1;
    let name = format!("{template}_{}", worker());
    // CREATE DATABASE ... TEMPLATE needs no one connected to the original, this connection included
    let (client, connection) = tokio_postgres::connect(&with_database(tests_url, "postgres"), NoTls).await?;
    let connected = tokio::spawn(connection);
    if fresh {
        // (a copy it can't drop is still there: the copy's CREATE says so)
        let _ = client.execute(&format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", ident(&name)), &[]).await;
    }
    let made = client.execute(&format!("CREATE DATABASE {} TEMPLATE {}", ident(&name), ident(template)), &[]).await;
    drop(client);
    let _ = connected.await;
    let code = made.as_ref().err().and_then(tokio_postgres::Error::code).map(|c| c.code().to_owned());
    match (made, code.as_deref()) {
        // something is connected to the original (Postgres has waited five seconds for it to leave)
        (Err(e), Some("55006")) => Err(Error::Other(
            format!(
                "rowstile::testing: {template} can't be copied while anything is connected to it: close what holds \
                 it (the app, a migration tool, a console). Where the service keeps a connection of its own for \
                 minutes after yours (Neon does), a copy per binary can't be made: use one test database, where \
                 each test rolls back, or a branch for each run: {e}"
            )
            .into(),
        )),
        (Err(e), code) if fresh || code != Some("42P04") => Err(e.into()),
        // made, or kept from an earlier run, as asked
        _ => {
            Ok(Database { url: with_database(tests_url, &name), app_url: app_url.map(|app| with_database(app, &name)) })
        }
    }
}

/// The refusal `err` must be (it panics otherwise): by `command`'s rule, unless `command` is empty.
/// `refused(result.unwrap_err(), "update")`.
///
/// # Panics
///
/// When `err` is no refusal, or one by another rule.
#[track_caller]
#[allow(clippy::must_use_candidate)] // called for its check as much as for what it gives
pub fn refused(err: Error, command: &str) -> Refused {
    match err {
        Error::Refused(r) if command.is_empty() || r.command.as_deref() == Some(command) => *r,
        Error::Refused(r) => panic!("expected the {command} rule to refuse it, but: {:?}: {}", r.command, r.message),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// The [`NotFound`] `err` must be (it panics otherwise): `not_found(result.unwrap_err())`.
///
/// # Panics
///
/// When `err` is anything else.
#[track_caller]
#[allow(clippy::must_use_candidate)] // called for its check as much as for what it gives
pub fn not_found(err: Error) -> NotFound {
    match err {
        Error::NotFound(n) => n,
        other => panic!("expected NotFound, got {other:?}"),
    }
}
