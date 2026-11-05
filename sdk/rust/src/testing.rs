//! Help for an app's tests: a copy of the migrated test database for each test binary, and assertions on
//! refusals.
//!
//! `cargo test` runs each test binary (each file in `tests/`, and the crate's own) in a process of its own: each
//! binary is a worker, and gets its own database, named after the one it copies and the binary. The tests of one
//! binary share it. cargo-nextest runs each test in a process of its own, many at once: there a worker is a slot
//! of nextest's (`NEXTEST_TEST_GLOBAL_SLOT`, a number no other running test has), and each test makes its copy
//! again. The copy is named `<database>_<worker>`; a name longer than Postgres's 63 bytes is shortened: its first
//! 54 bytes (fewer, not to cut a character in two), `_`, and the first 8 hex digits of the SHA-256 of the whole
//! name.
//!
//! ```no_run
//! # async fn setup() -> Result<(), rowstile::Error> {
//! let tests = std::env::var("TESTS_URL").unwrap(); // the migrated test database, the owner's URL
//! let db = rowstile::testing::per_binary(&tests, Some("postgres://app:app@localhost/x"), true).await?;
//! // db.url, the owner's, and db.app_url, the app role's, for this binary's own copy
//! # Ok(())
//! # }
//! ```

use std::fmt::Write as _;

use sha2::{Digest, Sha256};
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
/// hash: `conformance_0f1e2d3c4b5a6978`), lowercase, a `_` for what Postgres would quote; under cargo-nextest, and
/// its slot (`conformance_0f1e2d3c4b5a6978_s3`).
#[must_use]
pub fn worker() -> String {
    let exe = std::env::current_exe().ok();
    let name = exe.as_deref().and_then(std::path::Path::file_stem).map_or("rust".into(), |s| s.to_string_lossy());
    let slot = std::env::var("NEXTEST_TEST_GLOBAL_SLOT").map_or_else(|_| String::new(), |slot| format!("_s{slot}"));
    let name = name + slot.as_str();
    name.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '_' }).collect()
}

/// A Postgres URL's parts around its database's name: `postgres://u@h`, the name (as the URL writes it, without
/// its `/`; empty when it names none), and `?...`.
fn parts(url: &str) -> Option<(&str, &str, &str)> {
    let authority = url.find("://")? + 3;
    let end = authority + url[authority..].find(['/', '?']).unwrap_or(url.len() - authority);
    let (path, query) = url[end..].split_at(url[end..].find('?').unwrap_or(url.len() - end));
    Some((&url[..end], path.strip_prefix('/').unwrap_or(path), query))
}

/// A URL from its parts, naming the database `name` (percent-encoded).
fn named(base: &str, name: &str, query: &str) -> String {
    let mut url = format!("{base}/");
    for b in name.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => url.push(char::from(b)),
            _ => {
                let _ = write!(url, "%{b:02X}"); // (to a String: it can't fail)
            }
        }
    }
    url + query
}

/// The name a URL writes, percent-decoded; `None` for an escape that isn't one, or bytes that aren't UTF-8.
fn decoded(text: &str) -> Option<String> {
    let mut bytes = Vec::new();
    let mut rest = text;
    while let Some(c) = rest.chars().next() {
        if c == '%' {
            let hex = rest.get(1..3).filter(|h| h.bytes().all(|b| b.is_ascii_hexdigit()));
            bytes.push(hex.and_then(|h| u8::from_str_radix(h, 16).ok())?);
            rest = &rest[3..];
        } else {
            bytes.extend_from_slice(&rest.as_bytes()[..c.len_utf8()]);
            rest = &rest[c.len_utf8()..];
        }
    }
    String::from_utf8(bytes).ok()
}

/// A database's name within Postgres's 63 bytes (see the module's doc): Postgres would cut a longer one at 63
/// bytes, where two workers' names, or a copy's and its original's, can come out the same.
fn fitted(name: &str) -> String {
    if name.len() <= 63 {
        return name.to_owned();
    }
    let mut end = 54;
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    let hash = Sha256::digest(name.as_bytes());
    format!("{}_{:02x}{:02x}{:02x}{:02x}", &name[..end], hash[0], hash[1], hash[2], hash[3])
}

/// What a URL that names no database to copy is not.
const COPY: &str = "a URL that names a database to copy";

/// The error for a URL that isn't what it should be.
fn not_a(url: &str, what: &str) -> Error {
    Error::Other(format!("rowstile::testing: {url:?} is not {what}").into())
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
/// A URL that names no database, an app role's URL that isn't a Postgres URL, the database's errors, and one that
/// says so when something is connected to the original.
pub async fn per_binary(tests_url: &str, app_url: Option<&str>, fresh: bool) -> Result<Database, Error> {
    let (base, path, query) = parts(tests_url).ok_or_else(|| not_a(tests_url, COPY))?;
    let template = decoded(path).filter(|name| !name.is_empty()).ok_or_else(|| not_a(tests_url, COPY))?;
    let name = fitted(&format!("{template}_{}", worker()));
    let mut app_named = None;
    if let Some(app) = app_url {
        let (base, _, query) = parts(app).ok_or_else(|| not_a(app, "a Postgres URL"))?;
        app_named = Some(named(base, &name, query));
    }
    let copied = Database { url: named(base, &name, query), app_url: app_named };
    // CREATE DATABASE ... TEMPLATE needs no one connected to the original, this connection included
    let (client, connection) = tokio_postgres::connect(&named(base, "postgres", query), NoTls).await?;
    let connected = tokio::spawn(connection);
    if fresh {
        // (a copy it can't drop is still there: the copy's CREATE says so)
        let _ = client.execute(&format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", ident(&name)), &[]).await;
    }
    let made = client.execute(&format!("CREATE DATABASE {} TEMPLATE {}", ident(&name), ident(&template)), &[]).await;
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
        _ => Ok(copied),
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
