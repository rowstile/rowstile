//! rowstile for Rust apps (a preview: it may change in any release; it is not part of what 1.0 keeps stable).
//!
//! Every transaction signs in as whoever the request (or the job) acts for, with `authz.act_as()`; the database
//! filters what it reads and refuses what it may not write. This crate holds no rowstile logic: it calls the
//! `authz.*` functions the policy made, and translates their answers. A refused write is [`Error::Refused`] (a 403
//! with the rule and the reason), a row the user can't see [`Error::NotFound`] (a 404), and the other codes the
//! runtime answers with [`Error::Call`] (each with its page's status).
//!
//! - [`pg`]: over tokio-postgres (the default feature).
//! - [`sqlx`]: over sqlx's Postgres connections (the `sqlx` feature).
//! - [`axum`]: a transaction signed in for each request, and rowstile's errors answered as problem bodies (the
//!   `axum` feature).
//! - [`testing`]: a copy of the migrated test database for each test binary, and assertions (the `testing` feature).
//!
//! ```no_run
//! # async fn edit(pool: &::sqlx::PgPool, body: &str, id: i64) -> Result<(), rowstile::Error> {
//! let mut tx = rowstile::sqlx::begin(pool, &rowstile::Principal::user("42")).await?;
//! let changed = ::sqlx::query("UPDATE app.notes SET body = $1 WHERE id = $2")
//!     .bind(body)
//!     .bind(id)
//!     .execute(&mut *tx)
//!     .await? // a refused write: Error::Refused
//!     .rows_affected();
//! // no row changed: the database says why (Error::NotFound, or Error::Refused with the reason)
//! rowstile::sqlx::expect(&mut tx, changed, "app.notes", "update", id).await?;
//! tx.commit().await?;
//! # Ok(())
//! # }
//! ```
//!
//! The policy's names come from `rowstile client rust`: each type's permissions are an enum implementing
//! [`Permission`], which `can`, `perms_of` and `list` take, so a misspelled name doesn't compile.
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod error;
#[cfg(any(feature = "tokio-postgres", feature = "sqlx"))]
mod queries;

pub use error::{CallError, CallKind, ConnectionProblem, DbError, Error, NotFound, Problem, Refused};

#[cfg(feature = "tokio-postgres")]
pub mod pg;

#[cfg(feature = "sqlx")]
pub mod sqlx;

#[cfg(feature = "axum")]
pub mod axum;

#[cfg(feature = "testing")]
pub mod testing;

/// Who a transaction acts for: a user, another principal type the policy declares (a service, a bot), or nobody
/// (only what `anyone` may see).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum Principal {
    /// No one signed in: only what `anyone` may see.
    #[default]
    Nobody,
    /// A principal of the policy: `principal_type` is `user` for a user.
    Signed {
        /// The principal's type, as the policy names it: `user`, `service`, ...
        principal_type: String,
        /// Its id, as text: `42`.
        id: String,
    },
}

impl Principal {
    /// The user whose id this is, whatever it holds (`service:3` too: ids come from outside).
    pub fn user(id: impl Into<String>) -> Self {
        Self::of("user", id)
    }

    /// A principal of another type the policy declares: `Principal::of("service", "3")`.
    pub fn of(principal_type: impl Into<String>, id: impl Into<String>) -> Self {
        Self::Signed { principal_type: principal_type.into(), id: id.into() }
    }
}

/// A permission of a type the policy declares, as `rowstile client rust` writes them: each type's permissions are
/// an enum (`NotePermission::Edit`), so a misspelled one doesn't compile, and neither does a plain string where
/// [`pg::can`] or [`sqlx::can`] take a permission.
pub trait Permission: Copy + Sized + 'static {
    /// The type these are permissions of, as the policy names it: `note`.
    const OBJECT_TYPE: &'static str;

    /// This permission's name, as the policy writes it: `edit`.
    fn name(self) -> &'static str;

    /// The permission of this name, if the type has one.
    fn from_name(name: &str) -> Option<Self>;
}

/// A page of a list: the ids after `after` (none: from the first), `limit` of them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Page {
    /// The last id of the page before, as the database writes it.
    pub after: Option<String>,
    /// How many ids.
    pub limit: i32,
}

/// A key of several columns as Postgres writes a row's key, and as the `authz.*` functions read it: `(1,2)`, a
/// field quoted only where Postgres would (empty, or holding a comma, a quote, a backslash, a parenthesis or a
/// space), and nothing for a NULL. A key of one column is its value as text: `7`.
#[must_use]
pub fn composite_key(fields: &[Option<&str>]) -> String {
    let shown: Vec<String> = fields
        .iter()
        .map(|field| match field {
            Some(text) if text.is_empty() || text.contains(|c: char| ",\"\\() \t\n\r\x0b\x0c".contains(c)) => {
                format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\"\""))
            }
            Some(text) => (*text).to_owned(),
            None => String::new(),
        })
        .collect();
    format!("({})", shown.join(","))
}
