//! rowstile over sqlx's Postgres connections: a transaction signed in, the policy's questions, and refusals as
//! [`Error`]. The functions that ask take the transaction's connection: `&mut *tx`.
//!
//! ```no_run
//! # async fn notes(pool: &::sqlx::PgPool) -> Result<Vec<i64>, rowstile::Error> {
//! let mut tx = rowstile::sqlx::begin(pool, &rowstile::Principal::user("42")).await?;
//! let notes = ::sqlx::query_scalar("SELECT id FROM app.notes ORDER BY id").fetch_all(&mut *tx).await?;
//! tx.commit().await?;
//! Ok(notes)
//! # }
//! ```

use std::collections::HashMap;
use std::fmt::Display;

use ::sqlx::postgres::PgDatabaseError;
use ::sqlx::{PgConnection, PgPool, Postgres, Transaction};

use crate::queries::{ACT_AS, CAN, CONNECTION_CHECK, EXPLAIN_RULE, LIST, PERMS_OF, act_as, perms_by_id, unchanged};
use crate::{DbError, Error, Page, Permission, Principal};

impl From<::sqlx::Error> for Error {
    /// The database's error as rowstile's when it is one ([`Error::from_database`]); any other [`Error::Other`].
    fn from(e: ::sqlx::Error) -> Self {
        match e.as_database_error().and_then(|db| db.try_downcast_ref::<PgDatabaseError>()) {
            Some(db) => Self::from_database(DbError {
                sqlstate: db.code().to_owned(),
                message: db.message().to_owned(),
                detail: db.detail().map(str::to_owned),
                hint: db.hint().map(str::to_owned),
                schema: db.schema().map(str::to_owned),
                table: db.table().map(str::to_owned),
                constraint: db.constraint().map(str::to_owned),
                source: Some(Box::new(e)),
            }),
            None => Self::Other(Box::new(e)),
        }
    }
}

/// A transaction on the pool, signed in as `who` (`authz.act_as`): commit it, or drop it to roll it back. The
/// sign-in lasts the transaction alone, so pools and poolers in transaction mode are safe.
///
/// # Errors
///
/// The database's, translated.
pub async fn begin(pool: &PgPool, who: &Principal) -> Result<Transaction<'static, Postgres>, Error> {
    let mut tx = pool.begin().await?;
    let (principal_type, id) = act_as(who);
    ::sqlx::query(ACT_AS).bind(principal_type).bind(id).execute(&mut *tx).await?;
    Ok(tx)
}

/// Nothing when row-level security applies to the pool's connections, and [`Error::Connection`] when it skips them
/// (a superuser, BYPASSRLS, the tables' owner): call it at start-up, and refuse to start on an error.
///
/// # Errors
///
/// [`Error::Connection`], or the database's.
pub async fn check(pool: &PgPool) -> Result<(), Error> {
    let problems: Vec<String> = ::sqlx::query_scalar(CONNECTION_CHECK).fetch_all(pool).await?;
    if problems.is_empty() { Ok(()) } else { Err(Error::Connection(crate::ConnectionProblem { problems })) }
}

// The calls generic over the policy's names say them in words to these, which hold what each call does: an app's
// every use of them runs the same code.

/// Whether whoever the transaction signed in as holds `perm` on the object with this id:
/// `can(&mut *tx, NotePermission::Edit, 7)`.
///
/// # Errors
///
/// The database's, translated: [`Error::NotSignedIn`] outside a signed-in transaction.
pub async fn can<P: Permission>(conn: &mut PgConnection, perm: P, id: impl Display) -> Result<bool, Error> {
    can_named(conn, P::OBJECT_TYPE, perm.name(), id.to_string()).await
}

async fn can_named(conn: &mut PgConnection, kind: &str, perm: &str, id: String) -> Result<bool, Error> {
    let query = ::sqlx::query_scalar(CAN).bind(kind).bind(id).bind(perm);
    query.fetch_one(conn).await.map_err(Error::from)
}

/// The permissions held on each of these objects, by id as the database writes it, in one call (a list's
/// buttons): `perms_of::<ProjectPermission>(&mut *tx, &ids)`.
///
/// # Errors
///
/// The database's, translated.
pub async fn perms_of<P: Permission>(
    conn: &mut PgConnection,
    ids: &[impl Display],
) -> Result<HashMap<String, Vec<P>>, Error> {
    perms_named(conn, P::OBJECT_TYPE, ids.iter().map(ToString::to_string).collect()).await.map(perms_by_id)
}

async fn perms_named(
    conn: &mut PgConnection,
    kind: &str,
    ids: Vec<String>,
) -> Result<Vec<(String, Vec<String>)>, Error> {
    ::sqlx::query_as(PERMS_OF).bind(kind).bind(ids).fetch_all(conn).await.map_err(Error::from)
}

/// The ids of the objects of `perm`'s type on which whoever the transaction signed in as holds `perm`, in key
/// order; with a page, that page alone (the database says when its size or its cursor is wrong: [`Error::Call`],
/// 400). To filter a query to them instead, join `authz.list(type, perm)` in it.
///
/// # Errors
///
/// The database's, translated.
pub async fn list<P: Permission>(conn: &mut PgConnection, perm: P, page: Option<&Page>) -> Result<Vec<String>, Error> {
    list_named(conn, P::OBJECT_TYPE, perm.name(), page).await
}

async fn list_named(
    conn: &mut PgConnection,
    kind: &str,
    perm: &str,
    page: Option<&Page>,
) -> Result<Vec<String>, Error> {
    let (after, limit) = page.map_or((None, None), |p| (p.after.clone(), Some(p.limit)));
    let query = ::sqlx::query_scalar(LIST).bind(kind).bind(perm).bind(after).bind(limit);
    query.fetch_all(conn).await.map_err(Error::from)
}

/// Nothing when an UPDATE or DELETE changed rows (`affected`: its `rows_affected()`). When it changed none,
/// row-level security left the row out: `expect` asks the database why, in the same transaction, and gives
/// [`Error::NotFound`] (the user can't see the row, or the statement matched nothing for another reason, such as a
/// WHERE with more than the key) or [`Error::Refused`], worded as the database words a refused insert:
/// `permission denied: user 2 may not update row 7 of app.notes`. `key`: the row's key, or
/// [`crate::composite_key`] for a key of several columns.
///
/// # Errors
///
/// [`Error::NotFound`], [`Error::Refused`], or the database's.
pub async fn expect(
    conn: &mut PgConnection,
    affected: u64,
    table: &str,
    command: &str,
    key: impl Display,
) -> Result<(), Error> {
    expect_named(conn, affected, table, command, key.to_string()).await
}

async fn expect_named(
    conn: &mut PgConnection,
    affected: u64,
    table: &str,
    command: &str,
    key: String,
) -> Result<(), Error> {
    if affected > 0 {
        return Ok(());
    }
    let (why, who, named): (Option<Vec<String>>, String, String) =
        ::sqlx::query_as(EXPLAIN_RULE).bind(table).bind(command).bind(&key).fetch_one(conn).await?;
    Err(unchanged(why, &who, named, command, key))
}
