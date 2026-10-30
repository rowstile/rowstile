//! rowstile over tokio-postgres: a transaction signed in, the policy's questions, and refusals as [`Error`].
//!
//! ```no_run
//! # async fn notes(client: &mut tokio_postgres::Client) -> Result<Vec<i64>, rowstile::Error> {
//! let tx = rowstile::pg::begin(client, &rowstile::Principal::user("42")).await?;
//! let rows = tx.query("SELECT id FROM app.notes ORDER BY id", &[]).await?;
//! tx.commit().await?;
//! Ok(rows.iter().map(|row| row.get(0)).collect())
//! # }
//! ```

use std::collections::HashMap;
use std::fmt::Display;

use tokio_postgres::{Client, Transaction};

use crate::queries::{ACT_AS, CAN, CONNECTION_CHECK, EXPLAIN_RULE, LIST, PERMS_OF, act_as, perms_by_id, unchanged};
use crate::{DbError, Error, Page, Permission, Principal};

impl From<tokio_postgres::Error> for Error {
    /// The database's error as rowstile's when it is one ([`Error::from_database`]); the connection's
    /// [`Error::Other`].
    fn from(e: tokio_postgres::Error) -> Self {
        match e.as_db_error() {
            Some(db) => Self::from_database(DbError {
                sqlstate: db.code().code().to_owned(),
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

/// A transaction on `client`, signed in as `who` (`authz.act_as`): commit it, or drop it to roll it back. The
/// sign-in lasts the transaction alone, so pools and poolers in transaction mode are safe. A pooled client
/// (deadpool's, bb8's) derefs to a [`Client`].
///
/// # Errors
///
/// The database's, translated.
pub async fn begin<'a>(client: &'a mut Client, who: &Principal) -> Result<Transaction<'a>, Error> {
    let tx = client.transaction().await?;
    let (principal_type, id) = act_as(who);
    tx.execute(ACT_AS, &[&principal_type, &id]).await?;
    Ok(tx)
}

/// Nothing when row-level security applies to this connection, and [`Error::Connection`] when it skips it (a
/// superuser, BYPASSRLS, the tables' owner): call it at start-up, and refuse to start on an error.
///
/// # Errors
///
/// [`Error::Connection`], or the database's.
pub async fn check(client: &Client) -> Result<(), Error> {
    let rows = client.query(CONNECTION_CHECK, &[]).await?;
    let problems: Vec<String> = rows.iter().map(|row| row.get(0)).collect();
    if problems.is_empty() { Ok(()) } else { Err(Error::Connection(crate::ConnectionProblem { problems })) }
}

// The calls generic over the policy's names say them in words to these, which hold what each call does: an app's
// every use of them runs the same code. They ask in the transaction `begin` gave (a pooled one derefs to it).

/// Whether whoever the transaction signed in as holds `perm` on the object with this id:
/// `can(&tx, NotePermission::Edit, 7)`.
///
/// # Errors
///
/// The database's, translated: [`Error::NotSignedIn`] in a transaction nobody signed in to.
pub async fn can<P: Permission>(tx: &Transaction<'_>, perm: P, id: impl Display) -> Result<bool, Error> {
    can_named(tx, P::OBJECT_TYPE, perm.name(), id.to_string()).await
}

async fn can_named(tx: &Transaction<'_>, kind: &str, perm: &str, id: String) -> Result<bool, Error> {
    tx.query_one(CAN, &[&kind, &id, &perm]).await.map(|row| row.get(0)).map_err(Error::from)
}

/// The permissions held on each of these objects, by id as the database writes it, in one call (a list's
/// buttons): `perms_of::<ProjectPermission>(&tx, &ids)`.
///
/// # Errors
///
/// The database's, translated.
pub async fn perms_of<P: Permission>(
    tx: &Transaction<'_>,
    ids: &[impl Display],
) -> Result<HashMap<String, Vec<P>>, Error> {
    perms_named(tx, P::OBJECT_TYPE, ids.iter().map(ToString::to_string).collect()).await.map(perms_by_id)
}

async fn perms_named(tx: &Transaction<'_>, kind: &str, ids: Vec<String>) -> Result<Vec<(String, Vec<String>)>, Error> {
    let rows = tx.query(PERMS_OF, &[&kind, &ids]).await?;
    Ok(rows.iter().map(|row| (row.get(0), row.get(1))).collect())
}

/// The ids of the objects of `perm`'s type on which whoever the transaction signed in as holds `perm`, in key
/// order; with a page, that page alone (the database says when its size or its cursor is wrong: [`Error::Call`],
/// 400). To filter a query to them instead, join `authz.list(type, perm)` in it.
///
/// # Errors
///
/// The database's, translated.
pub async fn list<P: Permission>(tx: &Transaction<'_>, perm: P, page: Option<&Page>) -> Result<Vec<String>, Error> {
    list_named(tx, P::OBJECT_TYPE, perm.name(), page).await
}

async fn list_named(tx: &Transaction<'_>, kind: &str, perm: &str, page: Option<&Page>) -> Result<Vec<String>, Error> {
    let (after, limit) = page.map_or((None, None), |p| (p.after.as_deref(), Some(p.limit)));
    let rows = tx.query(LIST, &[&kind, &perm, &after, &limit]).await?;
    Ok(rows.iter().map(|row| row.get(0)).collect())
}

/// Nothing when an UPDATE or DELETE changed rows (`affected`: what `execute` returned). When it changed none,
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
    tx: &Transaction<'_>,
    affected: u64,
    table: &str,
    command: &str,
    key: impl Display,
) -> Result<(), Error> {
    expect_named(tx, affected, table, command, key.to_string()).await
}

async fn expect_named(
    tx: &Transaction<'_>,
    affected: u64,
    table: &str,
    command: &str,
    key: String,
) -> Result<(), Error> {
    if affected > 0 {
        return Ok(());
    }
    let row = tx.query_one(EXPLAIN_RULE, &[&table, &command, &key]).await?;
    Err(unchanged(row.get(0), row.get(1), row.get(2), command, key))
}
