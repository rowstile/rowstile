//! rowstile in an Axum app, on sqlx: each request's transaction signed in as whoever it acts for ([`Tx`], an
//! extractor), and rowstile's errors answered as `application/problem+json` (an [`Error`] is a response).
//!
//! The app's state says where the pool is and who a request is ([`SignIn`]); a handler takes a [`Tx`] and
//! returns `Result<_, rowstile::Error>`, so `?` answers a refusal 403 and a hidden row 404. A [`Tx`] holds a
//! connection from the moment Axum extracts it, and Axum extracts in the order the handler names them: name `Path`
//! and `Query` before it, and in a handler that reads a body take [`SignedIn`] instead, and begin once the body is
//! read.
//!
//! ```no_run
//! use axum::extract::Path;
//! use axum::http::request::Parts;
//! use rowstile::axum::{SignIn, SignedIn, Tx};
//! use rowstile::{Error, Principal};
//!
//! #[derive(Clone)]
//! struct App {
//!     pool: sqlx::PgPool,
//! }
//!
//! impl SignIn for App {
//!     fn pool(&self) -> &sqlx::PgPool {
//!         &self.pool
//!     }
//!     async fn principal(&self, request: &mut Parts) -> Result<Principal, Error> {
//!         Ok(Principal::Nobody) // the app's session or token says who it is (looked up, if need be)
//!     }
//! }
//!
//! async fn delete_note(Path(id): Path<i64>, mut tx: Tx) -> Result<(), Error> {
//!     let deleted = sqlx::query("DELETE FROM app.notes WHERE id = $1").bind(id).execute(&mut *tx).await?;
//!     rowstile::sqlx::expect(&mut tx, deleted.rows_affected(), "app.notes", "delete", id).await?;
//!     tx.commit().await
//! }
//!
//! async fn edit_note(Path(id): Path<i64>, who: SignedIn, body: String) -> Result<(), Error> {
//!     let mut tx = who.begin().await?; // the body is read: now a connection
//!     let edited = sqlx::query("UPDATE app.notes SET body = $2 WHERE id = $1").bind(id).bind(body);
//!     let edited = edited.execute(&mut *tx).await?;
//!     rowstile::sqlx::expect(&mut tx, edited.rows_affected(), "app.notes", "update", id).await?;
//!     tx.commit().await
//! }
//! ```

use std::ops::{Deref, DerefMut};

use ::axum::extract::FromRequestParts;
use ::axum::http::request::Parts;
use ::axum::http::{StatusCode, header};
use ::axum::response::{IntoResponse, Response};
use ::sqlx::{PgConnection, PgPool, Postgres, Transaction};

use crate::{Error, Principal};

/// What an app's state says for [`Tx`] and [`SignedIn`]: the pool of the app role's connections, and who a
/// request is.
pub trait SignIn: Send + Sync {
    /// The pool each request's transaction begins on.
    fn pool(&self) -> &PgPool;

    /// Who the request acts for, from its session or its token ([`Principal::Nobody`]: only what `anyone` may
    /// see). An error is the request's answer: [`Error::unauthorized`] for a bad token (401). It may wait for an
    /// answer from elsewhere (a session kept in a database, a key set fetched over the network), and may run
    /// another extractor on the request (a session's, a cookie jar's): it is an `async fn` in the app's impl, and
    /// it runs before any connection is taken from the pool.
    ///
    /// # Errors
    ///
    /// The request's answer, when it can't be told who sent it.
    fn principal(&self, request: &mut Parts) -> impl Future<Output = Result<Principal, Error>> + Send;
}

/// Who the request acts for, and where to begin its transaction: an extractor, for a state that is [`SignIn`],
/// which holds no connection. A handler that reads a body takes this: Axum reads the body after every other
/// extractor, so a [`Tx`] would hold a connection, its transaction open, while the client sends it. Once the body is
/// read, [`SignedIn::begin`] begins the transaction.
pub struct SignedIn {
    pool: PgPool,
    who: Principal,
}

impl SignedIn {
    /// Who the request acts for.
    #[must_use]
    pub fn principal(&self) -> &Principal {
        &self.who
    }

    /// The transaction, signed in as who the request acts for: a connection taken from the pool now.
    ///
    /// # Errors
    ///
    /// The database's, translated.
    pub async fn begin(self) -> Result<Tx, Error> {
        let tx = crate::sqlx::begin(&self.pool, &self.who).await?;
        Ok(Tx { tx, who: self.who })
    }
}

impl<S: SignIn> FromRequestParts<S> for SignedIn {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Error> {
        let who = state.principal(parts).await?;
        Ok(Self { pool: state.pool().clone(), who })
    }
}

/// A transaction signed in as whoever the request acts for: an extractor, for a state that is [`SignIn`]. It is
/// a connection (`&mut *tx` runs a query); [`Tx::commit`] commits it, and a request that ends without commits
/// nothing. It takes the connection when Axum extracts it, in the order the handler names its extractors: name
/// `Path` and `Query` before it, so that a request they turn down takes none, and take [`SignedIn`] instead in a
/// handler that reads a body.
pub struct Tx {
    tx: Transaction<'static, Postgres>,
    who: Principal,
}

impl Tx {
    /// Who the transaction acts for.
    #[must_use]
    pub fn principal(&self) -> &Principal {
        &self.who
    }

    /// Commits the transaction.
    ///
    /// # Errors
    ///
    /// The database's, translated: a deferred check that refuses the transaction's writes.
    pub async fn commit(self) -> Result<(), Error> {
        self.tx.commit().await.map_err(Error::from)
    }
}

impl Deref for Tx {
    type Target = PgConnection;

    fn deref(&self) -> &PgConnection {
        &self.tx
    }
}

impl DerefMut for Tx {
    fn deref_mut(&mut self) -> &mut PgConnection {
        &mut self.tx
    }
}

impl<S: SignIn> FromRequestParts<S> for Tx {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Error> {
        SignedIn::from_request_parts(parts, state).await?.begin().await
    }
}

impl IntoResponse for Error {
    /// rowstile's errors as `application/problem+json`, with the status [`Error::problem`] gives; any other is
    /// logged (`tracing`, at the error level) and answered 500.
    fn into_response(self) -> Response {
        if let Some(problem) = self.problem() {
            let status = StatusCode::from_u16(problem.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            return (status, [(header::CONTENT_TYPE, "application/problem+json")], problem.to_json().to_string())
                .into_response();
        }
        tracing::error!(error = %self, "rowstile: the request failed");
        (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response()
    }
}
