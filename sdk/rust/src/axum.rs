//! rowstile in an Axum app, on sqlx: each request's transaction signed in as whoever it acts for ([`Tx`], an
//! extractor), and rowstile's errors answered as `application/problem+json` (an [`Error`] is a response).
//!
//! The app's state says where the pool is and who a request is ([`SignIn`]); a handler takes a [`Tx`] and
//! returns `Result<_, rowstile::Error>`, so `?` answers a refusal 403 and a hidden row 404:
//!
//! ```no_run
//! use axum::extract::Path;
//! use axum::http::request::Parts;
//! use rowstile::axum::{SignIn, Tx};
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
//!     fn principal(&self, request: &Parts) -> Result<Principal, Error> {
//!         Ok(Principal::Nobody) // the app's session or token says who it is
//!     }
//! }
//!
//! async fn delete_note(mut tx: Tx, Path(id): Path<i64>) -> Result<(), Error> {
//!     let deleted = sqlx::query("DELETE FROM app.notes WHERE id = $1").bind(id).execute(&mut *tx).await?;
//!     rowstile::sqlx::expect(&mut tx, deleted.rows_affected(), "app.notes", "delete", id).await?;
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

/// What an app's state says for [`Tx`]: the pool of the app role's connections, and who a request is.
pub trait SignIn: Send + Sync {
    /// The pool each request's transaction begins on.
    fn pool(&self) -> &PgPool;

    /// Who the request acts for, from its session or its token ([`Principal::Nobody`]: only what `anyone` may
    /// see). An error is the request's answer: [`Error::unauthorized`] for a bad token (401).
    ///
    /// # Errors
    ///
    /// The request's answer, when it can't be told who sent it.
    fn principal(&self, request: &Parts) -> Result<Principal, Error>;
}

/// A transaction signed in as whoever the request acts for: an extractor, for a state that is [`SignIn`]. It is
/// a connection (`&mut *tx` runs a query); [`Tx::commit`] commits it, and a request that ends without commits
/// nothing.
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

    /// The transaction for who the state says the request is: what every app's extractor does, the same code.
    async fn begin(pool: &PgPool, who: Result<Principal, Error>) -> Result<Self, Error> {
        let who = who?;
        let tx = crate::sqlx::begin(pool, &who).await?;
        Ok(Self { tx, who })
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
        Self::begin(state.pool(), state.principal(parts)).await
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
