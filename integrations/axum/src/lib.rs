//! The conformance app: no permission checks anywhere. Each request's transaction signs in as its user (the
//! rowstile::axum::Tx extractor), the database filters reads and refuses writes, and the SDK answers a refusal 403
//! and a hidden row 404.

mod auth;
pub mod authz;

use axum::extract::{Path, Query};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use rowstile::axum::{SignIn, Tx};
use rowstile::{Error, Page, Permission, Principal};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::PgPool;
use std::collections::HashMap;

use crate::authz::ProjectPermission;

/// The app's state: the pool of the app role's connections, and who each request is.
#[derive(Clone)]
pub struct App {
    pool: PgPool,
}

impl SignIn for App {
    fn pool(&self) -> &PgPool {
        &self.pool
    }

    fn principal(&self, request: &Parts) -> Result<Principal, Error> {
        auth::session_user(request)
    }
}

/// The app's routes, on a pool of the app role's connections.
pub fn router(pool: PgPool) -> Router {
    Router::new()
        .route("/notes", get(notes).post(add_note))
        .route("/notes/{id}", patch(edit_note).delete(delete_note))
        .route("/notes/as/{user}", get(notes_as))
        .route("/projects", get(projects))
        .route("/projects/editable", get(editable_projects))
        .route("/projects/buttons", get(buttons))
        .route("/projects/page", get(page))
        .route("/projects/{id}/shares", get(shares))
        .route("/projects/{id}/requests", post(request_access))
        .route("/keys", post(create_key))
        .route("/keys/{id}", delete(revoke_key))
        .route("/folders/{id}", patch(move_folder))
        .route("/inbox", post(send_message))
        .route("/inbox/quietly", post(send_quietly))
        .with_state(App { pool })
}

/// The user the request acts for, as the tables' key.
fn signed_in(tx: &Tx) -> i64 {
    match tx.principal() {
        Principal::Signed { id, .. } => id.parse().unwrap_or_default(),
        Principal::Nobody => 0,
    }
}

async fn notes(mut tx: Tx) -> Result<Json<Vec<i64>>, Error> {
    let notes = sqlx::query_scalar("SELECT id FROM app.notes ORDER BY id").fetch_all(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(notes))
}

async fn projects(mut tx: Tx) -> Result<Json<Vec<i64>>, Error> {
    let projects = sqlx::query_scalar("SELECT id FROM app.projects ORDER BY id").fetch_all(&mut *tx).await?;
    Ok(Json(projects))
}

async fn editable_projects(mut tx: Tx) -> Result<Json<Vec<i64>>, Error> {
    // the projects the user may edit: a join on the ids authz.list gives, in the query
    let editable =
        "SELECT p.id FROM app.projects p JOIN authz.list('project', 'edit') x ON x = p.id::text ORDER BY p.id";
    Ok(Json(sqlx::query_scalar(editable).fetch_all(&mut *tx).await?))
}

async fn buttons(mut tx: Tx) -> Result<Json<HashMap<String, Vec<&'static str>>>, Error> {
    let projects: Vec<i64> = sqlx::query_scalar("SELECT id FROM app.projects ORDER BY id").fetch_all(&mut *tx).await?;
    let buttons = rowstile::sqlx::perms_of::<ProjectPermission>(&mut tx, &projects).await?;
    Ok(Json(buttons.into_iter().map(|(id, perms)| (id, perms.into_iter().map(Permission::name).collect())).collect()))
}

#[derive(Deserialize)]
struct PageQuery {
    #[serde(default)]
    limit: i32,
    after: Option<String>,
}

async fn page(mut tx: Tx, Query(q): Query<PageQuery>) -> Result<Json<Vec<String>>, Error> {
    // the projects the user may see, a page at a time: the database says when the size or the cursor is wrong
    let page = Page { after: q.after, limit: q.limit };
    let listed = rowstile::sqlx::list(&mut tx, ProjectPermission::View, Some(&page)).await?;
    Ok(Json(listed))
}

async fn revoke_key(mut tx: Tx, Path(id): Path<i64>) -> Result<StatusCode, Error> {
    // one of the user's API keys: someone else's, or one that isn't there, is 404
    sqlx::query("SELECT 1 FROM authz.revoke_api_key($1)").bind(id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct NewKey {
    name: String,
    principal_type: Option<String>,
    principal_id: Option<String>,
}

async fn create_key(mut tx: Tx, headers: HeaderMap, Json(k): Json<NewKey>) -> Result<(StatusCode, Json<Value>), Error> {
    // an API key, for the user or a principal whose keys they manage; a request that brings a key (x-api-key) signs
    // in with it first, in the same transaction: the database says who may make which
    if let Some(key) = headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
        sqlx::query("SELECT authz.login_key($1)").bind(key).execute(&mut *tx).await?;
    }
    let made = "SELECT authz.create_api_key($1, '', NULL, $2::text, $3::text)";
    let key: String =
        sqlx::query_scalar(made).bind(k.name).bind(k.principal_type).bind(k.principal_id).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(json!({"key": key}))))
}

async fn shares(mut tx: Tx, Path(id): Path<String>) -> Result<Json<Vec<String>>, Error> {
    let shared = "SELECT subject_id FROM authz.list_shares('project', $1::text)";
    Ok(Json(sqlx::query_scalar(shared).bind(id).fetch_all(&mut *tx).await?))
}

#[derive(Deserialize)]
struct Asked {
    relation: String,
    reason: String,
}

async fn request_access(
    mut tx: Tx,
    Path(id): Path<String>,
    Json(a): Json<Asked>,
) -> Result<(StatusCode, Json<Value>), Error> {
    // access asked for: the policy shares no relation of a project, so this is the app's mistake (a 500), once the
    // database knows who asks
    let asked = "SELECT authz.request_access('project', $1::text, $2, $3)";
    let id: i64 = sqlx::query_scalar(asked).bind(id).bind(a.relation).bind(a.reason).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(json!({"id": id}))))
}

async fn notes_as(mut tx: Tx, Path(user): Path<String>) -> Result<Json<Vec<i64>>, Error> {
    // who is signed in, changed by hand: the database doesn't believe it (the app's bug, a 500)
    sqlx::query("SELECT set_config('authz.user_id', $1, true)").bind(user).execute(&mut *tx).await?;
    Ok(Json(sqlx::query_scalar("SELECT id FROM app.notes ORDER BY id").fetch_all(&mut *tx).await?))
}

#[derive(Deserialize)]
struct Moved {
    parent_id: Option<i64>,
}

async fn move_folder(mut tx: Tx, Path(id): Path<i64>, Json(m): Json<Moved>) -> Result<Json<Value>, Error> {
    // inside one of its own subfolders: 409, the database's words
    let moved = sqlx::query("UPDATE app.folders SET parent_id = $2 WHERE id = $1")
        .bind(id)
        .bind(m.parent_id)
        .execute(&mut *tx)
        .await?;
    rowstile::sqlx::expect(&mut tx, moved.rows_affected(), "app.folders", "update", id).await?;
    tx.commit().await?;
    Ok(Json(json!({"id": id})))
}

#[derive(Deserialize)]
struct NewNote {
    project_id: i64,
    body: String,
}

async fn add_note(mut tx: Tx, Json(n): Json<NewNote>) -> Result<(StatusCode, Json<Value>), Error> {
    let author = signed_in(&tx);
    let added = "INSERT INTO app.notes (project_id, author_id, body) VALUES ($1, $2, $3) RETURNING id";
    // a refused insert: 403, with the rule and the reason
    let id: i64 = sqlx::query_scalar(added).bind(n.project_id).bind(author).bind(n.body).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(json!({"id": id}))))
}

#[derive(Deserialize)]
struct Edit {
    body: String,
}

async fn edit_note(mut tx: Tx, Path(id): Path<i64>, Json(e): Json<Edit>) -> Result<Json<Value>, Error> {
    let changed =
        sqlx::query("UPDATE app.notes SET body = $2 WHERE id = $1").bind(id).bind(e.body).execute(&mut *tx).await?;
    // 0 rows: expect asks the database why, and answers 404 (hidden) or 403 (with the reason)
    rowstile::sqlx::expect(&mut tx, changed.rows_affected(), "app.notes", "update", id).await?;
    tx.commit().await?;
    Ok(Json(json!({"id": id})))
}

async fn delete_note(mut tx: Tx, Path(id): Path<i64>) -> Result<StatusCode, Error> {
    let deleted = sqlx::query("DELETE FROM app.notes WHERE id = $1").bind(id).execute(&mut *tx).await?;
    rowstile::sqlx::expect(&mut tx, deleted.rows_affected(), "app.notes", "delete", id).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct Message {
    recipient_id: i64,
    body: String,
}

const SEND: &str = "INSERT INTO app.inbox (sender_id, recipient_id, body) VALUES ($1, $2, $3)";
const SEND_READ_BACK: &str = "INSERT INTO app.inbox (sender_id, recipient_id, body) VALUES ($1, $2, $3) RETURNING id";

async fn send_message(mut tx: Tx, Json(m): Json<Message>) -> Result<(StatusCode, Json<Value>), Error> {
    // reads the id back (RETURNING): only the recipient may read it
    let sender = signed_in(&tx);
    let id: i64 =
        sqlx::query_scalar(SEND_READ_BACK).bind(sender).bind(m.recipient_id).bind(m.body).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(json!({"id": id}))))
}

async fn send_quietly(mut tx: Tx, Json(m): Json<Message>) -> Result<(StatusCode, Json<Value>), Error> {
    // without reading the row back
    let sender = signed_in(&tx);
    sqlx::query(SEND).bind(sender).bind(m.recipient_id).bind(m.body).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok((StatusCode::ACCEPTED, Json(json!({}))))
}

/// A background job: it signs in as service 1, whatever started it, and counts the projects it may read.
///
/// # Errors
///
/// The database's, translated.
pub async fn digest(pool: &PgPool) -> Result<i64, Error> {
    let mut tx = rowstile::sqlx::begin(pool, &Principal::of("service", "1")).await?;
    let count = sqlx::query_scalar("SELECT count(*) FROM app.projects").fetch_one(&mut *tx).await?;
    tx.commit().await?;
    Ok(count)
}
