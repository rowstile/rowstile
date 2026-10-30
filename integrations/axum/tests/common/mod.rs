//! What both test binaries share: their own copy of the migrated test database (check 12: cargo test runs each test
//! binary in a process of its own, so each binary is a worker), the same few rows in it, the app on it, and the
//! lines the checks print.
#![allow(dead_code)]

use std::sync::OnceLock;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use rowstile::testing::Database;
use serde_json::Value;
use tower::ServiceExt;

/// The same few rows for every test: ann (1) owns project 1 (cy is a member, service 1 reads it) and the public
/// project 3; bo (2) owns project 2. Ann's folder 1 has folder 2 inside it.
pub const DATA: &str = "
TRUNCATE app.folders, app.inbox, app.notes, app.members, app.project_services, app.projects, app.services,
  app.users CASCADE;
INSERT INTO app.users VALUES (1, 'ann'), (2, 'bo'), (3, 'cy');
INSERT INTO app.services VALUES (1, 'digest');
INSERT INTO app.projects VALUES (1, 1, 'Plans', false), (2, 2, 'Bo''s', false), (3, 1, 'Open', true);
INSERT INTO app.members VALUES (1, 3);
INSERT INTO app.project_services VALUES (1, 1);
INSERT INTO app.notes (id, project_id, author_id, body) VALUES
  (1, 1, 1, 'plan'), (2, 2, 2, 'mine'), (3, 3, 1, 'hello'), (4, 1, 3, 'idea');
SELECT setval(pg_get_serial_sequence('app.notes', 'id'), 100);
INSERT INTO app.folders VALUES (1, NULL, 1, 'top'), (2, 1, 1, 'inside');";

/// This binary's copy of the migrated test database, made once, with the rows in it. Each test runs on a runtime
/// of its own (tokio::test), and a pool is tied to the runtime that made it: the copy is made on one of its own,
/// in a thread of its own, and each test makes its pool.
pub fn copied() -> &'static Database {
    static COPIED: OnceLock<Database> = OnceLock::new();
    COPIED.get_or_init(|| {
        std::thread::spawn(|| {
            let runtime = tokio::runtime::Runtime::new().expect("a runtime");
            runtime.block_on(async {
                let tests = std::env::var("ROWSTILE_TESTS_URL").expect("ROWSTILE_TESTS_URL (test.sh sets it)");
                let app = std::env::var("ROWSTILE_APP_URL").expect("ROWSTILE_APP_URL (test.sh sets it)");
                let db = rowstile::testing::per_binary(&tests, Some(&app), true).await.expect("a copy");
                as_owner(&db, DATA).await;
                db
            })
        })
        .join()
        .expect("the copy")
    })
}

/// Runs SQL on this binary's database as the tables' owner.
pub async fn as_owner(db: &Database, sql: &str) {
    let (client, connection) = tokio_postgres::connect(&db.url, tokio_postgres::NoTls).await.expect("the owner");
    let connected = tokio::spawn(connection);
    client.batch_execute(sql).await.expect("as the owner");
    drop(client);
    connected.await.expect("closed").expect("closed");
}

/// A pool of the app role's connections on this binary's database.
pub async fn pool() -> sqlx::PgPool {
    sqlx::PgPool::connect(copied().app_url.as_deref().expect("the app role's URL")).await.expect("the app's pool")
}

/// The app, on a pool of the app role's connections.
pub async fn app() -> Router {
    conformance::router(pool().await)
}

/// A check's line, printed when the test ends (when this is dropped), as the other suites print theirs: ok, or
/// FAIL when the test panicked.
pub struct Check(pub &'static str);

impl Drop for Check {
    fn drop(&mut self) {
        // on a line of its own: cargo test has written the test's name on the line before
        println!("\n{}  {}", if std::thread::panicking() { "FAIL" } else { "ok  " }, self.0);
    }
}

/// A response: its status, its content type and its body.
pub struct Answer {
    pub status: StatusCode,
    pub kind: String,
    pub body: Vec<u8>,
}

impl Answer {
    /// Its body as JSON.
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|_| panic!("not JSON ({}): {}", self.status, String::from_utf8_lossy(&self.body)))
    }
}

/// Sends a request to the app, as `user` (a user's id; "" is nobody), with headers and a JSON body (`Value::Null`:
/// none).
pub async fn call(app: &Router, method: &str, path: &str, user: &str, body: Value, headers: &[(&str, &str)]) -> Answer {
    let mut request = Request::builder().method(method).uri(path);
    if !user.is_empty() {
        request = request.header("x-user", user);
    }
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let body = if body.is_null() {
        Body::empty()
    } else {
        request = request.header("content-type", "application/json");
        Body::from(body.to_string())
    };
    let response = app.clone().oneshot(request.body(body).expect("a request")).await.expect("an answer");
    let status = response.status();
    let kind = response.headers().get("content-type").map_or("", |v| v.to_str().unwrap_or("")).to_owned();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.expect("the body").to_vec();
    Answer { status, kind, body }
}

/// The problem body of a call the database turned down.
pub fn problem(kind: &str, title: &str, status: u16, detail: &str, code: &str) -> Value {
    serde_json::json!({"type": format!("https://rowstile.dev/problems/{kind}"), "title": title, "status": status,
        "detail": detail, "code": code})
}
