//! The conformance suite (integrations/README.md): the same checks for every stack. This is Axum and sqlx, with
//! sqlx's migrations. test.sh does check 11 (a fresh database: migrate, the policy's tests, then sqlx's own list of
//! migrations shows nothing left to run), the server's half of check 13, and checks 9 and 14 (they compile Rust)
//! before and after these run, one at a time (cargo test --test-threads=1): a check that writes leaves its rows
//! for the next, as the other suites' do.

mod common;

use std::fmt::Debug;
use std::sync::Mutex;

use common::{Answer, Check, app, call, copied, pool, problem};
use conformance::authz::{NotePermission, ProjectPermission};
use rowstile::{Error, Principal};
use serde_json::{Value, json};
use sqlx::Executor;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

/// The notes each may see (the projects: nobody sees project 3 alone).
fn expected(user: &str) -> Value {
    match user {
        "1" | "3" => json!([1, 3, 4]),
        "2" => json!([2, 3]),
        _ => json!([3]),
    }
}

#[tokio::test]
async fn check_01_and_02_lists_show_what_each_may_see() {
    let _two = Check("2: signed out on purpose, only what anyone may see"); // (said last: dropped last first)
    let _one = Check("1: signed in, a list shows only the user's rows");
    let app = app().await;
    for user in ["1", "2", "3", ""] {
        assert_eq!(call(&app, "GET", "/notes", user, Value::Null, &[]).await.json(), expected(user), "user {user:?}");
    }
    assert_eq!(call(&app, "GET", "/projects", "", Value::Null, &[]).await.json(), json!([3]));
}

#[tokio::test]
async fn check_03_not_signed_in_is_an_error_that_says_how() {
    let _check = Check("3: not signed in: the not-signed-in error (AZ701), naming act_as");
    let pool = pool().await;
    let mut tx = pool.begin().await.unwrap();
    let err = Error::from(tx.execute("SELECT count(*) FROM app.notes").await.unwrap_err());
    let Error::NotSignedIn(db) = &err else { panic!("not the not-signed-in error: {err:?}") };
    assert_eq!(db.sqlstate, "28000");
    assert!(db.hint.as_deref().unwrap_or("").contains("act_as"), "{db:?}");
    assert_eq!(err.code(), Some("AZ701")); // rowstile help AZ701
    // the SDK's calls outside a signed-in transaction: the same error, which says how, and a 500
    let err = rowstile::sqlx::can(&mut pool.acquire().await.unwrap(), NotePermission::View, 1).await.unwrap_err();
    assert!(matches!(err, Error::NotSignedIn(_)), "{err:?}");
    assert!(err.to_string().contains("every transaction must begin with authz.act_as()"), "{err}");
    assert!(err.problem().is_none(), "the not-signed-in error is the app's bug, a 500");
}

#[tokio::test]
async fn check_04_a_pooled_connection_carries_no_one_over() {
    let _check =
        Check("4: with a pool of one connection, a request as Ann, then one as Bob: Bob never sees Ann's rows");
    let url = copied().app_url.clone().unwrap();
    let one = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect(&url).await.unwrap();
    let app = conformance::router(one.clone());
    for user in ["1", "2", ""] {
        assert_eq!(call(&app, "GET", "/notes", user, Value::Null, &[]).await.json(), expected(user), "user {user:?}");
    }
    // a transaction that commits (a folder moved where it is): a rollback undoes even a session's settings
    let moved = call(&app, "PATCH", "/folders/2", "1", json!({"parent_id": 1}), &[]).await;
    assert_eq!(moved.status, 200, "{}", moved.json());
    // each request signed in again, so the answers alone can't tell: the pool's one connection, as the last request
    // left it, outside a transaction anyone signed in to, holds no one
    let mut conn = one.acquire().await.unwrap();
    let who: Option<String> =
        sqlx::query_scalar("SELECT current_setting('authz.user_id', true)").fetch_one(&mut *conn).await.unwrap();
    assert!(who.unwrap_or_default().is_empty(), "the connection still holds someone");
    let err = Error::from(conn.execute("SELECT count(*) FROM app.notes").await.unwrap_err());
    assert_eq!(err.code(), Some("AZ701"), "{err:?}");
}

#[tokio::test]
async fn check_05_concurrent_requests_never_mix_users() {
    let _check = Check("5: concurrent requests never mix users");
    let app = app().await;
    let mut requests = tokio::task::JoinSet::new();
    for i in 0..40 {
        let (app, user) = (app.clone(), ["1", "2", "3", ""][i % 4]);
        requests.spawn(async move { (user, call(&app, "GET", "/notes", user, Value::Null, &[]).await.json()) });
    }
    while let Some(answer) = requests.join_next().await {
        let (user, notes) = answer.unwrap();
        assert_eq!(notes, expected(user), "user {user:?}");
    }
}

#[tokio::test]
async fn check_06_a_refused_insert_says_which_rule() {
    let _check = Check("6: a refused insert: 403 with the problem body naming the rule");
    let a = call(&app().await, "POST", "/notes", "2", json!({"project_id": 3, "body": "hi"}), &[]).await;
    let body = a.json();
    assert_eq!((a.status.as_u16(), a.kind.as_str()), (403, "application/problem+json"), "{body}");
    assert_eq!(
        (&body["table"], &body["command"], &body["code"]),
        (&json!("app.notes"), &json!("insert"), &json!("AZ709"))
    );
    assert!(body["detail"].as_str().unwrap().contains("user 2 may not insert this row into app.notes"), "{body}");
    assert!(body["why"].to_string().contains("project.edit"), "{body}");
}

#[tokio::test]
async fn check_07_hidden_is_404_and_not_allowed_is_403() {
    let _check =
        Check("7: an update of a hidden row: 404; of a visible row the user may not edit: 403, with the reason");
    let app = app().await;
    let hidden = call(&app, "PATCH", "/notes/1", "2", json!({"body": "x"}), &[]).await;
    let refused = call(&app, "PATCH", "/notes/1", "3", json!({"body": "x"}), &[]).await;
    let mine = call(&app, "PATCH", "/notes/4", "3", json!({"body": "better idea"}), &[]).await;
    let gone = call(&app, "DELETE", "/notes/2", "1", Value::Null, &[]).await;
    let no = call(&app, "DELETE", "/notes/1", "3", Value::Null, &[]).await;
    assert_eq!(hidden.status, 404);
    assert_eq!(
        hidden.json(),
        json!({"type": "https://rowstile.dev/problems/not-found", "title": "Not Found", "status": 404,
            "detail": "app.notes 1 not found"})
    );
    let r = refused.json();
    assert_eq!((refused.status.as_u16(), &r["command"]), (403, &json!("update")), "{r}");
    assert!(r["why"].to_string().contains("edit"), "{r}");
    // worded as the database words a refused insert: who, the command, the row, the table
    assert_eq!(r["detail"], "permission denied: user 3 may not update row 1 of app.notes");
    assert_eq!((mine.status.as_u16(), gone.status.as_u16()), (200, 404));
    let d = no.json();
    assert_eq!((no.status.as_u16(), &d["command"]), (403, &json!("delete")), "{d}");
    assert_eq!(d["detail"], "permission denied: user 3 may not delete row 1 of app.notes");
}

#[tokio::test]
async fn check_08_insert_then_read_back() {
    let _check = Check("8: insert, then read back, works when the select rule allows it, and is explained when not");
    let app = app().await;
    let ok = call(&app, "POST", "/notes", "1", json!({"project_id": 1, "body": "new"}), &[]).await;
    let unreadable = call(&app, "POST", "/inbox", "1", json!({"recipient_id": 2, "body": "hi bo"}), &[]).await;
    let quiet = call(&app, "POST", "/inbox/quietly", "1", json!({"recipient_id": 2, "body": "hi bo"}), &[]).await;
    assert_eq!(ok.status, 201);
    assert!(ok.json()["id"].as_i64().unwrap() > 100, "{}", ok.json());
    let u = unreadable.json();
    assert_eq!((unreadable.status.as_u16(), &u["command"]), (403, &json!("select")), "{u}");
    assert!(u["detail"].as_str().unwrap().contains("may not see the row as written"), "{u}");
    assert_eq!(quiet.status, 202);
}

#[tokio::test]
async fn check_10_a_job_acts_as_its_service() {
    let _check = Check("10: a background job signs in as a service principal");
    // whatever started it: service 1 sees two projects (the one it is added to, the public one)
    assert_eq!(conformance::digest(&pool().await).await.unwrap(), 2);
}

#[tokio::test]
async fn check_12_a_test_database_per_binary_has_the_policy() {
    let _check = Check("12: the test database has the policy: a copy of the migrated one for each test binary");
    let tests = std::env::var("ROWSTILE_TESTS_URL").unwrap();
    let template = tests.rsplit('/').next().unwrap(); // the migrated test database (test.sh's conf_tests)
    let db = copied();
    let name = db.url.rsplit('/').next().unwrap();
    let hash = name.strip_prefix(&format!("{template}_conformance_")).unwrap_or_else(|| panic!("{}", db.url));
    assert!(hash.len() == 16 && hash.chars().all(|c| c.is_ascii_hexdigit()), "{}", db.url);
    let app_url = db.app_url.as_deref().unwrap();
    assert!(app_url.starts_with("postgres://conf_app:") && app_url.ends_with(&format!("/{name}")), "{app_url}");
    let pool = pool().await;
    rowstile::sqlx::check(&pool).await.unwrap(); // the app's role, under row-level security
    let mut tx = rowstile::sqlx::begin(&pool, &Principal::user("1")).await.unwrap();
    assert_eq!(rowstile::sqlx::list(&mut tx, ProjectPermission::View, None).await.unwrap(), ["1", "3"]);
    // (test.sh checks the original is left as it was migrated, once no binary copies it: a connection to it would
    // stop another binary's copy)
}

#[tokio::test]
async fn check_13_refuses_a_connection_that_skips_rls() {
    let _check = Check("13: the app refuses to start on a connection that skips row-level security");
    let owner = sqlx::PgPool::connect(&copied().url).await.unwrap();
    let err = rowstile::sqlx::check(&owner).await.unwrap_err();
    assert!(matches!(err, Error::Connection(_)), "{err:?}");
    assert!(err.to_string().contains("an owner skips row-level security"), "{err}");
    rowstile::sqlx::check(&pool().await).await.unwrap();
}

/// An API key of ann's, made as the owner (in one transaction: it commits at the end); scopes "read" for one that
/// may only read. Its key, and its id.
async fn anns_key(scopes: &str) -> (String, i64) {
    let owner = sqlx::PgPool::connect(&copied().url).await.unwrap();
    let mut tx = owner.begin().await.unwrap();
    tx.execute("SELECT authz.act_as('user', '1')").await.unwrap();
    let key: String =
        sqlx::query_scalar("SELECT authz.create_api_key('ci', $1)").bind(scopes).fetch_one(&mut *tx).await.unwrap();
    let id: i64 =
        sqlx::query_scalar("SELECT max(id) FROM authz.api_keys WHERE user_id = '1'").fetch_one(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
    (key, id)
}

/// The answer must be this problem body, as application/problem+json.
fn is_problem(a: &Answer, want: &Value) {
    assert_eq!(
        (a.status.as_u16(), a.kind.as_str()),
        (want["status"].as_u64().unwrap() as u16, "application/problem+json")
    );
    assert_eq!(&a.json(), want);
}

#[tokio::test]
async fn check_16_not_there_is_404_and_a_wrong_argument_400() {
    let _check = Check("16: what a call names isn't there (AZ708): 404; a missing or wrong argument (AZ710): 400");
    let app = app().await;
    let (_, key) = anns_key("").await;
    let page = call(&app, "GET", "/projects/page?limit=1", "1", Value::Null, &[]).await;
    let negative = call(&app, "GET", "/projects/page?limit=-1", "1", Value::Null, &[]).await;
    let cursor = call(&app, "GET", "/projects/page?limit=1&after=x", "1", Value::Null, &[]).await;
    let others = call(&app, "DELETE", &format!("/keys/{key}"), "2", Value::Null, &[]).await; // bo's key it isn't
    let revoked = call(&app, "DELETE", &format!("/keys/{key}"), "1", Value::Null, &[]).await;
    let again = call(&app, "DELETE", &format!("/keys/{key}"), "1", Value::Null, &[]).await; // revoked: none now
    assert_eq!((page.status.as_u16(), page.json()), (200, json!(["1"])));
    is_problem(
        &negative,
        &problem("bad-argument", "Bad Request", 400, "the page size must not be negative (got -1)", "AZ710"),
    );
    is_problem(
        &cursor,
        &problem("bad-argument", "Bad Request", 400, "the page cursor 'x' is not a project id", "AZ710"),
    );
    assert_eq!(revoked.status, 204);
    // no refusal: for this user the key isn't there (bo's own keys don't hold it; ann's no longer do)
    for a in [others, again] {
        is_problem(&a, &problem("not-found", "Not Found", 404, &format!("no API key {key} of yours"), "AZ708"));
    }
}

/// What the app logs while the requests run (rowstile's IntoResponse logs the errors it answers 500): each event's
/// error, in words.
static LOGGED: Mutex<Vec<String>> = Mutex::new(Vec::new());

struct Logged;

struct Words(Option<String>);

impl Visit for Words {
    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        if field.name() == "error" {
            self.0 = Some(format!("{value:?}"));
        }
    }
}

impl Subscriber for Logged {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.target() == "rowstile::axum"
    }
    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }
    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn event(&self, event: &Event<'_>) {
        let mut words = Words(None);
        event.record(&mut words);
        LOGGED.lock().unwrap().extend(words.0);
    }
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
}

#[tokio::test]
async fn check_16_each_code_answers_as_its_page_says() {
    let _check = Check(
        "16: a login refused or a call that needs someone signed in 401, a move inside itself 409, a refusal by the \
         database's own code 403, the app's mistakes a 500",
    );
    let app = app().await;
    let (read_only, _) = anns_key("read").await;
    let none = Value::Null;
    let nobody = call(&app, "POST", "/keys", "", json!({"name": "k"}), &[]).await;
    let asks =
        call(&app, "POST", "/projects/1/requests", "", json!({"relation": "member", "reason": "the review"}), &[])
            .await;
    let bad_key = call(&app, "POST", "/keys", "1", json!({"name": "k"}), &[("x-api-key", "ak_nope")]).await;
    let scoped = call(&app, "POST", "/keys", "1", json!({"name": "k"}), &[("x-api-key", &read_only)]).await;
    let made = call(&app, "POST", "/keys", "1", json!({"name": "k"}), &[]).await;
    let not_shared = call(&app, "GET", "/projects/1/shares", "2", none.clone(), &[]).await;
    let inside = call(&app, "PATCH", "/folders/1", "1", json!({"parent_id": 2}), &[]).await;
    let stays = call(&app, "PATCH", "/folders/2", "1", json!({"parent_id": 1}), &[]).await;
    let service = call(&app, "POST", "/keys", "", json!({"name": "mine"}), &[("x-service", "1")]).await; // for itself
    let _ = tracing::subscriber::set_global_default(Logged);
    LOGGED.lock().unwrap().clear();
    let failed = [
        call(&app, "POST", "/projects/1/requests", "2", json!({"relation": "member", "reason": "the review"}), &[])
            .await,
        call(&app, "POST", "/keys", "1", json!({"name": "k", "principal_type": "service", "principal_id": "1"}), &[])
            .await,
        call(&app, "GET", "/notes/as/2", "1", none.clone(), &[]).await,
    ];
    let logged = LOGGED.lock().unwrap().clone();
    assert_eq!(made.status, 201);
    assert!(made.json()["key"].as_str().unwrap().starts_with("ak_"), "{}", made.json());
    assert_eq!(stays.status, 200);
    is_problem(&nobody, &problem("not-signed-in", "Unauthorized", 401, "sign in to create an API key", "AZ714"));
    is_problem(&asks, &problem("not-signed-in", "Unauthorized", 401, "sign in first", "AZ714"));
    is_problem(&bad_key, &problem("not-signed-in", "Unauthorized", 401, "invalid API key", "AZ703"));
    is_problem(&inside, &problem("conflict", "Conflict", 409, "folder 1 cannot be moved inside itself", "AZ713"));
    // refusals, by the database's own code: 403, naming no rule
    for (a, words, code) in [
        (&scoped, "this session is read-only", "AZ704"),
        (&not_shared, "you cannot see the shares of project 1", "AZ705"),
    ] {
        let got = a.json();
        assert_eq!((a.status.as_u16(), &got["type"]), (403, &json!("https://rowstile.dev/problems/refused")), "{got}");
        assert_eq!((&got["code"], &got["table"], &got["command"]), (&json!(code), &Value::Null, &Value::Null), "{got}");
        assert!(got["detail"].as_str().unwrap().starts_with(words), "{got}");
    }
    // a call that is for users, made by a service (rowstile help AZ715): a refusal too, 403
    assert_eq!(service.status, 403);
    assert_eq!(
        service.json(),
        json!({"type": "https://rowstile.dev/problems/refused", "title": "Forbidden", "status": 403,
            "detail": "authz.create_api_key for oneself is for users, not services (service 1 is signed in)",
            "table": null, "command": null, "why": [], "code": "AZ715"})
    );
    // the app's mistakes: a 500, and the database's own error, logged with its words
    let words = [
        "the policy does not allow sharing project.member with a user",
        "the policy gives service no manage_keys permission, so nobody manages its keys",
        "who is signed in was changed after signing in",
    ];
    assert_eq!(logged.len(), 3, "{logged:?}");
    for ((answer, said), words) in failed.iter().zip(&logged).zip(words) {
        assert_eq!(answer.status, 500);
        assert_eq!(String::from_utf8_lossy(&answer.body), "Internal Server Error");
        assert!(said.contains(words), "{said}");
    }
    // ... each with its code and its SQLSTATE: the database's error, kept as it is
    let pool = pool().await;
    for (sql, code, sqlstate) in [
        ("SELECT authz.request_access('project', '1', 'member', 'x')", "AZ706", "P0001"),
        ("SELECT authz.create_api_key('k', '', NULL, 'service', '1')", "AZ707", "P0001"),
        ("SELECT set_config('authz.user_id', '2', true), (SELECT count(*) FROM app.notes)", "AZ702", "28000"),
    ] {
        let mut tx =
            rowstile::sqlx::begin(&pool, &Principal::user(if code == "AZ706" { "2" } else { "1" })).await.unwrap();
        let err = Error::from(tx.execute(sql).await.unwrap_err());
        let Error::Database(db) = &err else { panic!("{err:?}") };
        assert_eq!((err.code(), db.sqlstate.as_str()), (Some(code), sqlstate), "{err}");
        assert!(err.problem().is_none());
    }
}

#[tokio::test]
async fn queries_by_permission() {
    let _check = Check("queries by permission: a join on authz.list, and one call for a list's buttons");
    let app = app().await;
    assert_eq!(call(&app, "GET", "/projects/editable", "3", Value::Null, &[]).await.json(), json!([1]));
    assert_eq!(
        call(&app, "GET", "/projects/buttons", "3", Value::Null, &[]).await.json(),
        json!({"1": ["edit", "view"], "3": ["view"]})
    );
}
