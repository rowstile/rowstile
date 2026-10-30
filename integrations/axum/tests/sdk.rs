//! The SDK's other paths: what the checks don't meet, run against this binary's own copy of the test database (a
//! second worker, check 12), so that every line and region of the SDK runs (test.sh fails otherwise): the
//! tokio-postgres module, sqlx's paths the app doesn't take, errors made up as the database would send them, and the
//! test helpers.

mod common;

use std::error::Error as _;

use axum::extract::FromRequestParts;
use axum::http::Request;
use axum::http::request::Parts;
use axum::response::IntoResponse;
use common::{Check, copied, pool};
use conformance::authz::{NotePermission, ProjectPermission};
use rowstile::axum::{SignIn, Tx};
use rowstile::{CallKind, DbError, Error, Page, Permission, Principal, Problem};
use serde_json::json;
use sqlx::Executor;
use tokio_postgres::{Client, NoTls};

/// A client of the app role's on this binary's database, and its connection's task.
async fn client() -> (Client, tokio::task::JoinHandle<Result<(), tokio_postgres::Error>>) {
    let (client, connection) = tokio_postgres::connect(copied().app_url.as_deref().unwrap(), NoTls).await.unwrap();
    (client, tokio::spawn(connection))
}

/// A client whose connection is gone.
async fn closed() -> Client {
    let (client, connected) = client().await;
    connected.abort();
    let _ = connected.await;
    client
}

/// Who the transaction is signed in as, in the words the database's refusals use.
async fn whom(tx: &tokio_postgres::Transaction<'_>) -> String {
    let who = "SELECT coalesce((SELECT principal_type || ' ' || principal_id FROM authz.principal()), 'nobody')";
    tx.query_one(who, &[]).await.unwrap().get(0)
}

#[tokio::test]
async fn tokio_postgres_signs_in_and_asks() {
    let _check = Check("tokio-postgres: a transaction signed in, as a user, a service or nobody, and the questions");
    let (mut client, _) = client().await;
    rowstile::pg::check(&client).await.unwrap();
    for (who, said) in [
        (Principal::user("2"), "user 2"),
        (Principal::of("service", "1"), "service 1"),
        (Principal::Nobody, "nobody"),
        (Principal::default(), "nobody"),
    ] {
        let tx = rowstile::pg::begin(&mut client, &who).await.unwrap();
        assert_eq!(whom(&tx).await, said);
    }
    let tx = rowstile::pg::begin(&mut client, &Principal::user("3")).await.unwrap();
    assert!(rowstile::pg::can(&tx, NotePermission::Edit, 4).await.unwrap());
    assert!(!rowstile::pg::can(&tx, NotePermission::Edit, 1).await.unwrap());
    let buttons = rowstile::pg::perms_of::<ProjectPermission>(&tx, &[1, 3]).await.unwrap();
    assert_eq!(buttons["1"], [ProjectPermission::Edit, ProjectPermission::View]);
    assert_eq!(buttons["3"], [ProjectPermission::View]);
    assert_eq!(rowstile::pg::list(&tx, ProjectPermission::View, None).await.unwrap(), ["1", "3"]);
    let page = Page { after: Some("1".into()), limit: 5 };
    assert_eq!(rowstile::pg::list(&tx, ProjectPermission::View, Some(&page)).await.unwrap(), ["3"]);
    // a change is no error; a hidden row NotFound; a visible one the rule refuses, with the reason
    let changed = tx.execute("UPDATE app.notes SET body = body WHERE id = 4", &[]).await.unwrap();
    rowstile::pg::expect(&tx, changed, "app.notes", "update", 4).await.unwrap();
    let hidden = rowstile::pg::expect(&tx, 0, "app.notes", "update", 2).await;
    let n = rowstile::testing::not_found(hidden.unwrap_err());
    assert_eq!((n.table.as_str(), n.id.as_str()), ("app.notes", "2"));
    let refused =
        rowstile::testing::refused(rowstile::pg::expect(&tx, 0, "app.notes", "delete", 1).await.unwrap_err(), "delete");
    assert_eq!(refused.message, "permission denied: user 3 may not delete row 1 of app.notes");
    // a refused insert: the database's error, translated
    let insert = tx.execute("INSERT INTO app.notes (project_id, author_id, body) VALUES (2, 3, 'x')", &[]).await;
    let r = rowstile::testing::refused(Error::from(insert.unwrap_err()), "insert");
    assert_eq!((r.table.as_deref(), r.code.as_str()), (Some("app.notes"), "AZ709"));
    assert!(r.source.as_ref().unwrap().source().is_some(), "the driver's error, under the database's");
    // and asked again in the failed transaction: the database's error
    let aborted = rowstile::pg::expect(&tx, 0, "app.notes", "update", 1).await.unwrap_err();
    assert!(matches!(&aborted, Error::Database(db) if db.sqlstate == "25P02"), "{aborted:?}");
}

#[tokio::test]
async fn tokio_postgres_errors() {
    let _check =
        Check("tokio-postgres: outside a signed-in transaction, a type that doesn't sign in, a closed connection");
    let (mut client, _) = client().await;
    // in transactions nobody signed in to (the first error ends the one it is in)
    let raw = client.transaction().await.unwrap();
    let err = rowstile::pg::can(&raw, NotePermission::View, 1).await.unwrap_err();
    assert!(matches!(err, Error::NotSignedIn(_)), "{err:?}");
    drop(raw);
    let raw = client.transaction().await.unwrap();
    let err = rowstile::pg::perms_of::<NotePermission>(&raw, &[1]).await.unwrap_err();
    assert!(matches!(err, Error::NotSignedIn(_)), "{err:?}");
    drop(raw);
    let tx = rowstile::pg::begin(&mut client, &Principal::user("1")).await.unwrap();
    let page = Page { after: None, limit: -1 };
    let err = rowstile::pg::list(&tx, ProjectPermission::View, Some(&page)).await.unwrap_err();
    assert!(matches!(&err, Error::Call(c) if c.kind == CallKind::BadArgument), "{err:?}");
    drop(tx);
    let err = rowstile::pg::begin(&mut client, &Principal::of("robot", "1")).await.err().unwrap();
    assert_eq!(err.code(), Some("AZ707"), "{err:?}");
    let mut gone = closed().await;
    let err = rowstile::pg::begin(&mut gone, &Principal::Nobody).await.err().unwrap();
    assert!(matches!(&err, Error::Other(_)) && err.code().is_none() && err.source().is_some(), "{err:?}");
    assert!(rowstile::pg::check(&gone).await.is_err());
    // the owner skips row-level security
    let (owner, connection) = tokio_postgres::connect(&copied().url, NoTls).await.unwrap();
    tokio::spawn(connection);
    let err = rowstile::pg::check(&owner).await.unwrap_err();
    assert!(err.to_string().contains("an owner skips row-level security"), "{err}");
}

#[tokio::test]
async fn sqlx_paths_the_app_doesnt_take() {
    let _check =
        Check("sqlx: nobody signed in, a page, Expect's other answers, a closed pool, a type that doesn't sign in");
    let pool = pool().await;
    let mut nobody = rowstile::sqlx::begin(&pool, &Principal::Nobody).await.unwrap();
    assert!(!rowstile::sqlx::can(&mut nobody, NotePermission::View, 1).await.unwrap());
    assert_eq!(rowstile::sqlx::list(&mut nobody, ProjectPermission::View, None).await.unwrap(), ["3"]);
    drop(nobody);
    let err = rowstile::sqlx::perms_of::<NotePermission>(&mut pool.acquire().await.unwrap(), &[1]).await.unwrap_err();
    assert!(matches!(err, Error::NotSignedIn(_)), "{err:?}");
    // cy may edit note 4: an UPDATE whose WHERE says more than the key matched nothing, and that is no refusal
    let mut tx = rowstile::sqlx::begin(&pool, &Principal::user("3")).await.unwrap();
    let changed = tx.execute("UPDATE app.notes SET body = 'x' WHERE id = 4 AND body = 'something else'").await.unwrap();
    let missed = rowstile::sqlx::expect(&mut tx, changed.rows_affected(), "app.notes", "update", 4).await;
    let n = rowstile::testing::not_found(missed.unwrap_err());
    assert_eq!((n.table.as_str(), n.id.as_str()), ("app.notes", "4"));
    // a table named without its schema is found on the search_path, and the refusal names it as an insert's does
    tx.execute("SET LOCAL search_path = app").await.unwrap();
    let refused = rowstile::sqlx::expect(&mut tx, 0, "notes", "update", 1).await;
    let r = rowstile::testing::refused(refused.unwrap_err(), "update");
    assert_eq!(
        (r.table.as_deref(), r.message.as_str()),
        (Some("app.notes"), "permission denied: user 3 may not update row 1 of app.notes")
    );
    // asked in a failed transaction: the database's error
    let _ = tx.execute("SELECT 1/0").await;
    assert!(rowstile::sqlx::expect(&mut tx, 0, "app.notes", "update", 1).await.is_err());
    // a principal of a type the policy doesn't sign in, and a pool that is closed
    drop(tx);
    let err = rowstile::sqlx::begin(&pool, &Principal::of("robot", "1")).await.unwrap_err();
    assert_eq!(err.code(), Some("AZ707"), "{err:?}");
    pool.close().await; // (once every connection is back)
    let err = rowstile::sqlx::begin(&pool, &Principal::Nobody).await.unwrap_err();
    assert!(matches!(&err, Error::Other(_)), "{err:?}");
    assert!(rowstile::sqlx::check(&pool).await.is_err());
}

#[tokio::test]
async fn postgres_own_refusals_name_the_rule() {
    let _check = Check("Postgres's own refusals (an update out of sight, an upsert, MERGE) name the rule");
    let pool = pool().await;
    let refused = async |sql: &'static str| {
        // as cy (3): author of note 4 in project 1, a member there
        let mut tx = rowstile::sqlx::begin(&pool, &Principal::user("3")).await.unwrap();
        rowstile::testing::refused(Error::from(tx.execute(sql).await.unwrap_err()), "")
    };
    let hidden = refused("UPDATE app.notes SET project_id = 2 WHERE id = 4").await; // into bo's project
    let upsert = refused(
        "INSERT INTO app.notes (id, project_id, author_id, body) VALUES (1, 1, 3, 'x') ON CONFLICT (id) DO UPDATE SET body = 'x'",
    )
    .await; // note 1 is ann's
    let merge = refused(
        "MERGE INTO app.notes n USING (VALUES (1)) s(id) ON n.id = s.id WHEN MATCHED THEN UPDATE SET body = 'x'",
    )
    .await;
    for (got, command, message) in [
        (
            hidden,
            Some("select"),
            "new row violates row-level security policy for table \"notes\": this user may not see the row as \
             written (the select rule). An insert that reads it back (RETURNING), an upsert, and an update with a \
             WHERE need to see it.",
        ),
        (
            upsert,
            Some("update"),
            "new row violates row-level security policy (USING expression) for table \"notes\": the row is there \
             already, and the update rule (or the select rule) doesn't let this user change it (ON CONFLICT DO UPDATE)",
        ),
        (
            merge,
            None,
            "target row violates row-level security policy (USING expression) for table \"notes\": MERGE matched a \
             row the update or delete rule doesn't let this user change",
        ),
    ] {
        assert_eq!(
            (got.table.as_deref(), got.command.as_deref(), got.message.as_str()),
            (Some("notes"), command, message)
        );
        let body = Error::Refused(Box::new(got)).problem().unwrap().to_json();
        assert_eq!((&body["command"], &body["why"]), (&json!(command), &json!([])), "{body}");
    }
}

/// A database error, made up as Postgres would send it.
fn db(sqlstate: &str, message: &str) -> DbError {
    DbError { sqlstate: sqlstate.into(), message: message.into(), ..DbError::default() }
}

#[test]
fn errors_made_up_as_the_database_sends_them() {
    let _check = Check("errors as the database sends them: each translated, said, and answered as the others do");
    // the code is read from the HINT, then the message; only a code that is one
    for (hint, message, code) in [
        (Some("rowstile help AZ709"), "no", Some("AZ709")),
        (None, "a check said no (rowstile help AZ612)", Some("AZ612")),
        (Some("see rowstile help AZx12"), "or rowstile help AZ1", None),
        (Some("nothing"), "nothing", None),
    ] {
        let e = DbError { hint: hint.map(Into::into), ..db("P0001", message) };
        assert_eq!(e.code(), code, "{hint:?} {message}");
    }
    // a refusal of rowstile's: its table, its rule, its reasons; a table named without its schema; none at all
    let refusal = DbError {
        hint: Some("rowstile help AZ709".into()),
        detail: Some("no: project.edit\nno: author".into()),
        table: Some("notes".into()),
        constraint: Some("authz_insert".into()),
        ..db("42501", "user 2 may not insert this row into notes")
    };
    let Error::Refused(r) = Error::from_database(refusal) else { panic!() };
    assert_eq!((r.table.as_deref(), r.command.as_deref(), r.why.len()), (Some("notes"), Some("insert"), 2));
    // a 42501 with no code (a table never granted), and one that is a call's (sign in first): no refusal
    assert!(matches!(Error::from_database(db("42501", "permission denied for table x")), Error::Database(_)));
    let call =
        Error::from_database(DbError { hint: Some("rowstile help AZ714".into()), ..db("42501", "sign in first") });
    assert!(matches!(&call, Error::Call(c) if c.kind == CallKind::NotSignedIn), "{call:?}");
    assert_eq!(
        (call.to_string(), call.source().unwrap().to_string()),
        ("sign in first".into(), "sign in first".into())
    );
    // Postgres's own words, cut short: no refusal it can name
    for message in [
        "new row violates row-level security policy for table notes",
        "new row violates row-level security policy for table \"notes",
        "row violates row-level security policy for table \"notes\"",
    ] {
        assert!(matches!(Error::from_database(db("42501", message)), Error::Database(_)), "{message}");
    }
    // the not-signed-in error, with its code or none; a login refused is a call's; settings changed by hand the app's
    for (hint, not_signed_in) in
        [(None, true), (Some("rowstile help AZ701"), true), (Some("rowstile help AZ702"), false)]
    {
        let e = Error::from_database(DbError { hint: hint.map(Into::into), ..db("28000", "x") });
        assert_eq!(matches!(e, Error::NotSignedIn(_)), not_signed_in, "{hint:?}");
    }
    // what each says, and what lies under it
    let not_signed_in = Error::from_database(db("28000", "x"));
    assert_eq!(
        not_signed_in.to_string(),
        "a query ran in a transaction nobody signed in to: every transaction must begin with authz.act_as() \
         (rowstile's begin does it; is this query outside it?): x"
    );
    assert_eq!(not_signed_in.source().unwrap().to_string(), "x");
    assert!(not_signed_in.source().unwrap().source().is_none(), "made up: no driver's error under it");
    let unauthorized = Error::unauthorized("bad token");
    assert!(unauthorized.source().is_none() && unauthorized.code().is_none());
    let not_found = Error::NotFound(rowstile::NotFound { table: "app.notes".into(), id: "(1,2)".into() });
    assert_eq!(
        (not_found.to_string(), not_found.code(), not_found.source().is_none()),
        ("app.notes (1,2) not found".into(), None, true)
    );
    let connection = Error::Connection(rowstile::ConnectionProblem { problems: vec!["a".into(), "b".into()] });
    assert_eq!(connection.to_string(), "the app's database connection can't be used with rowstile: a; b");
    assert!(connection.problem().is_none() && connection.code().is_none());
    let other = Error::Other("the network".into());
    assert_eq!((other.to_string(), other.source().unwrap().to_string()), ("the network".into(), "the network".into()));
    let database = Error::from_database(db("22012", "division by zero"));
    assert_eq!(
        (database.to_string(), database.code(), database.source().is_some()),
        ("division by zero".into(), None, true)
    );
    let refused = rowstile::testing::refused(
        Error::from_database(DbError {
            hint: Some("rowstile help AZ705".into()),
            ..db("42501", "you cannot see the shares of project 1")
        }),
        "",
    );
    let refused = Error::Refused(Box::new(refused));
    assert_eq!(
        (refused.to_string(), refused.source().is_some()),
        ("you cannot see the shares of project 1".into(), true)
    );
    assert_eq!(refused.code(), Some("AZ705"));
    let made_up = Error::Refused(Box::new(rowstile::Refused {
        message: "no".into(),
        table: None,
        command: None,
        why: vec![],
        code: "AZ709".into(),
        source: None,
    }));
    assert!(made_up.source().is_none());
    // the problem bodies: a refusal's names its table and command even when null; another's only its code
    assert_eq!(
        unauthorized.problem().unwrap().to_json(),
        json!({"type": "https://rowstile.dev/problems/not-signed-in", "title": "Unauthorized", "status": 401, "detail": "bad token"})
    );
    let p: Problem = made_up.problem().unwrap();
    assert_eq!(p.type_uri(), "https://rowstile.dev/problems/refused");
    assert_eq!(
        p.to_json(),
        json!({"type": "https://rowstile.dev/problems/refused", "title": "Forbidden", "status": 403, "detail": "no",
            "table": null, "command": null, "why": [], "code": "AZ709"})
    );
    assert_eq!(CallKind::Conflict.answer(), (409, "conflict", "Conflict"));
}

#[test]
fn keys_principals_and_names() {
    let _check = Check("a key of several columns as Postgres writes it; principals; a name the enum doesn't have");
    assert_eq!(
        rowstile::composite_key(&[Some("1"), Some("a b"), Some(""), Some("q\"t"), Some("b\\s"), Some("(1)"), None]),
        r#"(1,"a b","","q""t","b\\s","(1)",)"#
    );
    assert_eq!(Principal::user("7"), Principal::Signed { principal_type: "user".into(), id: "7".into() });
    assert_eq!(NotePermission::from_name("edit"), Some(NotePermission::Edit));
    assert_eq!((NotePermission::from_name("edt"), NotePermission::OBJECT_TYPE), (None, "note"));
}

/// A type's permissions as an app wrote them before the policy gave the type another: view is not among them.
#[derive(Clone, Copy, Debug, PartialEq)]
struct OnlyEdit;

impl Permission for OnlyEdit {
    const OBJECT_TYPE: &'static str = "project";

    fn name(self) -> &'static str {
        "edit"
    }

    fn from_name(name: &str) -> Option<Self> {
        (name == "edit").then_some(Self)
    }
}

#[tokio::test]
async fn a_permission_the_names_dont_have_is_left_out() {
    let _check = Check("perms_of: a permission the app's names don't have (the policy changed since) is left out");
    let pool = pool().await;
    let mut tx = rowstile::sqlx::begin(&pool, &Principal::user("3")).await.unwrap();
    let held = rowstile::sqlx::perms_of::<OnlyEdit>(&mut tx, &[1, 3]).await.unwrap();
    assert_eq!((held["1"].as_slice(), held["3"].as_slice()), ([OnlyEdit].as_slice(), [].as_slice()));
}

/// An app's state whose requests act for user 1.
struct Users(sqlx::PgPool);

impl SignIn for Users {
    fn pool(&self) -> &sqlx::PgPool {
        &self.0
    }

    fn principal(&self, _: &Parts) -> Result<Principal, Error> {
        Ok(Principal::user("1"))
    }
}

/// An app's state whose requests act for a type the policy doesn't sign in.
struct Robots(sqlx::PgPool);

impl SignIn for Robots {
    fn pool(&self) -> &sqlx::PgPool {
        &self.0
    }

    fn principal(&self, _: &Parts) -> Result<Principal, Error> {
        Ok(Principal::of("robot", "1"))
    }
}

#[tokio::test]
async fn the_extractor_answers_what_it_cant_begin() {
    let _check = Check("Axum: a request whose transaction can't sign in is answered 500; a bad token 401");
    let (mut parts, ()) = Request::new(()).into_parts();
    // one that can: its transaction is a connection, read or written
    let tx = Tx::from_request_parts(&mut parts, &Users(pool().await)).await.ok().unwrap();
    let connection: &sqlx::PgConnection = &tx;
    assert!(connection.server_version_num().is_some_and(|v| v >= 160_000));
    assert_eq!(tx.principal(), &Principal::user("1"));
    let err = Tx::from_request_parts(&mut parts, &Robots(pool().await)).await.err().unwrap();
    assert_eq!(err.code(), Some("AZ707"));
    assert_eq!(err.into_response().status(), 500);
    let app = common::app().await;
    let bad =
        common::call(&app, "GET", "/notes", "", serde_json::Value::Null, &[("authorization", "Bearer bad")]).await;
    assert_eq!(
        (bad.status.as_u16(), bad.json()),
        (
            401,
            json!({"type": "https://rowstile.dev/problems/not-signed-in", "title": "Unauthorized", "status": 401, "detail": "bad token"})
        )
    );
}

#[tokio::test]
async fn a_test_database_per_binary() {
    let _check = Check("12: ... each binary its own copy, kept with what the tests wrote, or copied again as migrated");
    let tests = std::env::var("ROWSTILE_TESTS_URL").unwrap();
    let db = copied();
    assert!(db.url.contains("_sdk_"), "{}", db.url);
    // kept, with what the tests wrote (the rows); copied again, as migrated (none)
    let users = async |url: &str| {
        let owner = sqlx::PgPool::connect(url).await.unwrap();
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM app.users").fetch_one(&owner).await.unwrap();
        owner.close().await;
        n
    };
    let kept = rowstile::testing::per_binary(&tests, Some("nonsense"), false).await.unwrap();
    assert_eq!(
        (kept.url.as_str(), kept.app_url.as_deref(), users(&kept.url).await),
        (db.url.as_str(), Some("nonsense"), 3)
    );
    let again = rowstile::testing::per_binary(&tests, None, true).await.unwrap();
    assert_eq!((again.url.as_str(), again.app_url, users(&again.url).await), (db.url.as_str(), None, 0));
    common::as_owner(db, common::DATA).await;
    // while anything is connected to the original, Postgres can't copy it, and says so: this binary's copy as the
    // original
    let holder = sqlx::PgPool::connect(&db.url).await.unwrap();
    let _held = holder.acquire().await.unwrap();
    let err = rowstile::testing::per_binary(&db.url, None, true).await.unwrap_err();
    assert!(err.to_string().contains("can't be copied while anything is connected to it"), "{err}");
    // a URL that names no database, a server that isn't there, an original that isn't there
    for url in ["nonsense", "postgres://conf_owner:owner@localhost", "postgres://conf_owner:owner@localhost/"] {
        let err = rowstile::testing::per_binary(url, None, true).await.unwrap_err();
        assert!(err.to_string().contains("is not a URL that names a database to copy"), "{err}");
    }
    let port = tests.split(':').nth(3).unwrap().split('/').next().unwrap().to_owned();
    let nowhere = tests.replace(&format!(":{port}/"), ":1/");
    assert!(rowstile::testing::per_binary(&nowhere, None, true).await.is_err());
    let missing = format!("{}_missing?sslmode=disable", tests);
    let err = rowstile::testing::per_binary(&missing, None, true).await.unwrap_err();
    assert!(err.to_string().contains("does not exist"), "{err}");
    let worker = rowstile::testing::worker();
    assert!(worker.starts_with("sdk_") && worker.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'), "{worker}");
}

#[test]
fn the_test_helpers_say_what_was_expected() {
    let _check = Check("the test helpers: a refusal by the rule expected, NotFound, and what each says otherwise");
    let refusal = || {
        Error::Refused(Box::new(rowstile::Refused {
            message: "no".into(),
            table: None,
            command: Some("update".into()),
            why: vec![],
            code: "AZ709".into(),
            source: None,
        }))
    };
    assert_eq!(rowstile::testing::refused(refusal(), "update").message, "no");
    let said = |f: Box<dyn FnOnce() + std::panic::UnwindSafe>| {
        let panicked = std::panic::catch_unwind(f).unwrap_err();
        panicked.downcast_ref::<String>().cloned().unwrap()
    };
    assert_eq!(
        said(Box::new(move || {
            rowstile::testing::refused(refusal(), "delete");
        })),
        "expected the delete rule to refuse it, but: Some(\"update\"): no"
    );
    assert_eq!(
        said(Box::new(|| {
            rowstile::testing::refused(Error::unauthorized("bad token"), "");
        }))
        .split(", kind")
        .next()
        .unwrap(),
        "expected a refusal, got Call(CallError { code: None"
    );
    assert_eq!(
        said(Box::new(move || {
            rowstile::testing::not_found(refusal());
        }))
        .split(", table")
        .next()
        .unwrap(),
        "expected NotFound, got Refused(Refused { message: \"no\""
    );
}
