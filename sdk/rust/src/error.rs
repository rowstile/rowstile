//! rowstile's errors: the database's answers, translated.

use std::fmt;

use serde_json::{Value, json};

/// The error of a source of errors: any driver's, boxed.
type Source = Box<dyn std::error::Error + Send + Sync>;

/// A database error, as Postgres sent it: the fields rowstile reads, and the driver's own error.
#[derive(Debug, Default)]
pub struct DbError {
    /// The SQLSTATE: `42501`.
    pub sqlstate: String,
    /// The message.
    pub message: String,
    /// The DETAIL, if any: a refusal's reasons, a line each.
    pub detail: Option<String>,
    /// The HINT, if any: rowstile's code is there, `rowstile help AZ709`.
    pub hint: Option<String>,
    /// The schema of the table it names, if any.
    pub schema: Option<String>,
    /// The table it names, if any.
    pub table: Option<String>,
    /// The constraint it names, if any: `authz_insert` for a rule's refusal.
    pub constraint: Option<String>,
    /// The driver's error.
    pub source: Option<Source>,
}

impl DbError {
    /// rowstile's code for this error (`AZ709`; `rowstile help AZ709` says what it means), from its HINT, where the
    /// runtime puts it, or its message; none for an error rowstile didn't raise.
    #[must_use]
    pub fn code(&self) -> Option<&str> {
        [self.hint.as_deref(), Some(&self.message)].into_iter().flatten().find_map(code_in)
    }
}

/// The first `rowstile help AZnnn` in a text: its code.
fn code_in(text: &str) -> Option<&str> {
    let at = text.find("rowstile help AZ")? + "rowstile help ".len();
    text.get(at..at + 5).filter(|code| code[2..].bytes().all(|b| b.is_ascii_digit()))
}

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for DbError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_deref().map(|e| e as _)
    }
}

/// The database refusing a write, and saying why: the rule (`table` and `command`), and the reasons, a line each.
/// `code` is rowstile's (`rowstile help AZ709`): `AZ709` for a rule's refusal, the database's own for another
/// (`AZ704`: a read-only session, `AZ705`: the shares of an object one can't see, `AZ715`: a call for users made by
/// a service), which names no rule.
#[derive(Debug)]
pub struct Refused {
    /// The database's words.
    pub message: String,
    /// The table, `schema.table`; none when the refusal names none.
    pub table: Option<String>,
    /// `insert`, `update`, `delete` or `select`; none when the refusal names none.
    pub command: Option<String>,
    /// The reasons, a line each.
    pub why: Vec<String>,
    /// rowstile's code.
    pub code: String,
    /// The database's error, when there was one.
    pub source: Option<DbError>,
}

/// A row that isn't there, or that whoever the transaction acts for can't see.
#[derive(Debug)]
pub struct NotFound {
    /// The table, as the policy names it.
    pub table: String,
    /// The row's key as Postgres writes it: `7`, or `(1,2)` for a key of several columns.
    pub id: String,
}

/// What a call the database turned down (that is no refusal) is, and so its status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallKind {
    /// An argument missing or wrong (`AZ710`): 400.
    BadArgument,
    /// A login refused, or a call that needs someone signed in (`AZ703`, `AZ714`): 401.
    NotSignedIn,
    /// Something it names that isn't there (`AZ708`): 404.
    NotFound,
    /// A folder moved into one of its own subfolders (`AZ713`): 409.
    Conflict,
}

impl CallKind {
    /// The kind of a code a call can meet, if `code` is one.
    fn of(code: &str) -> Option<Self> {
        match code {
            "AZ710" => Some(Self::BadArgument),
            "AZ703" | "AZ714" => Some(Self::NotSignedIn),
            "AZ708" => Some(Self::NotFound),
            "AZ713" => Some(Self::Conflict),
            _ => None,
        }
    }

    /// The HTTP status its code's page gives, the problem type's last part, and its title.
    #[must_use]
    pub fn answer(self) -> (u16, &'static str, &'static str) {
        match self {
            Self::BadArgument => (400, "bad-argument", "Bad Request"),
            Self::NotSignedIn => (401, "not-signed-in", "Unauthorized"),
            Self::NotFound => (404, "not-found", "Not Found"),
            Self::Conflict => (409, "conflict", "Conflict"),
        }
    }
}

/// A call the database turned down that is no refusal, with the status its code's page gives (`rowstile help
/// AZ708`): a login refused or a call that needs someone signed in 401 (`AZ703`, `AZ714`), something it names that
/// isn't there 404 (`AZ708`), an argument missing or wrong 400 (`AZ710`), a move inside itself 409 (`AZ713`).
#[derive(Debug)]
pub struct CallError {
    /// rowstile's code; none for [`Error::unauthorized`].
    pub code: Option<String>,
    /// What it is, and so its status.
    pub kind: CallKind,
    /// The database's words.
    pub message: String,
    /// The database's error, when there was one.
    pub source: Option<DbError>,
}

/// `authz.connection_check()` finding that the app's connection skips row-level security (or worse): a superuser,
/// a role with BYPASSRLS, the tables' owner.
#[derive(Debug)]
pub struct ConnectionProblem {
    /// What is wrong, a line each.
    pub problems: Vec<String>,
}

/// An error of an app on rowstile: the database's answers, translated.
#[derive(Debug)]
pub enum Error {
    /// The database refused a write, and says why: answered 403.
    Refused(Box<Refused>),
    /// A row that isn't there, or that the user can't see: answered 404.
    NotFound(NotFound),
    /// A query that needs to know who is asking, in a transaction nobody signed in to (`AZ701`): the app's bug,
    /// not the user's doing. Every transaction must begin with `authz.act_as()`, as `begin` does. A 500.
    NotSignedIn(Box<DbError>),
    /// A call the database turned down that is no refusal: answered with its kind's status.
    Call(Box<CallError>),
    /// The app's connection skips row-level security: refuse to start.
    Connection(ConnectionProblem),
    /// Any other database error, rowstile's (`code()`: the app's mistakes, `AZ702`, `AZ706`, `AZ707`) or not: a 500.
    Database(Box<DbError>),
    /// An error that isn't the database's: the connection's, the driver's. A 500.
    Other(Source),
}

impl Error {
    /// A database error as rowstile's when it is one: a refusal [`Error::Refused`], the not-signed-in error
    /// (`AZ701`) [`Error::NotSignedIn`], a call turned down [`Error::Call`]; anything else [`Error::Database`].
    #[must_use]
    pub fn from_database(db: DbError) -> Self {
        let code = db.code().map(str::to_owned);
        if db.sqlstate == "42501" {
            if let Some(refused) = generic_refusal(&db.message) {
                return Self::Refused(Box::new(Refused { source: Some(db), ..refused }));
            }
            // sign in first (AZ714) is a 42501 too, but no refusal; another 42501 with no code (a table the app role
            // was never granted) is the app's mistake
            if let Some(code) = code.clone().filter(|code| CallKind::of(code).is_none()) {
                return Self::Refused(Box::new(Refused {
                    message: db.message.clone(),
                    table: db
                        .table
                        .as_ref()
                        .map(|t| db.schema.as_ref().map_or_else(|| t.clone(), |s| format!("{s}.{t}"))),
                    command: db.constraint.as_deref().and_then(|c| c.strip_prefix("authz_")).map(str::to_owned),
                    why: db.detail.as_deref().map_or_else(Vec::new, |d| d.split('\n').map(str::to_owned).collect()),
                    code,
                    source: Some(db),
                }));
            }
        }
        match code.as_deref().map(|c| (c, CallKind::of(c))) {
            Some((_, Some(kind))) => {
                Self::Call(Box::new(CallError { code, kind, message: db.message.clone(), source: Some(db) }))
            }
            // a login refused (AZ703) and settings changed by hand (AZ702) share the SQLSTATE, and are no such thing
            None | Some(("AZ701", None)) if db.sqlstate == "28000" => Self::NotSignedIn(Box::new(db)),
            _ => Self::Database(Box::new(db)),
        }
    }

    /// A 401 for a request the app can't tell who sent (a bad token): the problem body says `message`.
    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::Call(Box::new(CallError {
            code: None,
            kind: CallKind::NotSignedIn,
            message: message.into(),
            source: None,
        }))
    }

    /// rowstile's code for this error (`rowstile help AZ709` says what it means): a refusal's, a call's, or that of
    /// any database error rowstile raised; none otherwise.
    #[must_use]
    pub fn code(&self) -> Option<&str> {
        match self {
            Self::Refused(r) => Some(&r.code),
            Self::Call(c) => c.code.as_deref(),
            Self::NotSignedIn(db) | Self::Database(db) => db.code(),
            _ => None,
        }
    }

    /// The problem body to answer this error with, when it is rowstile's to answer: a refusal 403, a hidden row 404,
    /// and a call the database turned down as its code's page says, with the database's words. Anything else (the
    /// not-signed-in error, a share the policy doesn't declare, a name not in the policy, who is signed in changed by
    /// hand) is the app's mistake: none, for a 500.
    #[must_use]
    pub fn problem(&self) -> Option<Problem> {
        match self {
            Self::Refused(r) => Some(Problem {
                kind: "refused",
                title: "Forbidden",
                status: 403,
                detail: r.message.clone(),
                table: r.table.clone(),
                command: r.command.clone(),
                why: r.why.clone(),
                code: Some(r.code.clone()),
            }),
            Self::NotFound(_) => Some(Problem::of(404, "not-found", "Not Found", self.to_string(), None)),
            Self::Call(c) => {
                let (status, kind, title) = c.kind.answer();
                Some(Problem::of(status, kind, title, c.message.clone(), c.code.clone()))
            }
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(r) => f.write_str(&r.message),
            Self::NotFound(n) => write!(f, "{} {} not found", n.table, n.id),
            Self::NotSignedIn(db) => write!(
                f,
                "a query ran in a transaction nobody signed in to: every transaction must begin with \
                 authz.act_as() (rowstile's begin does it; is this query outside it?): {db}"
            ),
            Self::Call(c) => f.write_str(&c.message),
            Self::Connection(c) => {
                write!(f, "the app's database connection can't be used with rowstile: {}", c.problems.join("; "))
            }
            Self::Database(db) => db.fmt(f),
            Self::Other(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Refused(r) => r.source.as_ref().map(|db| db as _),
            Self::Call(c) => c.source.as_ref().map(|db| db as _),
            Self::NotSignedIn(db) | Self::Database(db) => Some(&**db),
            Self::Other(e) => Some(&**e),
            _ => None,
        }
    }
}

/// Postgres's own words, not rowstile's: a check of a row no rule's own refusal covers. Postgres names the table
/// without its schema, and sets no field for it.
fn generic_refusal(message: &str) -> Option<Refused> {
    let (target, rest) = match message.strip_prefix("target row violates row-level security policy ") {
        Some(rest) => (true, rest),
        None => (false, message.strip_prefix("new row violates row-level security policy ")?),
    };
    let (using, rest) = rest.strip_prefix("(USING expression) ").map_or((false, rest), |rest| (true, rest));
    let (table, _) = rest.strip_prefix("for table \"")?.split_once('"')?;
    let (said, command) = match (target, using) {
        // MERGE matched a row the update or the delete rule hides; Postgres doesn't say which
        (true, _) => ("MERGE matched a row the update or delete rule doesn't let this user change", None),
        // an upsert whose existing row this user may not update, or not see
        (false, true) => (
            "the row is there already, and the update rule (or the select rule) doesn't let this user change it \
             (ON CONFLICT DO UPDATE)",
            Some("update"),
        ),
        // the select rule, on the row as written: an insert that reads it back, an upsert, or an update after which
        // the row would be out of this user's sight
        (false, false) => (
            "this user may not see the row as written (the select rule). An insert that reads it back (RETURNING), \
             an upsert, and an update with a WHERE need to see it.",
            Some("select"),
        ),
    };
    Some(Refused {
        message: format!("{message}: {said}"),
        table: Some(table.to_owned()),
        command: command.map(str::to_owned),
        why: Vec::new(),
        code: "AZ709".to_owned(),
        source: None,
    })
}

/// An RFC 9457 problem body: a refusal's (403, with `table`, `command`, `why` and `code`), a hidden row's (404), or
/// a call the database turned down (with `code`). [`Problem::to_json`] writes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Problem {
    /// The type's last part: `refused`, `not-found`, `not-signed-in`, `bad-argument`, `conflict`.
    pub kind: &'static str,
    /// The status's title: `Forbidden`.
    pub title: &'static str,
    /// The HTTP status.
    pub status: u16,
    /// The database's words.
    pub detail: String,
    /// A refusal's table, `schema.table`.
    pub table: Option<String>,
    /// A refusal's command.
    pub command: Option<String>,
    /// A refusal's reasons.
    pub why: Vec<String>,
    /// rowstile's code.
    pub code: Option<String>,
}

impl Problem {
    fn of(status: u16, kind: &'static str, title: &'static str, detail: String, code: Option<String>) -> Self {
        Self { kind, title, status, detail, table: None, command: None, why: Vec::new(), code }
    }

    /// Its `type`: `https://rowstile.dev/problems/refused`.
    #[must_use]
    pub fn type_uri(&self) -> String {
        format!("https://rowstile.dev/problems/{}", self.kind)
    }

    /// The body, as the other SDKs write it: a refusal's table and command as null when it names none, and its why
    /// as `[]`; a code only where there is one.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut body =
            json!({"type": self.type_uri(), "title": self.title, "status": self.status, "detail": self.detail});
        if self.kind == "refused" {
            body["table"] = json!(self.table);
            body["command"] = json!(self.command);
            body["why"] = json!(self.why);
        }
        if let Some(code) = &self.code {
            body["code"] = json!(code);
        }
        body
    }
}
