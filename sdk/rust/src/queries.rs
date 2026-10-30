//! What the drivers' modules send, and what they make of the answers: the same for each.

use std::collections::HashMap;

use crate::{Error, NotFound, Permission, Principal, Refused};

/// The type and the id `authz.act_as` takes: both NULL for nobody.
pub(crate) fn act_as(who: &Principal) -> (Option<&str>, Option<&str>) {
    match who {
        Principal::Nobody => (None, None),
        Principal::Signed { principal_type, id } => (Some(principal_type), Some(id)),
    }
}

/// `authz.act_as`, first in every transaction: the type and the id, both NULL for nobody.
pub(crate) const ACT_AS: &str = "SELECT authz.act_as($1, $2)";

/// What `check` asks: the problems of this connection that make it unusable with rowstile.
pub(crate) const CONNECTION_CHECK: &str = "SELECT problem FROM authz.connection_check() WHERE severity = 'error'";

pub(crate) const CAN: &str = "SELECT authz.can($1, $2::text, $3)";

pub(crate) const PERMS_OF: &str = "SELECT id, perms FROM authz.perms_of($1, $2::text[])";

pub(crate) const LIST: &str = "SELECT x FROM authz.list($1, $2, $3, $4) x";

/// The table as the policy names it (a table named without its schema is looked up on the `search_path`),
/// `authz.explain_rule`'s answer, and who is signed in, in the words the database's own refusals use.
pub(crate) const EXPLAIN_RULE: &str = "SELECT authz.explain_rule(t.tbl, $2, $3, NULL), \
    coalesce((SELECT p.principal_type || ' ' || p.principal_id FROM authz.principal() p), \
    'someone not signed in'), t.tbl FROM (SELECT coalesce((SELECT n.nspname || '.' || c.relname \
    FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
    WHERE position('.' in $1::text) = 0 AND c.oid = pg_catalog.to_regclass(pg_catalog.quote_ident($1::text))), \
    $1::text) AS tbl) t";

/// What `expect` makes of `authz.explain_rule`'s answer about a write that changed no row: nothing there for this
/// user (none, or a first line saying `yes`: the statement matched nothing for another reason) is
/// [`Error::NotFound`], else a refusal worded as the database words a refused insert.
pub(crate) fn unchanged(why: Option<Vec<String>>, who: &str, table: String, command: &str, key: String) -> Error {
    match why {
        Some(why) if !why.first().is_some_and(|line| line.trim_start().starts_with("yes")) => {
            Error::Refused(Box::new(Refused {
                message: format!("permission denied: {who} may not {command} row {key} of {table}"),
                table: Some(table),
                command: Some(command.to_owned()),
                why,
                code: "AZ709".to_owned(),
                source: None,
            }))
        }
        _ => Error::NotFound(NotFound { table, id: key }),
    }
}

/// The permissions `authz.perms_of` answered with, by id, as `P`: a name `P` doesn't have (the policy changed since
/// `rowstile client` wrote the names) is left out.
pub(crate) fn perms_by_id<P: Permission>(
    rows: impl IntoIterator<Item = (String, Vec<String>)>,
) -> HashMap<String, Vec<P>> {
    rows.into_iter().map(|(id, perms)| (id, perms.iter().filter_map(|p| P::from_name(p)).collect())).collect()
}
