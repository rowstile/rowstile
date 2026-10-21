#!/usr/bin/env python3
"""features: every feature of rowstile, the parts of its surface each one covers, and the checks that hold it.

    python3 tests/features.py            # what is missing: exit 1 if anything is
    python3 tests/features.py --matrix   # each feature against each suite
    python3 tests/features.py --page     # the table docs/how-it-is-checked.md shows

The surface is read from the code, not from memory: the authz.* functions applying makes (GENERATED_FUNCTIONS) and
those the app role may call (api_signatures()), the command's commands as it dispatches them and as its usage
lists them (with each flag), the forms of the language (the editors' grammar, which tests/parse_agreement.py holds
to the parser), the error codes (errors.CODES), what the SDKs export, the language server's methods, the MCP
server's tools and Studio's routes. Each item is in one feature, and each feature names:

- its tier: 1 decides access or keeps data; 2 is an answer shown to people; 3 is delivery;
- where the docs say it: a page, and a heading on it (or the bold words a paragraph starts with, or a table's
  first cell);
- its fixed checks: a suite, and words that suite holds (a check's label as it prints it, a test's name, the call
  it makes);
- its oracle: the checks that hold it to an answer this code didn't give (the reference evaluator, a rebuild,
  the policy applied whole, Postgres, the answers before), at random or over every case up to a size.
  A feature of tier 1 has one;
- the hand answers worked out for it (the anchors of docs/reference/language.md), and the cases of the editors'
  grammar that parse its forms.

A feature's refusals are its error codes: each of them is asked for by its words somewhere (the RAISE statements
that carry it, by `Guards` in tests/unit_test.py; a mistake in a policy, by its page's example). `Features` in
tests/unit_test.py runs problems() and checks the page's table.
"""

from __future__ import annotations

import ast
import glob
import os
import re
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import NamedTuple

HERE = os.path.dirname(os.path.abspath(__file__))
CORE = os.path.dirname(HERE)
REPO = os.path.dirname(CORE)
for _p in (CORE, os.path.join(CORE, "cli")):
    if _p not in sys.path:
        sys.path.insert(0, _p)


class Check(NamedTuple):
    """A check: a file (under core/, or else the repository's root) and words it holds."""

    path: str
    words: str


class Doc(NamedTuple):
    """Where the docs say it: a page, and a heading on it, the bold words a paragraph or an item starts with, or a
    table row's first cell (each as written, or its start)."""

    page: str
    at: str


@dataclass(frozen=True)
class Feature:
    id: str
    tier: int
    title: str  # what the page's table shows
    covers: tuple[str, ...]  # surface items; `prefix.*` covers every item under the prefix
    doc: Doc
    checks: tuple[Check, ...]
    oracle: tuple[Check, ...] = ()
    hand: tuple[str, ...] = ()  # anchors of docs/reference/language.md
    grammar: tuple[str, ...] = ()  # cases of editor/tree-sitter-authz/test/corpus/
    note: str = ""  # what is known to be missing


def T(suite: str, words: str) -> Check:
    """A check of a suite in core/tests."""
    return Check(f"tests/{suite}", words)


DIFF = "difftest.py"
LANG = "docs/reference/language.md"
APP = "docs/reference/app-code.md"
TOOLS = "docs/reference/tools.md"
GOV = "docs/reference/governance.md"
IDENT = "docs/reference/identity.md"
MIGR = "docs/reference/migrations.md"
FASTAPI = "integrations/fastapi/tests/test_conformance.py"
FASTAPI_SDK = "integrations/fastapi/tests/test_sdk.py"
NEXT = "integrations/nextjs/tests/conformance.test.ts"
NEXT_SDK = "integrations/nextjs/tests/sdk.test.ts"
NEXT_NEXT = "integrations/nextjs/tests/next.test.ts"
REACT = "integrations/nextjs/tests/react.test.tsx"

# the suites that hold rowstile to an answer it didn't give, and what that answer is
ORACLES: dict[str, str] = {
    "difftest.py": "the reference evaluator, after each of a hundred random changes to six policies' data",
    "genpolicy.py": "the reference evaluator, on random policies",
    "around.py": "the reference evaluator, on random policies in random worlds around them",
    "small.py": "the reference evaluator, on every small policy of the core language",
    "invariance.py": "the same answers, for a policy written another way and data renumbered",
    "rewrites.py": "the database's answers, for the review's verdict on rewritten permissions",
    "interleave.py": "a rebuild and the reference evaluator, after every order of two writes",
    "interrupt.py": "the answers before, after a cut after each statement",
    "upgrade_world.py": "a new database with the same rows, after an upgrade from each release from the beta on",
    "migrate_test.py": "the policy applied whole, after each kind of change",
    "conditions_test.py": "Postgres's answer, for each condition the evaluator reads itself",
    "stress.sh": "a rebuild, after sixteen clients write one tree",
}

FEATURES: list[Feature] = [
    # --- what the app asks ------------------------------------------------------------------------------
    Feature(
        "api.answers",
        1,
        "Checks and lists: `authz.can`, `authz.list`, `authz.perms`, `authz.perms_of`",
        ("api.can", "api.list", "api.perms", "api.perms_of"),
        Doc(APP, "check, list, all permissions"),
        (T("scenario.sql", "authz.can("), T("devx.sh", "authz.perms('team'"), T("capitals.sh", "run list")),
        (
            T(DIFF, "authz.can("),
            T(DIFF, "authz.list("),
            T(DIFF, "authz.perms_of("),
            T("small.py", "every policy judged"),
            T("invariance.py", "the same answers"),
            T("upgrade_world.py", "answers as on a new database"),
        ),
    ),
    Feature(
        "api.verify",
        1,
        "Inheritance tables that match a rebuild: `authz.verify`",
        ("api.verify",),
        Doc(APP, "inheritance tables match a rebuild"),
        (
            T("scenario.sql", "every inheritance table matches a from-scratch rebuild"),
            T("moves.sh", "rows inside the moved folder were left alone"),
            T("keep.sh", "a new permission keeps every inheritance table"),
            T("apply.sh", "a move made with the triggers off leaves the inheritance tables behind: verify() is false"),
        ),
        (
            T(DIFF, "authz.verify() is false"),
            T("interleave.py", "inheritance tables exact after each"),
            T("stress.sh", "the inheritance tables match a rebuild"),
        ),
    ),
    Feature(
        "api.who",
        2,
        "Who holds a permission: `authz.who`, `authz.who_among`",
        ("api.who", "api.who_among"),
        Doc(APP, "who has access"),
        (T("devx.sh", "authz.who_among("), T("principals.sh", "authz.who lists users")),
        (T(DIFF, "authz.who("), T(DIFF, "authz.who_among(")),
    ),
    Feature(
        "api.explain",
        2,
        "Why, or why not: `authz.explain`, `authz.explain_rule`",
        ("api.explain", "api.explain_rule"),
        Doc(APP, "why, or what is missing"),
        (
            T("devx.sh", "a refused insert says which rule, and which part of it"),
            T("adversarial.sh", "a write refused in a hidden folder explains as for a missing one"),
            T("docs_test.sh", "explain-rule says which rule and what is missing"),
        ),
        (T(DIFF, "explain self"), T(DIFF, "authz.explain_rule(")),
    ),
    Feature(
        "api.sharing",
        1,
        "Shares: `shared`, `shared by`, `shared if`, their start and end; `authz.share`, `authz.unshare`, "
        "`authz.list_shares`",
        ("api.share", "api.unshare", "api.list_shares", "lang.shared", "err.AZ207", "err.AZ706"),
        Doc(LANG, "Shares"),
        (
            T("multi_scenario.sql", "shared if: no sharing with inactive users"),
            T("governance.sh", "erin (share, but not manage_editors) cannot unshare"),
            T("concurrency.sh", "the share waits for the delete, then is refused"),
            T("scenario.sql", "share on the old id is gone"),
            T("principals.sh", "a viewer may share helper, but not grant assist, which they don't hold"),
        ),
        (
            T(DIFF, "difftest_app.try_share("),
            T(DIFF, "difftest_app.try_list_shares("),
            T("around.py", "def share_problems("),
            T("genpolicy.py", "def shared_if("),
        ),
        hand=("shared-if", "shares-by", "shares-expire", "runtime-share"),
        grammar=("Types, keys and sources",),
        note="a link's `shared if` is not tried at random (it would read the token's hash, drawn at random)",
    ),
    Feature(
        "api.links",
        1,
        "Share links: `link`, `authz.create_link`, `authz.list_links`, `authz.revoke_link`",
        ("api.create_link", "api.list_links", "api.revoke_link", "api.link_hashes"),
        Doc(APP, "share links"),
        (
            T("multi_scenario.sql", "authz.create_link("),
            T("multi_scenario.sql", "nor turn one off, whether its id names a link or not"),
            T("adversarial.sh", "listing the links of a hidden object"),
        ),
        (
            T(DIFF, "difftest_app.try_create_link("),
            T(DIFF, "difftest_app.try_list_links("),
            T("genpolicy.py", "def share_links("),
        ),
        note="links presented by users: the multi policy only at random",
    ),
    Feature(
        "api.roles",
        1,
        "Custom roles at run time: `authz.create_role`, `authz.set_role_permissions`, `authz.delete_role`, "
        "`authz.roles_of`",
        ("api.create_role", "api.set_role_permissions", "api.delete_role", "api.roles_of"),
        Doc(APP, "custom roles"),
        (
            T("multi_scenario.sql", "erin adds edit to reviewer: dave can now edit"),
            T("multi_scenario.sql", "erin deletes the role: its assignments go with it"),
            T("multi_scenario.sql", "alice is no Acme admin: she cannot define roles for Acme"),
        ),
        (
            T(DIFF, "difftest_app.try_create_role("),
            T(DIFF, "difftest_app.try_roles_of("),
            T("genpolicy.py", "def custom_roles("),
        ),
        hand=("roles-create", "runtime-manage-roles"),
    ),
    Feature(
        "api.identity",
        1,
        "Signing in: `authz.act_as`, `authz.login_key`, `authz.login_jwt`, `authz.view_as`, `authz.principal`, "
        "`authz.connection_check`; signed sessions",
        (
            "api.act_as",
            "api.uid",
            "api.principal",
            "api.login_key",
            "api.login_jwt",
            "api.view_as",
            "api.connection_check",
            "err.AZ606",
            "err.AZ701",
            "err.AZ702",
            "err.AZ703",
            "err.AZ704",
            "err.AZ714",
        ),
        Doc(IDENT, "Every sign-in is signed"),
        (
            T("sessions.sh", "changing authz.user_id after signing in is an error"),
            T("sessions.sh", "a signature from an earlier transaction is refused in the next one"),
            T("sessions.sh", "that says it is the policy's owner, whose sessions are believed unsigned"),
            T("identity.sh", "a valid token signs in as bob, with its scope"),
            T("identity.sh", "wrong signature"),
            T("identity.sh", "and cannot change anything"),
            T("principals.sh", "an id the user table doesn't have is nobody: no uid, no principal"),
            Check(FASTAPI, "test_13_refuses_a_connection_that_skips_rls"),
        ),
        (
            T("around.py", "def login_problems("),
            T("around.py", "def unsigned_problems("),
            T("around.py", "def bad_tokens("),
        ),
    ),
    Feature(
        "api.keys",
        1,
        "API keys: `authz.create_api_key`, `authz.list_api_keys`, `authz.revoke_api_key`",
        ("api.create_api_key", "api.list_api_keys", "api.revoke_api_key"),
        Doc(IDENT, "API keys"),
        (
            T("identity.sh", "only the key's hash is kept, and its first ten characters"),
            T("identity.sh", "a session limited to a scope cannot make a key with another"),
            T("principals.sh", "deleting a user deletes their keys"),
            T("principals.sh", "a service given a new id loses its keys, as its shares"),
            T(
                "children.sh",
                "a bot's keys go when its id changes, inside its partition or to another, and with its row",
            ),
        ),
        (T("around.py", "def api_key("), T(DIFF, "def check_scoped(")),
    ),
    Feature(
        "api.sync",
        1,
        "Group sync from an identity provider: `authz.sync_members`",
        ("api.sync_members",),
        Doc(APP, "group sync from an identity provider"),
        (T("identity.sh", "authz.sync_members("), T("identity.sh", "the app role cannot sync")),
        (T(DIFF, "authz.sync_members("),),
    ),
    Feature(
        "api.requests",
        2,
        "Requests for access and breaking the glass: `authz.request_access`, `authz.decide_request`, "
        "`authz.cancel_request`, `authz.pending_requests`, `authz.break_glass`",
        ("api.request_access", "api.decide_request", "api.cancel_request", "api.pending_requests", "api.break_glass"),
        Doc(GOV, "Requests and approvals"),
        (
            T("governance.sh", "carol cannot approve her own request"),
            T("governance.sh", "the share ends after the requested week"),
            T("governance.sh", "a pending request is cancelled when its requester is deleted"),
            T("governance.sh", "a later user with the id has none of the old one's requests"),
            T("governance.sh", "carol breaks the glass, and the alert goes out"),
            T("concurrency.sh", "breaking the glass waits for the delete, then is refused"),
        ),
        hand=("runtime-break-glass",),
    ),
    Feature(
        "api.reviews",
        2,
        "Access reviews: `authz.start_review`, `authz.review_items`, `authz.review_decide`, `authz.close_review`",
        ("api.start_review", "api.review_items", "api.review_decide", "api.close_review"),
        Doc(GOV, "Access reviews"),
        (
            T("governance.sh", "closing the review revokes what was marked"),
            T("governance.sh", "dave (not decided) kept it"),
            T("governance.sh", "authz.review_items("),
            T("governance.sh", "authz.review_decide("),
            T("principals.sh", "authz.start_review is for users: a service is told so"),
        ),
    ),
    Feature(
        "api.feed",
        2,
        "The change feed: `authz.changes_since`, `authz.trim_changes`",
        ("api.changes_since", "api.trim_changes", "err.AZ712"),
        Doc(GOV, "Change feed"),
        (
            T("governance.sh", "moving a folder announces it (and what sits below it)"),
            T("governance.sh", "a reader behind the trimmed part is told to read everything again"),
            T("governance.sh", "the feed keeps 7 days by default: older entries are trimmed"),
            Check(NEXT_SDK, "one connection listens for every subscriber, until the last one leaves"),
        ),
    ),
    Feature(
        "api.audit",
        2,
        "The audit trail: `authz.audit`, `authz.trim_audit`",
        ("api.trim_audit", "err.AZ711"),
        Doc(GOV, "Audit trail"),
        (
            T("governance.sh", "the trail cannot be edited, even by an administrator"),
            T("governance.sh", "a share is recorded, with who made it"),
            T("governance.sh", "memberships kept in your tables are recorded too"),
            T("governance.sh", "and the trim is recorded"),
        ),
    ),
    Feature(
        "api.checks",
        2,
        "Checking the database: `authz.lint`, `authz.check_invariants`",
        ("api.lint", "api.check_invariants"),
        Doc(GOV, "Checking the database"),
        (
            T("governance.sh", "the app role cannot run lint"),
            T("governance.sh", "lint finds a move nothing checks the destination of"),
            T("governance.sh", "lint finds a permission no rule reads that is slow to plan"),
            T("adversarial.sh", "lint reports a grant on rowstile's objects made after apply"),
            T("apply.sh", "lint reports an app role that is a member of the policy's owner: an error"),
            T("governance.sh", "FORCE ROW LEVEL SECURITY or not, since an owner may turn it off"),
            T("governance.sh", "a Globex user owning an Acme folder breaks it"),
        ),
        (T("around.py", "def lint_errors("), T("around.py", "def drift(")),
    ),
    Feature(
        "api.refusals",
        1,
        "What apps see of a refusal: each code's SQLSTATE and HTTP answer, the reason in the error",
        ("err.AZ705", "err.AZ707", "err.AZ708", "err.AZ710"),
        Doc(APP, "Refusals say why."),
        (
            T("unit_test.py", "class RuntimeAnswers("),
            T("reference.sh", "the refusal app-code.md shows is the docs app's, word for word"),
            T("adversarial.sh", "answers as for a missing file"),
            Check(FASTAPI, "test_16_each_code_answers_as_its_page_says"),
            Check(NEXT_NEXT, "16: route: each code as its page says, with the database's words"),
        ),
        (T("around.py", "def write_problems("), T("around.py", "def stranger_problems(")),
    ),
    # --- the command ------------------------------------------------------------------------------------
    Feature(
        "cli.apply",
        1,
        "Applying a policy: `rowstile apply`, `check`, `push`, `diff`, `remove`",
        (
            "cli.apply",
            "cli.check",
            "cli.push",
            "cli.diff",
            "cli.remove",
            "err.AZ609",
            "err.AZ610",
            "err.AZ612",
            "err.AZ614",
            "err.AZ624",
        ),
        Doc(TOOLS, "`rowstile apply"),
        (
            T("apply.sh", "the owner applies the policy, with no superuser"),
            T("apply.sh", "again: unchanged"),
            T("apply.sh", "shares are kept"),
            T("apply.sh", "its schemas are gone"),
            T("apply.sh", "applying refuses the policy's owner as the app role"),
            T("cli.sh", "check: ok, exit 0"),
            T("cli.sh", "diff lists who loses what"),
            T("migrations.sh", "a second change is pushed too"),
            T("children.sh", "apply is not 'unchanged' then: it applies"),
        ),
        (
            T("interrupt.py", "after each cut, the database is as it was"),
            T("around.py", "def drift("),
            T("migrate_test.py", "applying whole"),
        ),
    ),
    Feature(
        "cli.migrate",
        1,
        "Migrations: `rowstile migrate`, the lock file, trees built beside then swapped in",
        ("cli.migrate", "err.AZ607", "err.AZ608", "err.AZ615", "err.AZ619"),
        Doc(MIGR, "Deploying a policy: migrations"),
        (
            T("migrations.sh", "migrate writes two: build beside, then swap in"),
            T("migrations.sh", "the second swaps it in, with what the app wrote meanwhile"),
            T("migrations.sh", "a migration run a statement at a time is refused (AZ615), and changes nothing"),
            T("migrations.sh", "the same migration again is refused: the database holds it already"),
            T("unit_test.py", "test_lines_that_only_move_need_no_migration"),
        ),
        (
            T("migrate_test.py", "applying whole"),
            T("interrupt.py", "between a migration's two: the old policy in force"),
        ),
    ),
    Feature(
        "cli.upgrade",
        1,
        "Upgrading rowstile: `rowstile reapply`, migrations from an older release (from the beta on)",
        ("cli.reapply", "err.AZ616", "err.AZ626"),
        Doc(MIGR, "Upgrading rowstile"),
        (
            T("upgrade.sh", "it holds what applying this version on a new database leaves"),
            T("upgrade.sh", "the API key made before still signs dave in"),
            T("unit_test.py", "test_the_alphas_are_never_the_release_before"),
            T("apply.sh", "a policy a newer version applied is refused, naming both versions"),
            T(
                "cli.sh",
                "a function an older rowstile didn't make: which version applied the policy, and rowstile reapply (AZ626)",
            ),
            T("cli.sh", "... one a newer rowstile applied: upgrade the command (AZ616)"),
        ),
        (T("upgrade_world.py", "answers as on a new database"),),
    ),
    Feature(
        "cli.test",
        2,
        "Running the policy's tests: `rowstile test`",
        ("cli.test",),
        Doc(TOOLS, "`rowstile test [tests.authz"),
        (
            T("cli.sh", "test passes and shows each check"),
            T("cli.sh", "a failing test fails the command, exit 1"),
            T("devx.sh", "test runs named test files, exit 0"),
            T("confidence_test.py", 'cli(db, "test"'),
        ),
    ),
    Feature(
        "cli.questions",
        2,
        "Asking the database as someone: `rowstile can`, `explain`, `perms`, `list`, `who`, `explain-rule`, `sql`",
        ("cli.can", "cli.explain", "cli.perms", "cli.list", "cli.who", "cli.explain-rule", "cli.sql", "err.AZ618"),
        Doc(TOOLS, "`rowstile can"),
        (
            T("cli.sh", "run can"),
            T("devx.sh", "run explain"),
            T("cli.sh", "run explain-rule"),
            T("cli.sh", "run perms"),
            T("capitals.sh", "run list"),
            T("cli.sh", "run who"),
            T("cli.sh", "run sql"),
            T("cli.sh", "explain-rule shows a row a Windows shell took the quotes out of, and how to write it there"),
        ),
        note="the command asks the authz.* functions the random checks judge",
    ),
    Feature(
        "cli.why",
        2,
        "What would grant a permission: `rowstile why`",
        ("cli.why",),
        Doc(TOOLS, "`rowstile why"),
        (
            T("studio_test.py", 'cli(db, "why"'),
            T("studio_test.py", "the smallest change first: a share on the folder itself"),
            T("studio_test.py", "nothing it tried stays"),
            T("unit_test.py", "class Why("),
        ),
    ),
    Feature(
        "cli.review",
        2,
        "Reviewing a change: `rowstile review`, `rowstile snapshot`",
        ("cli.review", "cli.snapshot", "err.AZ623"),
        Doc("docs/reference/review.md", "Reviewing a policy change"),
        (
            T("review.sh", "Access: who gains what, on the review data"),
            T("review.sh", "a refactor: meaning unchanged, checked in small worlds"),
            T("review.sh", "the review database is left as it was"),
            T("review.sh", "the comment in the file, and the annotations printed, from one review"),
            T("unit_test.py", "test_the_action_reviews_once_for_the_comment_and_the_annotations"),
            T("unit_test.py", "test_a_widening_is_flagged_however_it_is_made"),
            T("confidence_test.py", 'cli(db, "snapshot"'),
            T("confidence_test.py", "more people in the data than a snapshot is for: refused, saying how many"),
        ),
        (T("rewrites.py", "grants the same"),),
    ),
    Feature(
        "cli.fmt",
        2,
        "One layout for policies: `rowstile fmt`",
        ("cli.fmt",),
        Doc(TOOLS, "`rowstile fmt"),
        (
            T("review.sh", "CLI fmt"),
            T("unit_test.py", "class Fmt("),
            T("unit_test.py", "test_the_repositorys_policies_are_laid_out_as_fmt_writes_them"),
        ),
        (T("invariance.py", "def laid_out("),),
    ),
    Feature(
        "cli.prove",
        2,
        "Invariants in small worlds: `rowstile prove`",
        ("cli.prove",),
        Doc(TOOLS, "`rowstile prove"),
        (
            T(
                "confidence_test.py",
                "an invariant the policy doesn't guarantee: exit 1, and the smallest counterexample",
            ),
            T("unit_test.py", "test_prove_finds_the_smallest_counterexample"),
            T("unit_test.py", "test_prove_finds_a_counterexample_that_needs_conditions_at_once"),
            T("cli.sh", "run prove"),
        ),
        (T("genpolicy.py", "def invariant_problems("),),
    ),
    Feature(
        "cli.perf",
        2,
        "Speed: `rowstile indexes`, `plans`, `bench`",
        ("cli.indexes", "cli.plans", "cli.bench"),
        Doc(TOOLS, "`rowstile indexes"),
        (
            T("capitals.sh", "run indexes"),
            T("confidence_test.py", 'cli(db, "plans"'),
            T("confidence_test.py", 'cli(db, "bench"'),
            T("unit_test.py", "class Plans("),
        ),
    ),
    Feature(
        "cli.tools",
        3,
        "The diagram, the clients, lint and help: `rowstile graph`, `client`, `lint`, `help`, `--version`",
        ("cli.graph", "cli.client", "cli.lint", "cli.help", "cli.--version"),
        Doc(TOOLS, "`rowstile graph"),
        (
            T("cli.sh", "check, graph and client of a file need no database"),
            T("tools_test.py", "expect, a row the user may not change: Refused, with why"),
            T("cli.sh", "lint where it finds nothing says so, exit 0"),
            T("unit_test.py", "test_typescript_sdk_gets_only_the_names"),
            T("cli.sh", "help AZ"),
            T("cli.sh", "--version"),
        ),
    ),
    Feature(
        "cli.dev",
        3,
        "The development loop: `rowstile dev`",
        ("cli.dev",),
        Doc(TOOLS, "`rowstile dev"),
        (
            T("devx.sh", "compiles, applies, tests, writes the client"),
            T("devx.sh", "says before each push who gains and loses what: rows by table, permissions by type"),
            T("devx.sh", "dev won't push to a database with a policy that isn't marked as a development database"),
            T("migrations.sh", "a save, then quiet: the migration is written, named after what changed"),
        ),
    ),
    Feature(
        "cli.init",
        3,
        "A first policy from the database: `rowstile init`",
        ("cli.init", "err.AZ620", "err.AZ621", "err.AZ622"),
        Doc(TOOLS, "`rowstile init"),
        (
            T("devx.sh", "a second init changes nothing in it"),
            T("unit_test.py", "class Draft("),
            T("devx.sh", "a schema with no tables is named"),
            T("devx.sh", "init where the users are in a schema not drafted: says which, and what to do"),
            T("devx.sh", "a users table keyed by two columns: says what it lacks"),
            T("devx.sh", "init --out outside the folder, by a $k path: refused, exit 2, nothing written"),
            T("unit_test.py", "test_a_user_table_the_draft_leaves_out_is_said"),
        ),
    ),
    # --- the servers ------------------------------------------------------------------------------------
    Feature(
        "studio.read",
        2,
        "Studio, reading: `rowstile studio`, the rows as anyone, why, the graph, the access diff, shares, tests",
        (
            "cli.studio",
            "studio.overview",
            "studio.rows",
            "studio.why",
            "studio.graph",
            "studio.diff",
            "studio.shares",
            "studio.test",
        ),
        Doc(TOOLS, "`rowstile studio"),
        tuple(T("studio_test.py", f"/api/{r}") for r in ("overview", "rows", "why", "graph", "diff", "shares", "test"))
        + (T("studio_test.py", "the API needs the token"), T("studio_test.py", "read-only: no shares made")),
        note="the rows: what the app role reads, as row-level security gives it, not held to the reference",
    ),
    Feature(
        "studio.write",
        1,
        "Studio, writing (`--write`): share, unshare, decide a request",
        ("studio.share", "studio.unshare", "studio.decide"),
        Doc(TOOLS, "`rowstile studio"),
        (
            T("studio_test.py", "/api/share"),
            T("studio_test.py", "/api/unshare"),
            T("studio_test.py", "/api/decide"),
            T("studio_test.py", "it says it can write, and does"),
        ),
        (T(DIFF, "difftest_app.try_share("),),
        note="its oracle is authz.share's, which Studio calls as the person viewed as",
    ),
    Feature(
        "lsp",
        3,
        "The language server: `rowstile lsp`",
        ("cli.lsp", "lsp.*"),
        Doc(TOOLS, "`rowstile lsp"),
        tuple(
            T("lsp_test.py", f'"{m}"')
            for m in (
                "initialize",
                "shutdown",
                "exit",
                "textDocument/didOpen",
                "textDocument/didChange",
                "textDocument/didSave",
                "textDocument/didClose",
                "textDocument/hover",
                "textDocument/definition",
                "textDocument/references",
                "textDocument/completion",
                "textDocument/documentSymbol",
            )
        ),
    ),
    Feature(
        "mcp",
        2,
        "The MCP server, for coding agents: `rowstile mcp`",
        ("cli.mcp", "mcp.*"),
        Doc(TOOLS, "Coding agents: `rowstile mcp`"),
        tuple(T("mcp_test.py", f'"{t}"') for t in ("check", "lint", "prove", "push", "review", "test", "why"))
        + (
            T("mcp_test.py", "push to a database nobody marked: refused"),
            T("reference.sh", "the MCP server tools.md's settings start lists the tools the page names"),
        ),
        note="each tool runs the command once: its answers are the command's",
    ),
    # --- the language: each form the grammar names ------------------------------------------------------
    Feature(
        "lang.types",
        1,
        "Types and the rows that count: `type`, `where`, `app role`",
        ("lang.source_file", "lang.app_role", "lang.type", "lang.table_name", "lang.principal")
        + ("err.AZ101", "err.AZ107", "err.AZ109", "err.AZ111", "err.AZ201", "err.AZ202", "err.AZ601"),
        Doc(LANG, "Rows that count"),
        (
            T("unit_test.py", "test_a_rule_gives_no_row_the_type_leaves_out"),
            T("policy_errors.py", "COMPILE = ["),
            T("principals.sh", "a service failing the type's where is nobody"),
            T(
                "apply.sh",
                "a column it reads that the app dropped since: apply refuses it with its line, not unchanged",
            ),
        ),
        (T(DIFF, "class CrossGen("), T("small.py", "user_where"), T("genpolicy.py", "def make(")),
        hand=("rows-hold-nothing", "rows-in-permissions", "rows-no-rule", "rows-no-invariant"),
        grammar=("Types, keys and sources",),
    ),
    Feature(
        "lang.keys",
        1,
        "Keys: of any type, of several columns",
        ("lang.key", "lang.key_column", "err.AZ206", "err.AZ602"),
        Doc(LANG, "Keys"),
        (T("unit_test.py", "class CompositeKeys("), T("unit_test.py", "class KeyTypeChecks(")),
        (T(DIFF, "class CompositeGen("), T("genpolicy.py", "keytype"), T("around.py", "keys: two columns")),
        hand=("keys-composite",),
        grammar=("Types, keys and sources",),
    ),
    Feature(
        "lang.includes",
        2,
        "Policies in several files: `include`",
        ("lang.include", "err.AZ108"),
        Doc(LANG, "The policy language"),
        (
            T("unit_test.py", "class Includes("),
            T("cli.sh", "apply reads the included files from disk"),
            T("policy_errors.py", "a file above the policy's folder"),
        ),
        (T("invariance.py", "def included("), T("genpolicy.py", "def write_policy(")),
    ),
    Feature(
        "lang.relations",
        1,
        "Relations and their sources: columns, pairs of columns, link tables",
        (
            "lang.relation",
            "lang.column",
            "lang.columns",
            "lang.typed_columns",
            "lang.table_source",
            "lang.side",
        )
        + ("err.AZ103", "err.AZ205", "err.AZ208", "err.AZ209"),
        Doc(LANG, "Relations"),
        (T("unit_test.py", "class LanguageForms("), T("scenario.sql", "TRUNCATE of the link table")),
        (
            T(DIFF, "class CrossGen("),
            T(DIFF, "class MultiGen("),
            T("small.py", "def sources("),
            T("genpolicy.py", "def named_columns("),
        ),
        hand=("relation-sources", "relation-again", "polymorphic-type-names"),
        grammar=("Types, keys and sources", "Relations named like the words that start a line"),
    ),
    Feature(
        "lang.subjects",
        1,
        "Subjects and principals: a type, a group's members, `user:*`, `anyone`, `link`, services",
        ("lang.subject", "lang.anyone", "lang.link", "err.AZ204", "err.AZ715"),
        Doc(LANG, "Subjects"),
        (
            T("principals.sh", "so a column that still names it grants nothing, nor does user:*"),
            T("principals.sh", "authz.create_role is for users: a service is told so"),
            T("principals.sh", "it shares as itself: created_by says so"),
            T("unit_test.py", "class Principals("),
        ),
        (T(DIFF, "class MultiGen("), T("small.py", "def subject_ids(")),
        hand=("subjects", "principals", "signed-in-anyone-nobody"),
        grammar=("Types, keys and sources",),
    ),
    Feature(
        "lang.permissions",
        1,
        "Permissions: `can`, `or`, `and`, `not`, following a relation",
        ("lang.permission", "lang.or", "lang.and", "lang.not", "lang.parenthesized", "lang.ref", "lang.arrow")
        + ("err.AZ102", "err.AZ104", "err.AZ203", "err.AZ301", "err.AZ302", "err.AZ307"),
        Doc(LANG, "Permissions"),
        (T("unit_test.py", "class LanguageForms("), T("policy_errors.py", "and next to or")),
        (
            T(DIFF, "authz.can("),
            T("genpolicy.py", "def make("),
            T("small.py", "every policy judged"),
            T("rewrites.py", "def rewrites("),
        ),
        hand=("permission-operators", "follow-relation", "own-row"),
        grammar=("Permissions: or < and < not, lines that continue",),
    ),
    Feature(
        "lang.conditions",
        1,
        "Conditions: `{...}`, `this`, read with the policy's rights",
        ("lang.sql", "lang.sql_text", "err.AZ110", "err.AZ112", "err.AZ113", "err.AZ613"),
        Doc(LANG, "Conditions name their row `this`"),
        (
            T("devx.sh", "a rule condition that reads a governed table runs with the policy's rights, as a function"),
            T("apply.sh", "a condition that doesn't run names its line"),
            T("unit_test.py", "class ThisRow("),
            T("apply.sh", "a signing-in type's where whose subquery calls its table w: applies, then is unchanged"),
            T("governance.sh", "the audit trail relates only the link rows whose where holds"),
            T("policy_errors.py", "a name that starts with authz__ in a condition"),
        ),
        (T("conditions_test.py", "def condition("), T("genpolicy.py", "READS = [")),
        hand=("conditions-sql", "conditions-null", "conditions-this", "conditions-rights"),
        grammar=("Words for conditions, custom roles where they give, this in conditions",),
    ),
    Feature(
        "lang.inheritance",
        1,
        "Inheritance and denies: `parent.view`, `and {condition}`, `and not`; moves, loops",
        (
            "err.AZ303",
            "err.AZ304",
            "err.AZ305",
            "err.AZ306",
            "err.AZ603",
            "err.AZ604",
            "err.AZ605",
            "err.AZ713",
        ),
        Doc(LANG, "Inheritance"),
        (
            T("scenario.sql", "moving Engineering into its own subfolder is refused"),
            T("scenario.sql", "a loop through links does not hang and changes nothing for carol"),
            T("moves.sh", "rows inside the moved folder were left alone"),
            T("concurrency.sh", "no loop"),
            T("policy_errors.py", "a deny that doesn't cover what is below"),
            T("policy_errors.py", "a deny on a permission that inherits through a relation to another type too"),
            T("unit_test.py", "class Denies("),
        ),
        (
            T(DIFF, "class CrossGen("),
            T("interleave.py", "inheritance tables exact after each"),
            T("small.py", "def denies("),
            T("genpolicy.py", "def across("),
            T("stress.sh", "the inheritance tables match a rebuild"),
        ),
        hand=("inheritance", "condition-every-level", "deny-below", "deny-other-types"),
    ),
    Feature(
        "lang.roles",
        1,
        "Custom roles in the policy: `roles : ... from ...`, `roles` in a permission",
        ("lang.roles", "err.AZ210", "err.AZ211"),
        Doc(LANG, "Custom roles"),
        (
            T("multi_scenario.sql", "cannot give the archivist role, for he does not hold archive"),
            T("unit_test.py", "test_roles_from_an_org_count_only_on_its_objects"),
            T("unit_test.py", "test_roles_without_from_count_wherever_they_are_given"),
        ),
        (T(DIFF, "authz.roles (id, owner_type"), T("genpolicy.py", "def custom_roles(")),
        hand=("roles-from", "roles-include", "roles-refused", "roles-without-from"),
        grammar=("Words for conditions, custom roles where they give, this in conditions",),
    ),
    Feature(
        "lang.rules",
        1,
        "Rules: `select`, `insert`, `update` (before, after, on columns), `delete`",
        ("lang.rules", "lang.rule", "lang.command", "err.AZ105", "err.AZ401", "err.AZ403", "err.AZ709"),
        Doc(LANG, "Rules"),
        (
            T("devx.sh", "a refused insert says which rule, and which part of it"),
            T("adversarial.sh", "alice can't move her folder under a folder she may not edit"),
            T("adversarial.sh", "and both at once: the rule on the row before the change says why"),
            T("unit_test.py", "test_triggers_are_named_after_what_they_guard"),
            T("children.sh", "rule"),
            Check(FASTAPI, "test_6_a_refused_insert_says_which_rule"),
        ),
        (T(DIFF, "policy as app"), T("around.py", "def write_problems("), T("genpolicy.py", "def before_after(")),
        hand=("rules-commands", "update-before-after", "column-rules"),
        grammar=("Rules, masks, scopes, caveats, invariants",),
    ),
    Feature(
        "lang.masks",
        1,
        "Masked columns: `mask`, the view",
        ("lang.mask", "err.AZ402", "err.AZ611", "err.AZ617"),
        Doc(LANG, "Masked columns"),
        (
            T("masks.sh", "the app role cannot read the masked column from the table"),
            T("masks.sh", "a mask PUBLIC could read around is refused"),
            T("multi_scenario.sql", "sees doc 01 in the masked view, but not its text"),
            T("apply.sh", "replaced in place, the app's view stays"),
        ),
        (T(DIFF, "the view of"), T("genpolicy.py", "def masks(")),
        hand=("mask-table", "mask-view"),
        grammar=("Rules, masks, scopes, caveats, invariants",),
    ),
    Feature(
        "lang.cascades",
        2,
        "Foreign keys whose action is meant: `cascade from`, and the warning of the others",
        ("lang.cascade", "err.AZ625"),
        Doc(LANG, "Rules"),
        (
            T("apply.sh", "re-applying warns of a foreign key that deletes a governed table's rows by cascade"),
            T("apply.sh", "(ON DELETE SET NULL)"),
            T("apply.sh", "a cascade marked as meant (cascade from) is no warning"),
            T("apply.sh", "a cascade line that two keys answer to is refused"),
            T("apply.sh", "a cascade line that names no foreign key that acts is refused (AZ625)"),
            T("policy_errors.py", "a cascade line written twice"),
            T("unit_test.py", "test_a_cascade_line_added_and_removed"),
            T("unit_test.py", "test_a_cascade_line(self)"),
        ),
        grammar=("Foreign keys whose action is meant",),
    ),
    Feature(
        "lang.scopes",
        1,
        "Scopes: what a key or a token may do",
        ("lang.scope", "lang.scope_item", "lang.scope_name", "err.AZ404"),
        Doc(IDENT, "scopes"),
        (
            T("identity.sh", "files key: sees no folders (not in its scope)"),
            T("identity.sh", "read-only key: may view file 11, not edit it"),
            T("sessions.sh", "clearing its scopes is an error, not a way to write"),
        ),
        (T(DIFF, "def check_scoped("), T("genpolicy.py", "def draw_scopes(")),
        grammar=("Rules, masks, scopes, caveats, invariants",),
    ),
    Feature(
        "lang.caveats",
        1,
        "Caveats: conditions a share carries",
        ("lang.caveat", "api.ctx"),
        Doc(LANG, "caveat"),
        (T("multi_scenario.sql", "caveat"),),
        (T(DIFF, "business_hours"), T("genpolicy.py", "CAVEATS = {")),
        hand=("caveats",),
        grammar=("Rules, masks, scopes, caveats, invariants",),
    ),
    Feature(
        "lang.invariants",
        2,
        "Invariants: `never`",
        ("lang.invariants", "lang.never"),
        Doc(LANG, "Invariants"),
        (
            T("governance.sh", "the example data keeps the invariant"),
            T("principals.sh", "invariants are asked as each service too, named as the audit trail names it"),
            T("unit_test.py", "test_prove_finds_the_smallest_counterexample"),
        ),
        (T("genpolicy.py", "def invariant_problems("),),
        hand=("invariants",),
        grammar=("Rules, masks, scopes, caveats, invariants",),
    ),
    Feature(
        "lang.tests",
        2,
        "The policy's tests: checks, named tests, `given`, `as`, `with scope`",
        (
            "lang.test",
            "lang.given",
            "lang.as",
            "lang.check",
            "lang.limited",
            "err.AZ106",
            "err.AZ501",
            "err.AZ502",
            "err.AZ503",
        ),
        Doc(LANG, "Tests"),
        (
            T("devx.sh", "a failing check names its file and line, and explains itself"),
            T("devx.sh", "with scope: a line is checked as a key limited to those scopes, and the next line is not"),
            T("unit_test.py", "class TestFiles("),
            T("cookbook.sh", "every line of policy and tests its page shows is in its files"),
        ),
        hand=("tests-refused", "tests-scope"),
        grammar=("Tests: checks, and named tests with their own data",),
    ),
    # --- the SDKs: each judged by its conformance suite (integrations/README.md's checks) ---------------
    Feature(
        "sdk.python",
        2,
        "The Python SDK: signing in, refusals as answers, jobs",
        ("sdk.py.*",),
        Doc(APP, "Python: supported."),
        (
            Check(FASTAPI, "test_3_not_signed_in_is_an_error_that_says_how"),
            Check(FASTAPI, "test_10_a_job_acts_as_its_service"),
            Check(FASTAPI, "test_refused_means_the_database_said_no"),
            Check(FASTAPI_SDK, "test_a_principal_as_it_is_and_one_without_an_id"),
        ),
        note="the SDK's own code is not measured by the coverage runs",
    ),
    Feature(
        "sdk.python.stacks",
        2,
        "The Python SDK's stacks: FastAPI, SQLAlchemy, psycopg, asyncpg, Alembic, pytest",
        ("sdk.py.fastapi.*", "sdk.py.sqlalchemy.*", "sdk.py.psycopg.*", "sdk.py.asyncpg.*", "sdk.py.alembic.*")
        + ("sdk.py.testing.*", "sdk.py.command.*"),
        Doc(APP, "Python: supported."),
        (
            Check(FASTAPI, "test_5_concurrent_requests_never_mix_users"),
            Check(FASTAPI, "test_psycopg_transactions"),
            Check(FASTAPI, "test_asyncpg_transactions"),
            Check(FASTAPI, "test_sqlalchemy_sync_engine"),
            Check(FASTAPI, "test_the_pytest_helpers"),
            Check(FASTAPI_SDK, "test_autogenerate_leaves_rowstiles_tables_alone_with_include_object_alone"),
            Check(FASTAPI_SDK, "test_where_the_command_is"),
        ),
    ),
    Feature(
        "sdk.typescript",
        2,
        "The TypeScript SDK: `@rowstile/client`",
        ("sdk.ts.client.*",),
        Doc(APP, "TypeScript: preview."),
        (
            Check(NEXT, "3: not signed in is an error that says how"),
            Check(NEXT_SDK, "ids and principals, as the database writes them"),
            Check(NEXT_SDK, "errors, as a problem body and as a response"),
            Check(NEXT, "refused means the database said no"),
        ),
    ),
    Feature(
        "sdk.typescript.drivers",
        2,
        "The TypeScript SDK's drivers: `/pg`, `/postgres`, `/prisma`, `/drizzle`",
        ("sdk.ts.pg.*", "sdk.ts.postgres.*", "sdk.ts.prisma.*", "sdk.ts.drizzle.*"),
        Doc(APP, "TypeScript: preview."),
        (
            Check(NEXT, "5: concurrent requests never mix users"),
            Check(NEXT, "pg: transactions signed in, refusals as errors"),
            Check(NEXT, "postgres.js: begin() signed in"),
            Check(NEXT, "Drizzle: transactions signed in, inIds, expect"),
            Check(NEXT_SDK, "@rowstile/prisma"),
        ),
    ),
    Feature(
        "sdk.typescript.next",
        2,
        "The TypeScript SDK for Next.js and React: `/next`, `/react`, `/vitest`",
        ("sdk.ts.next.*", "sdk.ts.react.*", "sdk.ts.vitest.*"),
        Doc(APP, "TypeScript: preview."),
        (
            Check(NEXT, "15: signed-in pages are never cached for another user"),
            Check(NEXT_NEXT, "checkAtStart: the server stops on a connection that skips row-level security, with why"),
            Check(NEXT_NEXT, "GET: a list's permissions, the shares, and nothing else"),
            Check(REACT, "usePerms"),
            Check(NEXT_SDK, "@rowstile/vitest"),
        ),
    ),
]


# --- the surface, read from the code -------------------------------------------------------------------


def read(rel: str) -> str:
    with open(os.path.join(REPO, rel), encoding="utf-8") as fh:
        return fh.read()


def api() -> set[str]:
    """The authz.* functions applying makes (GENERATED_FUNCTIONS), and those the app role may call."""
    from authzlib.base import GENERATED_FUNCTIONS

    return {f"api.{n}" for n in GENERATED_FUNCTIONS} | app_callable()


def app_callable() -> set[str]:
    """The authz.* functions the app role may execute, as the docs app's policy grants them (api_signatures())."""
    from authzlib import Compiler, parse_policy

    path = os.path.join(CORE, "example", "docs.authz")
    with open(path, encoding="utf-8") as fh:
        compiler = Compiler(parse_policy(fh.read(), path))
    return {"api." + s.split("(")[0].removeprefix("authz.") for s in compiler.api_signatures()}


USAGE_LINE = re.compile(r"^ {4}rowstile (\S+)(.*)$")


def usage() -> dict[str, set[str]]:
    """Each command the usage lists, and the flags its lines name."""
    import rowstile_cli

    assert rowstile_cli.__doc__ is not None
    out: dict[str, set[str]] = {}
    cmd = ""
    for line in rowstile_cli.__doc__.splitlines():
        if m := USAGE_LINE.match(line):
            cmd = m[1]
            out.setdefault(cmd, set())
        elif not line.startswith(" " * 6):  # the end of a command's lines
            cmd = ""
        if cmd:
            # a flag is its command's, unless the word before it names another (`migrate --check`)
            for m in re.finditer(r"(?<![\w-])--[a-z][a-z-]*", line):
                before = line[: m.start()].split()
                whose = before[-1] if before and before[-1] in rowstile_cli.ARGUMENTS else cmd
                if m[0] != cmd:
                    out.setdefault(whose, set()).add(m[0])
    return out


def commands() -> set[str]:
    """The command's commands as it dispatches them (ARGUMENTS) and as its usage lists them, with their flags."""
    import rowstile_cli

    out = {f"cli.{c}" for c in rowstile_cli.ARGUMENTS}
    for cmd, flags in usage().items():
        out.add(f"cli.{cmd}")
        out |= {f"cli.{cmd} {f}" for f in flags}
    return out


def codes() -> set[str]:
    from authzlib import errors

    return {f"err.{c}" for c in errors.CODES}


def mcp_tools() -> set[str]:
    import mcp

    return {f"mcp.{t}" for t in mcp.TOOLS}


def studio_routes() -> set[str]:
    """Studio's API: the GET routes (its `gets` table) and the changes a page may POST."""
    text = read("core/cli/studio.py")
    table = text[text.index("gets: dict[") :]
    table = table[: table.index("}")]
    gets = set(re.findall(r'"(\w+)":\s*studio\.', table))
    m = re.search(r'method == "POST" and name in \(([^)]*)\)', text)
    assert m is not None, "Studio's POST routes are not where they were"
    return {f"studio.{n}" for n in gets | set(re.findall(r'"(\w+)"', m[1]))}


def lsp_methods() -> set[str]:
    """The language server's methods, as its dispatch (`handle`) names them."""
    text = read("core/cli/lsp.py")
    body = text[text.index("    def handle(") :]
    end = re.compile(r"\n {0,4}\S").search(body, 10)  # the next line no deeper than the def
    body = body[: end.start() if end else len(body)]
    names: set[str] = set()
    for m in re.finditer(r'method (?:==|in) (\([^)]*\)|"[^"]+")', body):
        names |= set(re.findall(r'"([^"]+)"', m[1]))
    return {f"lsp.{n.split('/')[-1]}" for n in names}


def sdk_python() -> set[str]:
    """What the Python package exports: its __all__, and the public names of the modules beside it."""
    out: set[str] = set()
    folder = os.path.join(REPO, "sdk", "python", "rowstile")
    for name in sorted(os.listdir(folder)):
        if not name.endswith(".py") or (name.startswith("_") and name != "__init__.py"):
            continue
        tree = ast.parse(read(f"sdk/python/rowstile/{name}"))
        prefix = "sdk.py." if name == "__init__.py" else f"sdk.py.{name[:-3]}."
        for node in tree.body:
            if name == "__init__.py":
                if isinstance(node, ast.Assign) and any(
                    isinstance(t, ast.Name) and t.id == "__all__" for t in node.targets
                ):
                    assert isinstance(node.value, ast.List | ast.Tuple)
                    out |= {prefix + str(ast.literal_eval(e)) for e in node.value.elts}
            elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                if not node.name.startswith("_"):
                    out.add(prefix + node.name)
            elif isinstance(node, ast.Assign):
                out |= {
                    prefix + t.id
                    for t in node.targets
                    if isinstance(t, ast.Name) and t.id.isupper() and not t.id.startswith("_")
                }
    return out


def sdk_typescript() -> set[str]:
    """What each TypeScript package exports from its index."""
    out: set[str] = set()
    root = os.path.join(REPO, "sdk", "typescript")
    for pkg in sorted(os.listdir(root)):
        found = [p for p in (os.path.join(root, pkg, "src", f"index.{e}") for e in ("ts", "tsx")) if os.path.exists(p)]
        for index in found:
            with open(index, encoding="utf-8") as fh:
                text = fh.read()
            names = set(
                re.findall(
                    r"^export\s+(?:async\s+)?(?:function|class|const|let|type|interface|enum)\s+(\w+)", text, re.M
                )
            )
            for group in re.findall(r"^export\s+(?:type\s+)?\{([^}]*)\}", text, re.M):
                names |= {n.split(" as ")[-1].strip().removeprefix("type ") for n in group.split(",") if n.strip()}
            out |= {f"sdk.ts.{pkg}.{n}" for n in names}
    return out


def language() -> set[str]:
    """The language's forms, as the editors' grammar names them: its rules, less the hidden ones (`_x`) and the
    ones that read a token's characters (names, values, comments) rather than a word of the language."""
    text = read("editor/tree-sitter-authz/grammar.js")
    out: set[str] = set()
    for m in re.finditer(r"^ {4}(\w+): \((\$|_)\) =>(.*)$", text, re.M):
        name, arg, body = m.groups()
        if name.startswith("_") or (arg == "_" and ("/" in body or '"' not in body)):
            continue
        out.add(f"lang.{name}")
    return out


SURFACES: dict[str, Callable[[], set[str]]] = {
    "the authz.* API": api,
    "the command": commands,
    "error codes": codes,
    "the MCP server": mcp_tools,
    "Studio": studio_routes,
    "the language server": lsp_methods,
    "the Python SDK": sdk_python,
    "the TypeScript SDK": sdk_typescript,
    "the language": language,
}


def surface() -> dict[str, set[str]]:
    return {name: f() for name, f in SURFACES.items()}


# --- what the registry is checked against ---------------------------------------------------------------


def owner(item: str, features: Iterable[Feature] = FEATURES) -> list[str]:
    """The features that cover an item: by name, by a prefix (`sdk.py.*`), or, for a command's flag, the
    feature of its command."""
    base = item.split(" ")[0] if item.startswith("cli.") else item
    named = [f.id for f in features if base in f.covers]
    if named:
        return named
    # by the longest prefix: `sdk.py.fastapi.*` before `sdk.py.*`
    prefixes = [(len(c), f.id) for f in features for c in f.covers if c.endswith(".*") and base.startswith(c[:-1])]
    longest = max((n for n, _ in prefixes), default=0)
    return [i for n, i in prefixes if n == longest]


def path_of(rel: str) -> str:
    """A check's file: under core/, or else the repository's root."""
    under_core = os.path.join(CORE, rel)
    return under_core if os.path.exists(under_core) else os.path.join(REPO, rel)


def suite(rel: str) -> str:
    """The suite a check's file belongs to, as the table names it."""
    if rel.startswith("tests/hand/"):
        return "hand_answers.sh"
    if rel.startswith("tests/"):
        return rel.removeprefix("tests/")
    if rel.startswith("integrations/"):
        return "/".join(rel.split("/")[:2])
    return rel


def anchors() -> list[str]:
    """The anchors of the paragraphs of the language's reference that say an answer."""
    page = read("docs/reference/language.md")
    return [a for m in re.findall(r"<!-- answer: ([a-z0-9-]+(?:, [a-z0-9-]+)*) -->", page) for a in m.split(", ")]


def grammar_cases() -> list[str]:
    """The names of the editors' grammar's test cases."""
    out: list[str] = []
    for path in sorted(glob.glob(os.path.join(REPO, "editor", "tree-sitter-authz", "test", "corpus", "*.txt"))):
        with open(path, encoding="utf-8") as fh:
            out += re.findall(r"^=+\n(.+)\n=+$", fh.read(), re.M)
    return out


def places(page: str) -> list[str]:
    """What a Doc may point to on a page: its headings, the bold words a paragraph or an item starts with, and
    each table row's first cell."""
    out: list[str] = []
    fence = False
    for line in read(page).splitlines():
        if line.startswith("```"):
            fence = not fence
        if fence:
            continue
        if m := re.match(r"#{1,6} (.+)", line):
            out.append(m[1])
        out += re.findall(r"\*\*(.+?)\*\*", line)
        if line.startswith("|"):
            out.append(line.split("|")[1].strip())
    return out


def suite_texts() -> dict[str, str]:
    """The suites' files (core/tests, and the conformance apps' tests), each file's text: not the unit tests,
    which name what they look for."""
    out: dict[str, str] = {}
    for pattern in ("core/tests/*.*", "core/tests/hand/*.*", "integrations/*/test.sh", "integrations/*/tests/*.*"):
        for path in sorted(glob.glob(os.path.join(REPO, *pattern.split("/")))):
            if path.endswith((".sh", ".py", ".sql", ".ts", ".tsx", ".authz")) and os.path.basename(path) not in (
                "unit_test.py",  # names the words it looks for
                "features.py",
            ):
                with open(path, encoding="utf-8", errors="replace") as fh:
                    out[os.path.relpath(path, REPO)] = fh.read()
    return out


def unused_flags(every: set[str]) -> list[str]:
    """The command's flags no suite uses: none of the files that say the flag also names its command."""
    texts = list(suite_texts().values())
    out = []
    for item in sorted(i for i in every if i.startswith("cli.") and " " in i):
        cmd, flag = item.removeprefix("cli.").split(" ")
        word = re.compile(rf"(?<![\w-]){re.escape(flag)}(?![\w-])")
        if not any(word.search(t) and re.search(rf"\b{re.escape(cmd)}\b", t) for t in texts):
            out.append(item)
    return out


def problems(features: list[Feature] = FEATURES) -> list[str]:
    """What is missing: an item of the surface in no feature (or in two), an item a feature names that the code
    doesn't have, a check whose file or words are gone, a tier-1 feature with no oracle, a doc that isn't there, a
    hand answer or a grammar case that isn't there or that no feature names. (The refusals are checked by
    `Features` in tests/unit_test.py, with `Guards`.)"""
    out: list[str] = []
    found = surface()
    every = set().union(*found.values())
    for name, items in found.items():
        for item in sorted(items):
            owners = owner(item, features)
            if not owners:
                out.append(f"{name}: {item} is in no feature")
            elif len(owners) > 1:
                out.append(f"{name}: {item} is in {' and '.join(owners)}")
    ids = [f.id for f in features]
    out += [f"{i}: two features with this id" for i in sorted({i for i in ids if ids.count(i) > 1})]
    # the usage and the dispatch name the same commands (help and --version are answered before the dispatch)
    import rowstile_cli

    listed = set(usage()) - {"help", "--version"}
    if listed != set(rowstile_cli.ARGUMENTS):
        out.append(
            f"the usage lists {sorted(listed - set(rowstile_cli.ARGUMENTS))} and the dispatch has "
            f"{sorted(set(rowstile_cli.ARGUMENTS) - listed)} besides"
        )
    out += [f"the command: {item}: no suite uses the flag" for item in unused_flags(every)]
    cases, hands = grammar_cases(), anchors()
    texts: dict[str, str] = {}
    for f in features:
        if f.tier not in (1, 2, 3):
            out.append(f"{f.id}: tier {f.tier}")
        for c in f.covers:
            if c.endswith(".*"):
                if not any(i.startswith(c[:-1]) for i in every):
                    out.append(f"{f.id}: covers {c}, which matches nothing the code has")
            elif c not in every:
                out.append(f"{f.id}: covers {c}, which the code doesn't have")
        if not f.checks:
            out.append(f"{f.id}: no fixed check")
        for c in f.checks + f.oracle:
            path = path_of(c.path)
            if path not in texts:
                try:
                    with open(path, encoding="utf-8") as fh:
                        texts[path] = fh.read()
                except OSError:
                    texts[path] = ""
                    out.append(f"{f.id}: {c.path} is gone")
                    continue
            if c.words not in texts[path]:
                out.append(f"{f.id}: {c.path} no longer says {c.words!r}")
        for c in f.oracle:
            if suite(c.path) not in ORACLES:
                out.append(f"{f.id}: {c.path} holds it to no other answer (ORACLES)")
        if f.tier == 1 and not f.oracle:
            out.append(f"{f.id}: tier 1, and no check holds it to another answer at random")
        if not os.path.exists(os.path.join(REPO, f.doc.page)):
            out.append(f"{f.id}: {f.doc.page} is gone")
        elif not any(p.startswith(f.doc.at) for p in places(f.doc.page)):
            out.append(f"{f.id}: {f.doc.page} has no heading, label or row {f.doc.at!r}")
        out += [f"{f.id}: no answer {a!r} on the language's reference" for a in f.hand if a not in hands]
        out += [f"{f.id}: no grammar case {g!r}" for g in f.grammar if g not in cases]
    named = [a for f in features for a in f.hand]
    out += [f"answer {a!r}: in no feature" for a in hands if a not in named]
    out += [f"answer {a!r}: in two features" for a in sorted({a for a in named if named.count(a) > 1})]
    out += [f"grammar case {g!r}: in no feature" for g in cases if not any(g in f.grammar for f in features)]
    return out


# --- the refusals: each error code, asked for by its words ----------------------------------------------


def guard_codes() -> dict[str, set[str]]:
    """The codes each RAISE EXCEPTION of authzlib carries (in its message, [AZ601], or its HINT, rowstile help
    AZ701), by where it is, `file.py:line` as `Guards` in tests/unit_test.py names it."""
    out: dict[str, set[str]] = {}
    folder = os.path.join(CORE, "authzlib")
    for name in sorted(os.listdir(folder)):
        if not name.endswith(".py"):
            continue
        src = read(f"core/authzlib/{name}")
        for m in re.finditer(r"RAISE EXCEPTION", src):
            end = re.compile(r";(?=\n|\"|')").search(src, m.start())  # the statement's end, in SQL or a string
            stmt = src[m.start() : end.end() if end else len(src)]
            found = {a or b for a, b in re.findall(r"\[(AZ\d{3})\]|rowstile help (AZ\d{3})", stmt)}
            out[f"{name}:{src.count(chr(10), 0, m.start()) + 1}"] = found
    return out


def unnamed_codes() -> list[str]:
    """The codes asked for neither by a RAISE's words (`Guards` holds those) nor by their page's example (a
    mistake in a policy or its tests, which `ErrorCodes` compiles to its code), that no suite names."""
    from authzlib import errors

    raised = set().union(*guard_codes().values())
    texts = suite_texts().values()
    return [
        f"err.{code}: no suite names it"
        for code, c in errors.CODES.items()
        if code not in raised
        and not (c.wrong and c.when in ("compile", "tests"))
        and not any(re.search(rf"\b{code}\b", t) for t in texts)
    ]


# --- the table -----------------------------------------------------------------------------------------


def suites_of(f: Feature) -> tuple[list[str], list[str]]:
    """(the suites of its fixed checks, the suites that hold it to another answer), in order."""
    fixed = list(dict.fromkeys(suite(c.path) for c in f.checks))
    oracle = list(dict.fromkeys(suite(c.path) for c in f.oracle))
    if f.hand:
        oracle.append("hand answers")
    return fixed, oracle


def matrix(features: list[Feature] = FEATURES) -> str:
    """Each feature against each suite: `o` a check against another answer, `x` a fixed check."""
    columns: list[str] = []
    for f in features:
        fixed, oracle = suites_of(f)
        columns += [s for s in oracle + fixed if s not in columns]
    columns.sort(key=lambda s: (s not in ORACLES and s != "hand answers", s))
    width = max(len(f.id) for f in features)
    head = [" " * (width + 3) + "".join(f"{i % 100:>3}" for i in range(1, len(columns) + 1))]
    rows = []
    for f in features:
        fixed, oracle = suites_of(f)
        cells = "".join(f"{'o' if s in oracle else 'x' if s in fixed else '.':>3}" for s in columns)
        rows.append(f"{f.id:<{width}} {f.tier} {cells}")
    legend = [f"{i:>3} {s}" + (f"  ({ORACLES[s]})" if s in ORACLES else "") for i, s in enumerate(columns, 1)]
    return "\n".join(head + rows + ["", "o: holds it to another answer; x: a fixed check", *legend])


BEGIN = "<!-- features: the table below is written by core/tests/features.py -->"
END = "<!-- features: end of the table -->"


def page_table(features: list[Feature] = FEATURES) -> str:
    """The table docs/how-it-is-checked.md shows, between BEGIN and END."""
    lines = [
        BEGIN,
        "",
        "| feature | tier | documented in | fixed checks | held to another answer by |",
        "|---|---|---|---|---|",
    ]
    for f in features:
        fixed, oracle = suites_of(f)
        page = f.doc.page.removeprefix("docs/")
        where = f"[{os.path.basename(page)[:-3]}]({page})"
        lines.append(
            f"| {f.title} | {f.tier} | {where} | {', '.join(f'`{s}`' for s in fixed)} | "
            f"{', '.join(s if s == 'hand answers' else f'`{s}`' for s in oracle)} |"
        )
    lines += ["", END]
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    if "--matrix" in argv:
        print(matrix())
        return 0
    if "--page" in argv:
        print(page_table())
        return 0
    found = problems()
    total = len(set().union(*surface().values()))
    print(f"{total} surface items in {len(FEATURES)} features; {len(found)} problem(s)")
    for p in found:
        print(f"  {p}")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
