# The policy language

A policy is one or more `.authz` files. This one uses most of the language; the list after it says what
each part does.

```authz
app role app_user                               -- the role the policies apply to
include "roles.authz"                           -- split big policies into files

type user = app.users where {active}            -- suspended users hold nothing
type team = app.teams
  member : user        = app.team_members(team_id -> user_id)
  member : team#member = app.teams(parent_id -> id)   -- declared twice: two sources;
                                                      -- sub-teams' members count too
type folder = app.folders where {not archived}
  org         : org    = org_id                 -- from a column you already have
  parent      : folder, project = (parent_type, parent_id)   -- inside a folder or a project
  linked_into : folder = app.folder_links(folder_id -> parent_id)   -- from a table you have
  owner       : user   = owner_id
  viewer      : user, team#member, user:*, anyone, link  shared by edit   -- authz.share()
  editor      : user, team#member  shared if {subject_type <> 'user' or ...}
  roles       : user, team#member  from org     -- custom roles, defined at runtime by the org

  can share = owner or org.admin or (parent.share and {inherit})
  can edit  = share or editor or roles or (parent.edit and {inherit and not locked})
  can view  = edit or viewer or roles or parent.view or linked_into.view   -- roles: one that includes view
  can break_glass = org.member                  -- may use authz.break_glass here

caveat business_hours = {authz.ctx('mode') = 'business'}   -- conditions attached to single shares
caveat from_ip        = {authz.ctx('ip') = arg('ip')}

scope read  = select, view                      -- what a token may do (API keys, JWTs)
scope files = app.files.select, app.files.update, file.view, file.edit

rules app.files view app.files_visible          -- also make a view with masked columns
  select                            : view
  insert                            : folder.edit and owner  -- the new row names you as its owner
  update                            : edit
  update folder_id after            : folder.edit            -- checked on the row after the change
  update id, owner_id, confidential : share                  -- only when these columns change
  mask body                         : edit                   -- NULL in the view unless you may edit
  delete                            : edit

invariants
  never folder: share and not org.member        -- checked by the tests and authz.check_invariants(); rowstile prove
                                                -- finds a folder owner outside the org: the policy doesn't forbid it

test
  user 3 can view file 11                       -- against the data already there
  user 3 cannot edit file 11

test "a folder's owner edits what is inside"    -- brings its own data, rolled back after
  given ann = {INSERT INTO app.users (id, name) VALUES (9001, 'Ann') RETURNING id}
  given top = {INSERT INTO app.folders (org_id, owner_id, name) VALUES (1, $ann, 'Top') RETURNING id}
  given f   = {INSERT INTO app.files (folder_id, name) VALUES ($top, 'plan.txt') RETURNING id}
  user $ann can edit file $f
  as user $ann allowed {UPDATE app.files SET name = 'plan-2.txt' WHERE id = $f}   -- as the app role
  as user 7 refused {DELETE FROM app.files WHERE id = $f}
  as user 7 sees 0 {SELECT FROM app.files WHERE id = $f}
```

- **Keys**: a type's key is `id bigint` unless the type line says otherwise: `(gid)`,
  `(id uuid)`, or several columns for a composite key: `type folder = app.folders (org_id, id)`.
  The type is the column's own: a 32-bit key, as Prisma's `Int` or a `serial` makes, is `(id int)`.
  `rowstile init` writes it, and applying says so when it is missing (AZ602).
  A relation points at such an object with its columns in square brackets:
  `parent : folder = [org_id, parent_id]`, `app.folder_teams([org_id, folder_id] -> user_id)`,
  `(parent_type, [org_id, parent_id])`. <!-- answer: keys-composite --> The user type's key is one column.
- **Rows that count**: `where {...}` on a type line says which rows do. A row that fails it holds nothing
  and passes nothing on: a suspended user, an archived folder and what is inside it, a disbanded team's
  members (also through the team that holds it). <!-- answer: rows-hold-nothing --> No rule allows anything on it either: the app role can't
  read, change or delete an archived folder, so it can't un-archive one. <!-- checked: tests/difftest.py "CrossGen"; tests/unit_test.py "test_a_rule_gives_no_row_the_type_leaves_out" --> <!-- answer: rows-no-rule -->
  An invariant isn't asked of it either: `never folder: not owner` holds on no archived folder. <!-- answer: rows-no-invariant -->
  Leave such rows to a job that runs
  as the owner, or say it in permissions instead (`can edit = ... and {not archived}`). <!-- answer: rows-in-permissions -->
- **Relations** link rows to users or groups: from a column, from another table
  (`app.team_members(team_id -> user_id)`, or with the columns named:
  `app.team_members(object: team_id, subject: user_id)`; optionally `where {...}`), from a polymorphic pair of columns `(type_col, id_col)`,
  in the type's table or in a link table (`app.backings(project_id -> (backer_type, backer_id))`),
  or from shares people make (`shared`). <!-- answer: relation-sources --> In `table(this_col -> subject_col)`, the left column names this row and the right one what it links to: on a team, `app.team_members(team_id -> user_id)` reads the rows whose `team_id` is this team's id, each linking it to a `user_id`; and `app.teams(parent_id -> id)`, a table that links to itself, reads the teams whose `parent_id` is this team's id, the teams inside it. Declare a relation again to add a source. <!-- answer: relation-again --> The type column of a
  polymorphic pair holds the policy's type names (`'folder'`, `'project'`): renaming a type changes what the
  rows link to, and a row naming a type the relation doesn't list links to nothing. <!-- answer: polymorphic-type-names -->
- **Shares**: a `shared` relation is given with `authz.share()` by whoever holds `share` on the object, so the
  type needs a `can share`, or the relation names another permission: `shared by edit`. The giver must also hold
  each permission the relation feeds on the object (`view`, for `can view = ... or viewer`): a share can't give what
  its giver doesn't hold. <!-- checked: tests/principals.sh "a viewer may share helper, but not grant assist, which they don't hold"; tests/hand/shares-by.authz "reader gives view, which ed lacks" --> <!-- answer: shares-by --> `shared if {...}` is a
  condition on the share being made (`object_id`, `subject_type`, `subject_id`, `subject_relation`), which
  `authz.share` checks: "only to active users". <!-- checked: tests/multi_scenario.sql "shared if: no sharing with inactive users" --> <!-- answer: shared-if -->
  Shares may expire or start later. <!-- answer: shares-expire --> A **caveat** is a
  condition that goes with one share and is checked at each request:
  `authz.share('folder', 3, 'viewer', 'user', 4, '', NULL, NULL, 'from_ip', '{"ip": "10.0.0.1"}')` gives
  `viewer` while `caveat from_ip` holds, `arg('ip')` being what the share was made with. <!-- answer: caveats -->
- **Subjects**: `user`, a group such as `team#member` (nested to any depth, loops are
  fine), `user:*` (any signed-in user), `anyone` (also signed out) and `link` (anyone
  holding a share link's token). <!-- answer: subjects -->
- **Principals**: services, API clients and agents can sign in as themselves:
  `type service = app.services principal`. Relations name them like users
  (`bot : service = bot_id`, `reader : user, service shared`), and `service:*` means any
  signed-in service. `signed_in` and `user:*` stay about users. <!-- answer: principals -->
- **Permissions** combine relations with `or`, `and`, `not` and parentheses, which say what goes first
  where `and` and `or` meet: `owner or (parent.edit and {inherit})` (without them it is refused). <!-- checked: tests/policy_errors.py "and next to or"; tests/policy_errors.py "and next to or, the other way" --> <!-- answer: permission-operators -->
  `rel.perm` follows a relation (`parent.edit`, `org.admin`, or to a user's own: `manager.oversee`,
  `author.has_blocked`), `signed_in` means any user signed in, `anyone` anyone at all, signed in
  or not (for rules on directories), and `nobody` nobody (`update id : nobody`), `{...}` is any SQL
  condition on the row (columns, subqueries, `now()`, `authz.uid()`, request context
  with `authz.ctx('mfa')`, which the app sets in the transaction: `SET LOCAL authz_ctx.mfa = 'yes'`). <!-- answer: follow-relation, signed-in-anyone-nobody, conditions-sql -->
  Being SQL, a condition names a column as SQL does: one with capital letters, as Prisma makes them, takes
  double quotes there (`{"parentId" is null}`), while a relation's source is the bare name
  (`parent : folder = parentId`).
- **Conditions name their row `this`**: a bare column is the row's, unless a table the condition reads has
  one by that name, as most have an `id`. In a subquery, write `this.`:
  `{exists (select 1 from app.memberships m where m.project_id = this.id)}` (with `id` alone, that would be
  the membership's id, and applying warns). `this` is the object in a permission, a rule or an invariant,
  the type's row in its `where`, the link table's row in a link table's `where`, and the share being made in
  `shared if`. A caveat has no row. <!-- answer: conditions-this -->
  `this.` names the row whatever a subquery of the condition calls its tables, even by the name rowstile gives the row where it is checked. <!-- checked: tests/hand/conditions-this-alias.authz "this. names the row, whatever the condition's subquery calls its table" -->
  Names that start with `authz__` are rowstile's own: a condition that writes one is refused (AZ113). <!-- checked: tests/policy_errors.py "a name that starts with authz__ in a condition" -->
- **Conditions read with the policy's rights**, wherever they are checked (a rule, a permission, `authz.can`,
  another type's rule through `rel.perm`), as relations do: a subquery sees every row of the tables it reads,
  not only those the signed-in user may. <!-- checked: tests/devx.sh "a rule condition that reads a governed table runs with the policy's rights, as a function"; tests/apply.sh "a condition in a permission sees every membership in its table's rules too" --> <!-- answer: conditions-rights -->
  A condition that is NULL holds nothing: `{not archived}` is false
  where `archived` is NULL, `not {archived}` is true there. <!-- answer: conditions-null --> Where a relation says the same, write the
  relation: `insert : folder.edit and owner` rather than `{owner_id = authz.uid()}`, which `rowstile prove`
  and the review read as a fact about the row; your own row is a relation too (`self : user = id`, then
  `can edit = self`). <!-- answer: own-row -->
- **Inheritance**: `or rel.perm` back to the same type (or across types, like projects
  and folders inside each other) inherits as deep as it goes, through any mix of
  sources; `and {condition}` says where it stops. <!-- answer: inheritance -->
- **Denies**: `can view = (viewer or parent.view) and not hidden` takes `view` away on a
  hidden folder and everything below it, even from people who hold it higher up. The deny
  must inherit the same way (`can hidden = blocked or parent.hidden`), so it covers
  everything below; a deny on one object that only cuts inheritance there is refused, with
  a message saying so. <!-- checked: tests/policy_errors.py "a deny that doesn't cover what is below"; tests/unit_test.py "test_a_deny_inside_inheritance_covers_everything_below" --> <!-- answer: deny-below -->
  A deny can't inherit through a relation that also points at another type (`parent : folder, project`:
  give the projects a relation of their own), nor through another type's permission that comes back to it
  (a `project.view` that inherits from folders): both are refused (AZ306). <!-- checked: tests/policy_errors.py "a deny on a permission that inherits through a relation to another type too"; tests/policy_errors.py "a deny on a permission that inherits through another type" -->
  Another type's permission beside the deny is fine: in `(viewer or parent.view or project.view) and not hidden`,
  `project.view` gives `view` like `viewer` does, and `hidden` takes it away. <!-- answer: deny-other-types -->
  A condition joined the same way holds at every level:
  `(viewer or parent.view) and {not archived}` stops at an archived folder. <!-- answer: condition-every-level -->
- **Custom roles**: `roles : user, team#member` says who may hold roles people create at runtime
  (`authz.create_role('org', 1, 'folder', 'reviewer', ARRAY['view'])`) and share like relations. A
  permission writes `roles` where a role that includes it gives it, and a role may include the
  permissions that write it: `can view = (viewer or roles or parent.view) and not hidden` gives `view`
  to holders of a role that includes it, and the deny holds for them too, as it is written. <!-- answer: roles-include --> Creating a
  role needs `manage_roles` on its owner (`can manage_roles = admin` on the org type), and gives the
  role's id: the role is shared as the relation `role:<id>` (`authz.share('folder', 3, 'role:12',
  'user', 7)`), by someone who holds `share` on the object and everything the role grants. <!-- checked: tests/multi_scenario.sql "cannot give the archivist role, for he does not hold archive"; tests/multi_scenario.sql "alice is no Acme admin: she cannot define roles for Acme" --> <!-- answer: roles-create -->
  `from org`
  says whose roles count on an object: only those of the org its `org` relation links it to now (a
  column or a table, to one type). <!-- checked: tests/unit_test.py "test_roles_from_an_org_count_only_on_its_objects"; tests/multi_scenario.sql "until folder 1 moves to Globex" --> <!-- answer: roles-from -->
  `authz.share` refuses another owner's role (with an error, AZ706: offering it is the app's mistake), an assignment of one
  grants nothing, and a folder moved to another org stops honouring the first org's roles. <!-- checked: tests/multi_scenario.sql "alice cannot give Globex"; tests/multi_scenario.sql "and one written into authz.shares gives dave nothing while folder 1 is Acme"; tests/difftest.py "MultiGen" --> <!-- answer: roles-refused -->
  Without
  `from`, any role for the type counts wherever it is given, so an app must offer only the owner's
  roles. <!-- checked: tests/unit_test.py "test_roles_without_from_count_wherever_they_are_given" --> <!-- answer: roles-without-from -->
- **Rules** say what each command needs, per table, with column-level variants and
  masks. <!-- answer: rules-commands --> The plain `update` rule must hold on the row before and after the change (as
  Postgres checks both), unless `update after : ...` says what must hold after it. <!-- answer: update-before-after --> A column rule checks the
  row before the change (`update owner_id : share`, or
  `update owner_id before : share`) or after it (`update folder_id after : folder.edit`: where
  a row moves to). `authz.lint()` warns about a move in a tree (a column that links a row to another of its own
  type) that nothing checks the destination of, and about any column that gives a relation and that whoever
  may update the row may change, with no rule on it. <!-- checked: tests/governance.sh "lint finds a move nothing checks the destination of"; tests/governance.sh "lint finds a column that gives a relation and that an editor may change" -->
  A rule on the row before the change (`update org_id : share`) says who may move a row to another
  organisation, not to which: `update org_id after : org.member` or `update org_id : nobody` says that. <!-- answer: column-rules -->
  An update two column rules both refuse is refused in the words of a rule on the row before the change first
  (`update id, owner_id` before `update folder_id after`), then of the one whose columns come first in name
  order, whatever order the policy writes them in. <!-- checked: tests/adversarial.sh "and both at once: the rule on the row before the change says why"; tests/invariance.py "the same answers"; tests/unit_test.py "test_triggers_are_named_after_what_they_guard" -->
  **Invariants** state what must never be true, for everyone who can sign in (each user, each
  service or other principal) and for nobody. <!-- checked: tests/principals.sh "invariants are asked as each service too, named as the audit trail names it"; tests/principals.sh "and as nobody: the row with no user" --> <!-- answer: invariants -->
- **Tests**: the unnamed `test` section checks the data already in the database, with lines
  `user|<principal type> X can|cannot PERM TYPE ID` (or `anyone ...`). A named test,
  `test "..."`, brings its own: `given name = {SQL ... RETURNING id}` rows (as whoever applies
  policies; `$name` is what it returned, a key of several columns as its row text), then the same
  checks, and `as user X allowed|refused
  {SQL}` or `as user X sees N {SELECT ...}`, which run as the app role signed in as X. A write is
  refused if a rule or a missing privilege stops it, or if it changes no row (the rows it meant are
  hidden from X). <!-- checked: tests/devx.sh "a write after WITH or a comment that changes no row is refused, and one the app role has no privilege for"; tests/devx.sh "an 'allowed' that is refused shows the refusal and why" --> <!-- answer: tests-refused -->
  Any other error, a unique key say, fails the check whichever was expected. Each named test runs in a transaction that is rolled back.
  What a line sets for its transaction (`set_config(..., true)`, such as a share link's token in `authz_ctx.links`) holds for the test's later lines, unless the line ends in an error.
  After who a line is about, `with scope read` (or several: `with scope read, files`) checks it as a key or
  a token limited to those scopes would be: `user 3 with scope read cannot edit file 11`,
  `as user 3 with scope read refused {UPDATE ...}`. <!-- answer: tests-scope --> A scope the policy doesn't have is a mistake (AZ503).
  Named tests may live in their own files (only `test "..."` blocks); `rowstile test` and
  `rowstile dev` run them, never `apply`. <!-- checked: tests/devx.sh "test runs named test files, exit 0"; tests/unit_test.py "test_what_a_test_file_is_refused_for"; tests/apply.sh "apply runs no test" -->
  A failing check explains itself. <!-- checked: tests/devx.sh "a failing check names its file and line, and explains itself" -->

## Permissions the runtime asks for

Permission names are yours to choose, but five are asked for by name. The compiler refuses one declared
where nothing would ask for it (AZ307). <!-- checked: tests/policy_errors.py "impersonate on a type other than user"; tests/policy_errors.py "manage_keys on a type that doesn't sign in"; tests/policy_errors.py "break_glass with nothing to give"; tests/policy_errors.py "manage_roles with no roles to make" -->

| permission | on | lets its holders |
|---|---|---|
| `share` | a type with `shared` relations | share them (unless `shared by` names another), see who has access (`authz.who`, `authz.list_shares`), decide access requests <!-- checked: tests/scenario.sql "carol (viewer) cannot list who has access"; tests/governance.sh "erin (share, but not manage_editors) cannot unshare"; tests/governance.sh "erin (who may share Secrets) sees it to decide" --> <!-- answer: runtime-share --> |
| `break_glass` | a type with a relation shared with users | give themselves that relation for a while with `authz.break_glass`: audited, announced; a user, not a service (AZ715) <!-- checked: tests/principals.sh "authz.break_glass is for users: a service is told so"; tests/governance.sh "carol breaks the glass, and the alert goes out"; tests/governance.sh "the trail has it, with the reason"; tests/governance.sh "frank (Globex) cannot break the glass on an Acme folder" --> <!-- answer: runtime-break-glass --> |
| `impersonate` | the user type | view the app as that user with `authz.view_as`: read-only, audited; a user, not a service (AZ715) <!-- checked: tests/principals.sh "authz.view_as is for users: a service is told so"; tests/identity.sh "and cannot change anything"; tests/identity.sh "the audit trail has the reason"; tests/identity.sh "carol cannot view as erin" --> |
| `manage_keys` | a type that signs in | make and revoke its API keys (`authz.create_api_key(..., 'service', '7')`) <!-- checked: tests/principals.sh "its owner makes service 7 a key"; tests/principals.sh "someone else may not"; tests/principals.sh "the owner revoked it" --> |
| `manage_roles` | the type that owns custom roles (`roles : user from org`) | create, change and delete those roles; a user, not a service (AZ715) <!-- checked: tests/principals.sh "authz.create_role is for users: a service is told so"; tests/multi_scenario.sql "alice is no Acme admin: she cannot define roles for Acme"; tests/multi_scenario.sql "erin adds edit to reviewer: dave can now edit"; tests/multi_scenario.sql "erin deletes the role: its assignments go with it" --> <!-- answer: runtime-manage-roles --> |

## Masked columns

`rules app.files view app.files_visible` plus `mask body : edit` creates a view with
the rows `select` allows, where `body` is NULL unless the rule holds. <!-- checked: tests/multi_scenario.sql "sees doc 01 in the masked view, but not its text"; tests/multi_scenario.sql "the view has exactly the rows she may select" --> <!-- answer: mask-view -->
The app role
loses SELECT on `body` in the table itself (the other columns stay), so the view is
the only way to read it. <!-- checked: tests/masks.sh "the app role cannot read the masked column from the table"; tests/multi_scenario.sql "the text cannot be read from the table directly" --> <!-- answer: mask-table -->
Applying refuses to go on if the column would still be
readable through PUBLIC or another role. <!-- checked: tests/masks.sh "a mask PUBLIC could read around is refused"; tests/masks.sh "and applying refuses it, as for PUBLIC" -->
A later `GRANT` that makes it readable again
isn't refused (that would need an event trigger, and so a superuser): `authz.lint()`
reports it, and applying again takes it back. <!-- checked: tests/masks.sh "and applying again takes it back"; tests/apply.sh "and later grants aren't refused any more" -->
Removing the mask gives the table-wide
SELECT back. <!-- checked: tests/masks.sh "gives back table-wide SELECT and drops the view"; tests/apply.sh "remove gives back the table-wide SELECT the mask replaced" -->

The view is the app's to build on: a view of your own over it, or a function that reads it. Applying and
migrations replace it in place, so those go on working when the policy changes. <!-- checked: tests/apply.sh "replaced in place, the app's view stays"; tests/migrate_test.py "a mask that changes, under a view of the app's" -->
Two things can't be done in
place, and are refused with what is built on the view named (AZ617): taking the masked view out of the policy,
and a change of the table's columns that the view can't follow (a column renamed; a new column is
fine). <!-- checked: tests/apply.sh "a policy without the masked view, while the app's view is on it: refused, naming it, nothing changed"; tests/apply.sh "a column renamed under the app's view: refused, naming what is built on the masked view"; tests/apply.sh "and when the table gets a column (the view gets it too)" -->
Drop what you built, apply, and make it again.
