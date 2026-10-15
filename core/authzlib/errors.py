"""Every mistake rowstile reports has a stable code, like AZ201, at the end of its message: 'line 4: folder.owner:
unknown type 'person' [AZ201]'. This file is each code's page: what it means, a policy that makes the mistake and
the same policy fixed. `rowstile help AZ201` prints it; docs/errors/ is written from it (tests/unit_test.py
--update), and the unit tests compile every example: the mistake must give its code, the fix must compile.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .parse import PolicyError

# examples are compiled after these lines, unless they declare the user type themselves
PRELUDE = "app role app_user\ntype user = app.users\n"
CODE = re.compile(r" \[(AZ\d{3})\]$")


@dataclass(frozen=True)
class Code:
    title: str
    text: str  # what it means and what to do
    wrong: str = ""  # a policy that makes the mistake (after PRELUDE)
    right: str = ""  # the same policy, fixed
    when: str = "compile"  # compile | tests (found when the tests are compiled) | apply | deploy | command | runtime
    files: tuple[tuple[str, str], ...] = ()  # included files the examples need: ((name, text), ...)


GROUPS = [
    ("AZ1", "Reading the policy"),
    ("AZ2", "Types and relations"),
    ("AZ3", "Permissions and inheritance"),
    ("AZ4", "Rules, masks and scopes"),
    ("AZ5", "Tests"),
    ("AZ6", "Applying and deploying"),
    ("AZ7", "What apps see"),
]

CODES = {
    "AZ101": Code(
        "A line the language doesn't read",
        "A policy is made of blocks that start at the left margin (`app role`, `type`, `rules`, `scope`, `caveat`, "
        "`invariants`, `test`, `include`) and indented lines that belong to the block above them. This line is "
        "neither: a word no block starts with (often a typo), or an indented line with no block above it. The "
        "app role's line was written `role` before; it is `app role` now.",
        "typ folder = app.folders\n  owner : user = owner_id\n  can view = owner\n",
        "type folder = app.folders\n  owner : user = owner_id\n  can view = owner\n",
    ),
    "AZ102": Code(
        "An expression that doesn't parse",
        "Permissions, rules and invariants are expressions: names joined by `or`, `and` and `not`, in parentheses "
        "where needed, `relation.permission` to follow a relation, and SQL conditions in `{ }` on the row's own "
        "columns. The message says what was unexpected, or what is missing: a `)`, a closing `}`, or the rest of "
        "the expression. Where `and` and `or` meet, parentheses say which goes first: `a or b and c` reads two "
        "ways, so it is refused with the parentheses to add, `a or (b and c)`.",
        "type folder = app.folders\n  owner : user = owner_id\n  can view = owner or\n",
        "type folder = app.folders\n  owner : user = owner_id\n  can view = owner or {is_public}\n",
    ),
    "AZ103": Code(
        "A relation written wrongly",
        "A relation is `name : subjects = source`, or `name : subjects shared [by permission] [if {condition}]`.\n\n"
        "Subjects are a type (`user`), a group's relation (`team#member`), any signed-in user (`user:*`), `anyone` "
        "or `link`, separated by commas.\n\n"
        "The source is a column of the type's table (`owner_id`), two columns for a subject of several types "
        "(`(subject_type, subject_id)`), or a link table: `app.folder_editors(folder_id -> user_id)`, or "
        "`app.grants(object: folder_id, subject: (kind, who))`.\n\n"
        "Custom roles are `roles : subjects [from relation]`, and `roles` in each permission a role may give "
        "(`can edit = editor or roles`). They were once written `roles : subjects grant perm1, perm2`.",
        "type folder = app.folders\n  owner user = owner_id\n  can view = owner\n",
        "type folder = app.folders\n  owner : user = owner_id\n  can view = owner\n",
    ),
    "AZ104": Code(
        "A permission written wrongly",
        "A permission is `can name = expression`: `can view = owner or editor or parent.view`.",
        "type folder = app.folders\n  owner : user = owner_id\n  can view owner\n",
        "type folder = app.folders\n  owner : user = owner_id\n  can view = owner\n",
    ),
    "AZ105": Code(
        "A rule written wrongly",
        "Under `rules schema.table`, each line is a command and an expression: `select : view`, "
        "`insert : edit`, `update : edit`, `delete : owner`. Only update rules name columns or say when they are "
        "checked: `update owner_id : share` (who may change that column), `update after : edit` (checked on the "
        "row after the change; `check` was its old name). A plain `update` rule is checked on the row before and "
        "after the change, so `update before :` is refused. A column named `before` or `after` says when it is "
        "checked: `update after after : edit`. Masks are `mask col1, col2 : expression`.",
        "type folder = app.folders\n  owner : user = owner_id\n  can edit = owner\nrules app.folders\n"
        "  select owner_id : edit\n",
        "type folder = app.folders\n  owner : user = owner_id\n  can edit = owner\nrules app.folders\n"
        "  select : edit\n  update : edit\n  update owner_id : edit\n",
    ),
    "AZ106": Code(
        "A test or an invariant written wrongly",
        "The `test` section holds checks on the data there: `user 3 can view file 11`, `user 3 cannot edit "
        'file 11`. A named test, `test "name"`, brings its own data first, `given ann = {INSERT ... RETURNING '
        "id}`, then checks: `user $ann can view folder $top`, `as user $ann refused {UPDATE ...}`, `as user $ann "
        "sees 2 {SELECT ...}`. A test needs at least one line, and a test file holds only named tests.\n\n"
        "Invariants are `never type: expression`, under `invariants`.",
        "type folder = app.folders\n  owner : user = owner_id\n  can view = owner\n"
        'test "owners see their folders"\n  user 1 may view folder 1\n',
        "type folder = app.folders\n  owner : user = owner_id\n  can view = owner\n"
        'test "owners see their folders"\n'
        "  given ann = {INSERT INTO app.users (name) VALUES ('Ann') RETURNING id}\n"
        "  given top = {INSERT INTO app.folders (owner_id, name) VALUES ($ann, 'Top') RETURNING id}\n"
        "  user $ann can view folder $top\n",
        when="tests",
    ),
    "AZ107": Code(
        "A name the policy can't use",
        "Names can't contain `__`: generated names use it (`view__base`), and a policy can't refer to those. "
        "`signed_in`, `anyone`, `nobody`, `or`, `and`, `not`, `if`, `where` and `grant` are words of the language "
        "(so is `everyone`, which `anyone` replaced), and a "
        "permission can't be called like a command "
        "(`select`, `insert`, `update`, `delete`). Choose another name.",
        "type folder = app.folders\n  owner : user = owner_id\n  can select = owner\n",
        "type folder = app.folders\n  owner : user = owner_id\n  can read = owner\n",
    ),
    "AZ108": Code(
        "An included file that can't be read",
        '`include "roles.authz"` names a file relative to the file that includes it. The command reads it from '
        "disk; code that compiles a policy passes it in the `files` map (name -> text). A file can be included "
        "only once, and never by itself. It is in the policy's folder or below it: named with `/`, without `..` "
        "out of the folder, a drive or a `/` at the start (the review runs on a pull request's files, and must "
        "not read others).",
        'include "teams.authz"\ntype folder = app.folders\n  owner : user = owner_id\n  can view = owner\n',
        'include "teams.authz"\ntype folder = app.folders\n  owner : user = owner_id\n  can view = owner\n',
        files=(
            (
                "teams.authz",
                "type team = app.teams\n  member : user = app.team_members(team_id -> user_id)\n  can see = member\n",
            ),
        ),
    ),
    "AZ109": Code(
        "Declared twice",
        "Each type, relation, permission, caveat, named test, view and custom roles line is declared once, and a "
        "table has one rule of each kind (one `select`, one `update`, ...) and masks each column once. A "
        "relation and a permission can't share a name. Join the two into one: `can view = owner or editor`.",
        "type folder = app.folders\n  owner  : user = owner_id\n  editor : user = editor_id\n"
        "  can view = owner\n  can view = editor\n",
        "type folder = app.folders\n  owner  : user = owner_id\n  editor : user = editor_id\n"
        "  can view = owner or editor\n",
    ),
    "AZ110": Code(
        "A dollar-quote tag in a condition",
        "The SQL in `{...}` goes into generated functions, whose bodies are quoted with tags such as `$f$`. The "
        "same tag in a condition would end the body there. Write the text another way: `'$' || 'f$'`. A bare "
        "`$$` is fine; a tag with a name between the dollars (`$changed$`, as in `$$changed$$`) is not: quote "
        "such text with apostrophes.",
        "type folder = app.folders\n  owner : user = owner_id\n  can view = owner and {name <> '$f$'}\n",
        "type folder = app.folders\n  owner : user = owner_id\n  can view = owner and {name <> '$' || 'f$'}\n",
    ),
    "AZ111": Code(
        "No app role",
        "A policy names the app role, the Postgres role your app connects as, on a line of its own: "
        "`app role app_user`. The rules apply to it, it may call `authz.act_as` to say who is signing in, and it is "
        "the role tests run their statements as. It is one role: not PUBLIC, which would let every role in the "
        "database sign in as anyone.",
        "type user = app.users\ntype folder = app.folders\n  owner : user = owner_id\n  can view = owner\n",
        "app role app_user\ntype user = app.users\ntype folder = app.folders\n  owner : user = owner_id\n"
        "  can view = owner\n",
    ),
    "AZ112": Code(
        "`this` where there is no row",
        "In a condition, `this.column` is the row the condition is about: the object, in a permission, a rule or "
        "an invariant; the type's row in its `where`; the link table's row in a link table's `where`; the share "
        "being made in `shared if`. Inside a subquery a bare column name can be another table's, so the row's "
        "columns are best written `this.id`. A caveat has no row: it is checked with each request, on any share it "
        "goes with, and reads the request (`authz.ctx('ip')`) and what the share was made with (`arg('ip')`). "
        "And `this` is no other name: call a table in a condition something else.",
        "type folder = app.folders\n  owner : user = owner_id\n  viewer : user  shared\n  can share = owner\n"
        "  can view = owner or viewer\ncaveat own_ip = {this.ip = authz.ctx('ip')}\n",
        "type folder = app.folders\n  owner : user = owner_id\n  viewer : user  shared\n  can share = owner\n"
        "  can view = owner or viewer\ncaveat own_ip = {arg('ip') = authz.ctx('ip')}\n",
    ),
    "AZ113": Code(
        "A name rowstile keeps for itself",
        "Names that start with `authz__` are rowstile's own. Where a condition is placed, its row has an alias, and "
        "`this.column` is written with it. When a query inside the condition could call one of its tables by that "
        "alias (`select 1 from app.users u` where the row is `u` too), the row is called `authz__this` there "
        "instead, so that `this.` still names the row. A condition that wrote such a name could take it back: call "
        "the table, the column or the function something else.",
        "type folder = app.folders\n  owner : user = owner_id\n"
        "  can view = owner and {not exists (select 1 from app.folder_links authz__l where authz__l.folder_id = this.id)}\n",
        "type folder = app.folders\n  owner : user = owner_id\n"
        "  can view = owner and {not exists (select 1 from app.folder_links l where l.folder_id = this.id)}\n",
    ),
    "AZ201": Code(
        "Unknown type",
        "A relation's subjects, an invariant, a scope and a test name types the policy declares "
        "(`type team = app.teams`). Declare it, or fix the name.",
        "type folder = app.folders\n  owner : person = owner_id\n  can view = owner\n",
        "type folder = app.folders\n  owner : user = owner_id\n  can view = owner\n",
    ),
    "AZ202": Code(
        "No user type",
        "Every policy declares `type user = schema.table`: the people who sign in, whose ids "
        "`authz.act_as('user', id)` takes.",
        "app role app_user\ntype folder = app.folders\n  can view = signed_in\n",
        "app role app_user\ntype user = app.users\ntype folder = app.folders\n  can view = signed_in\n",
    ),
    "AZ203": Code(
        "A relation or permission that isn't there",
        "An expression, a `type#relation` subject, `shared by`, custom roles, a scope or a test names a relation "
        "or permission the type doesn't have. The message lists what it has; declare the missing one, or fix "
        "the name.",
        "type folder = app.folders\n  owner : user = owner_id\n  can view = owner or viewer\n",
        "type folder = app.folders\n  owner  : user = owner_id\n"
        "  viewer : user = app.folder_viewers(folder_id -> user_id)\n  can view = owner or viewer\n",
    ),
    "AZ204": Code(
        "anyone, link and type:*",
        "`anyone` (signed in or not), `link` (whoever has the link) and `user:*` (anyone signed in) stand alone, "
        "without `#relation`, and are given only by sharing: they go in a `shared` relation. `team:*` needs "
        "team to sign in (`type team = ... principal`). No type may be called `anyone` or `link`. For "
        "something every row says for itself, use a condition: `can view = owner or {is_public}`.",
        "type folder = app.folders\n  owner  : user = owner_id\n  public : anyone = is_public\n"
        "  can view = owner or public\n",
        "type folder = app.folders\n  owner  : user = owner_id\n  viewer : user, anyone  shared\n"
        "  can share = owner\n  can view  = owner or viewer or {is_public}\n",
    ),
    "AZ205": Code(
        "A source that can't hold these subjects",
        "A column or a link table's subject column points at one kind of subject: its type's key. For several "
        "kinds, share the relation (`shared`) or use two columns, `(subject_type, subject_id)`, which link to "
        "objects of the types named, not to a group's members.",
        "type team = app.teams\n  member : user = app.team_members(team_id -> user_id)\n"
        "type folder = app.folders\n  owner  : user = owner_id\n  editor : user, team#member = editor_id\n"
        "  can edit = owner or editor\n",
        "type team = app.teams\n  member : user = app.team_members(team_id -> user_id)\n"
        "type folder = app.folders\n  owner  : user = owner_id\n  editor : user, team#member  shared\n"
        "  can share = owner\n  can edit  = owner or editor\n",
    ),
    "AZ206": Code(
        "A key written wrongly, or of the wrong shape",
        "A type's key is its table's primary key: `id bigint` unless written after the table, "
        "`type folder = app.folders (folder_no)` or `(id uuid)`. A composite key names each column, "
        "`(org_id, slug text)`, of integers, text or uuid. A type that signs in (the user type, principals) has "
        "a key of one column. A relation to a type with a composite key gives its columns in brackets: "
        "`page : doc = [org_id, doc_slug]`.",
        "type folder = app.folders (id bigint uuid)\n  owner : user = owner_id\n  can view = owner\n",
        "type folder = app.folders (id uuid)\n  owner : user = owner_id\n  can view = owner\n",
    ),
    "AZ207": Code(
        "Sharing needs a permission",
        "A `shared` relation is given with `authz.share()` by someone who holds the type's `share` permission, "
        "or the permission it names: `editor : user shared by manage`. Declare that permission.",
        "type folder = app.folders\n  owner  : user = owner_id\n  viewer : user  shared\n"
        "  can view = owner or viewer\n",
        "type folder = app.folders\n  owner  : user = owner_id\n  viewer : user  shared\n"
        "  can share = owner\n  can view  = owner or viewer\n",
    ),
    "AZ208": Code(
        "A relation nothing uses",
        "No permission, rule, test or invariant uses this relation. It is often a typo in a second source of the "
        "same relation, or a permission not written yet. Use it, or remove it.",
        "type folder = app.folders\n  owner  : user = owner_id\n  editor : user = editor_id\n  can view = owner\n",
        "type folder = app.folders\n  owner  : user = owner_id\n  editor : user = editor_id\n"
        "  can view = owner or editor\n",
    ),
    "AZ209": Code(
        "A group made only of itself",
        "A group's members may include other groups' members (`team#member`), but something must bring in "
        "users, or the group is always empty.",
        "type team = app.teams\n  owner  : user = owner_id\n  member : team#member  shared by manage\n"
        "  can manage = owner or member\n",
        "type team = app.teams\n  owner  : user = owner_id\n  member : user, team#member  shared by manage\n"
        "  can manage = owner or member\n",
    ),
    "AZ210": Code(
        "Custom roles written where they can't be",
        "`roles : user, team#member from org` says who may hold the type's custom roles. A permission writes "
        "`roles` where a role that includes it gives it: `can edit = editor or roles or (parent.edit and "
        "{inherit})`, and the roles people create may include the permissions that write it. So `roles` goes in "
        "a permission of a type with a roles line: not under `not` (a role gives, it doesn't take away), not "
        "followed by a dot (it isn't a relation to objects), and not in a rule or an invariant, which don't say "
        "what a role gives (name the permission there). A roles line no permission uses is refused too.",
        "type org = app.orgs\n  admin : user = app.org_members(org_id -> user_id)\n  can manage_roles = admin\n"
        "type folder = app.folders\n  editor : user = editor_id\n  roles  : user\n"
        "  can edit = editor and not roles\n",
        "type org = app.orgs\n  admin : user = app.org_members(org_id -> user_id)\n  can manage_roles = admin\n"
        "type folder = app.folders\n  editor : user = editor_id\n  roles  : user\n"
        "  can edit = editor or roles\n",
    ),
    "AZ211": Code(
        "Custom roles from a relation that can't name their owner",
        "`roles : user from org` says whose roles count on an object: only those of the object its `org` "
        "relation links it to, now (an assignment of another owner's role grants nothing, and `authz.share` "
        "refuses it). That relation must be the type's own, kept in a column or a table (not shared), and link "
        "to objects of one type: the type whose `manage_roles` people create the roles.",
        "type org = app.orgs\n  admin : user = app.org_members(org_id -> user_id)\n  can manage_roles = admin\n"
        "type folder = app.folders\n  owner : user = owner_id\n  can view = owner or roles\n"
        "  roles : user from owner_org\n",
        "type org = app.orgs\n  admin : user = app.org_members(org_id -> user_id)\n  can manage_roles = admin\n"
        "type folder = app.folders\n  org   : org = org_id\n  owner : user = owner_id\n  can view = owner or roles\n"
        "  roles : user from org\n",
    ),
    "AZ301": Code(
        "Following a relation that can't be followed",
        "`relation.name` follows a relation to the objects it links to and asks for their relation or "
        "permission: `parent.view`, `org.member`. Only relations to objects can be followed: not a permission, "
        "and not a relation to groups (`team#member`), `anyone` or `link`. And a relation to objects is not a "
        "set of users: follow it (`parent.view`), don't use it alone.",
        "type folder = app.folders\n  owner  : user = owner_id\n  parent : folder = parent_id\n"
        "  can view = owner or parent\n",
        "type folder = app.folders\n  owner  : user = owner_id\n  parent : folder = parent_id\n"
        "  can view = owner or parent.view\n",
    ),
    "AZ302": Code(
        "A permission that depends on itself",
        "A permission may use itself only through a relation between objects of one type, `parent.view`: that "
        "is inheritance, stored as a tree. Any other loop (`a = b`, `b = a`, or two permissions inheriting "
        "through each other) has no answer.",
        "type folder = app.folders\n  owner : user = owner_id\n  can edit = owner or view\n  can view = edit\n",
        "type folder = app.folders\n  owner : user = owner_id\n  can edit = owner\n  can view = edit\n",
    ),
    "AZ303": Code(
        "Inheritance with no starting point",
        "`can view = parent.view` only passes on what a folder above has, and nothing gives it to the one at "
        "the top. Say what grants it directly.",
        "type folder = app.folders\n  owner  : user = owner_id\n  parent : folder = parent_id\n"
        "  can edit = owner\n  can view = parent.view\n",
        "type folder = app.folders\n  owner  : user = owner_id\n  parent : folder = parent_id\n"
        "  can edit = owner\n  can view = edit or parent.view\n",
    ),
    "AZ304": Code(
        "Inheritance limited by something other than a condition",
        "Inheritance is stored as a tree, so what may stop it is a condition on the object's own columns: "
        "`(parent.view and {inherit})`. A relation or permission can't narrow it; write it beside: "
        "`can view = (owner or parent.view) ...` with a deny (`and not blocked`) if someone must lose it.",
        "type folder = app.folders\n  owner  : user = owner_id\n  editor : user = editor_id\n"
        "  parent : folder = parent_id\n  can view = owner or (parent.view and editor)\n",
        "type folder = app.folders\n  owner  : user = owner_id\n  editor : user = editor_id\n"
        "  parent : folder = parent_id\n  can view = owner or editor or (parent.view and {inherit})\n",
    ),
    "AZ305": Code(
        "A condition inheritance can't store",
        "Conditions that limit inheritance, and a link table's `where`, are worked out once and stored in the "
        "tree, so they give the same answer for everyone at any time: not `now()`, not `authz.uid()`, and a "
        "link table's `where` reads only that table's columns. Use a column the app sets (`archived`), or put "
        "the time or the user in a permission beside the inheritance.",
        "type folder = app.folders\n  owner  : user = owner_id\n  parent : folder = parent_id\n"
        "  can view = owner or (parent.view and {created_at > now() - interval '1 day'})\n",
        "type folder = app.folders\n  owner  : user = owner_id\n  parent : folder = parent_id\n"
        "  can view = owner or (parent.view and {not archived})\n",
    ),
    "AZ306": Code(
        "A deny that doesn't fit its inheritance",
        "`can view = (reader or parent.view) and not blocked`: the deny must reach everything below, so "
        "`blocked` is a permission of the same type that inherits through the same relation "
        "(`can blocked = blocker or parent.blocked`), and the inheritance is joined with `and` only by the deny. "
        "`blocked` has no deny of its own: that could cut it below a blocked object. And `view` inherits within "
        "its own type: not through another type's permission (`project.view`, where projects and folders are "
        "inside each other).",
        "type folder = app.folders\n  owner   : user = owner_id\n  parent  : folder = parent_id\n"
        "  blocker : user = app.folder_blocks(folder_id -> user_id)\n  can blocked = blocker\n"
        "  can view = (owner or parent.view) and not blocked\n",
        "type folder = app.folders\n  owner   : user = owner_id\n  parent  : folder = parent_id\n"
        "  blocker : user = app.folder_blocks(folder_id -> user_id)\n  can blocked = blocker or parent.blocked\n"
        "  can view = (owner or parent.view) and not blocked\n",
    ),
    "AZ307": Code(
        "A permission the runtime asks for, where it doesn't",
        "Some permissions are asked for by name: `share` (who shares a type's shared relations, sees who has "
        "access and decides requests), `break_glass` (who may use `authz.break_glass` on an object), "
        "`impersonate` (on the user type: who may view the app as that user, `authz.view_as`), `manage_keys` "
        "(on a type that signs in: who makes and revokes its API keys) and `manage_roles` (on the type that owns "
        "custom roles: who creates them). Declared where nothing asks for them, they would never be used: "
        "`impersonate` on another type, `manage_keys` on a type that doesn't sign in, `break_glass` on a type with "
        "no relation shared with a user (which it would give), `manage_roles` on a type no roles line counts the "
        "roles of. And custom roles need someone who may create them: `roles : user from org` needs "
        "`can manage_roles` on the org's type.",
        "type org = app.orgs\n  admin : user = app.org_members(org_id -> user_id)\n  can see = admin\n"
        "type folder = app.folders\n  org   : org = org_id\n  owner : user = owner_id\n  roles : user from org\n"
        "  can view = owner or roles\n",
        "type org = app.orgs\n  admin : user = app.org_members(org_id -> user_id)\n  can see = admin\n"
        "  can manage_roles = admin\n"
        "type folder = app.folders\n  org   : org = org_id\n  owner : user = owner_id\n  roles : user from org\n"
        "  can view = owner or roles\n",
    ),
    "AZ401": Code(
        "Rules for a table no type maps to",
        "`rules schema.table` names the table of one of the policy's types: its rules use that type's "
        "permissions. Declare the type, or fix the table's name. Only one type maps to a table with rules: "
        "give another type its own table, or a view of this one.",
        "type folder = app.folders\n  owner : user = owner_id\n  can view = owner\nrules app.folder\n  select : view\n",
        "type folder = app.folders\n  owner : user = owner_id\n  can view = owner\nrules app.folders\n  select : view\n",
    ),
    "AZ402": Code(
        "Masks need a view",
        "Masked columns are hidden by a view the policy makes: `rules app.users view app.users_v`. The view "
        "shows the rows `select` allows, so the table needs a select rule, and the view's name must be a new "
        "one (not a table of the policy).",
        "type folder = app.folders\n  owner : user = owner_id\n  can view = owner\nrules app.folders\n"
        "  select : view\n  mask notes : owner\n",
        "type folder = app.folders\n  owner : user = owner_id\n  can view = owner\nrules app.folders view app.folders_v\n"
        "  select : view\n  mask notes : owner\n",
    ),
    "AZ403": Code(
        "An update refinement without an update rule",
        "`update after : ...` and column rules (`update owner_id : ...`) add to the table's `update` rule, which "
        "says who may update a row at all. Write it too.",
        "type folder = app.folders\n  owner : user = owner_id\n  can edit = owner\nrules app.folders\n"
        "  select : edit\n  update after : edit\n",
        "type folder = app.folders\n  owner : user = owner_id\n  can edit = owner\nrules app.folders\n"
        "  select : edit\n  update : edit\n  update after : edit\n",
    ),
    "AZ404": Code(
        "A scope written wrongly",
        "A scope limits what a token may do: `scope files = app.files.select, app.files.update, file.view`. "
        "Items are a command (`select`), a command on a table (`app.files.update`), or a permission of a type "
        "(`file.edit`); a bare word must be a command, or a permission some type has.",
        "type folder = app.folders\n  owner : user = owner_id\n  can view = owner\nscope read = folder.see\n",
        "type folder = app.folders\n  owner : user = owner_id\n  can view = owner\nscope read = folder.view\n",
    ),
    "AZ501": Code(
        "A $name used before it is given",
        "In a named test, `$ann` is the id a `given ann = {...}` line returned. Give it first, on a line above.",
        'type folder = app.folders\n  owner : user = owner_id\n  can view = owner\ntest "owners"\n'
        "  user $ann can view folder 1\n",
        'type folder = app.folders\n  owner : user = owner_id\n  can view = owner\ntest "owners"\n'
        "  given ann = {INSERT INTO app.users (name) VALUES ('Ann') RETURNING id}\n"
        "  given top = {INSERT INTO app.folders (owner_id, name) VALUES ($ann, 'Top') RETURNING id}\n"
        "  user $ann can view folder $top\n",
        when="tests",
    ),
    "AZ502": Code(
        "A test acting as a type that doesn't sign in",
        "A test acts as `anyone`, a user, or a principal type (`type bot = app.bots principal`).",
        "type team = app.teams\n  member : user = app.team_members(team_id -> user_id)\n  can see = member\n"
        "test \"teams\"\n  given t = {INSERT INTO app.teams (name) VALUES ('a') RETURNING id}\n  team $t can see team $t\n",
        "type team = app.teams\n  member : user = app.team_members(team_id -> user_id)\n  can see = member\n"
        "test \"teams\"\n  given t = {INSERT INTO app.teams (name) VALUES ('a') RETURNING id}\n  anyone cannot see team $t\n",
        when="tests",
    ),
    "AZ503": Code(
        "A test names a scope the policy doesn't have",
        "`with scope` checks a line as a key or a token limited to those scopes would be. The scopes are the "
        "policy's `scope` lines, and `read`, which is built in.",
        "type folder = app.folders\n  owner : user = owner_id\n  can view = owner\nscope files = folder.view\n"
        "test \"keys\"\n  given f = {INSERT INTO app.folders (owner_id, name) VALUES (1, 'a') RETURNING id}\n"
        "  user 1 with scope file can view folder $f\n",
        "type folder = app.folders\n  owner : user = owner_id\n  can view = owner\nscope files = folder.view\n"
        "test \"keys\"\n  given f = {INSERT INTO app.folders (owner_id, name) VALUES (1, 'a') RETURNING id}\n"
        "  user 1 with scope files can view folder $f\n",
        when="tests",
    ),
    "AZ601": Code(
        "A table or column that isn't there",
        "Applying checks the policy against the database first: each table a type or relation names, and each "
        "column a relation reads. Nothing is applied until they are all there. Run the app's schema migrations "
        "first, or fix the name.",
        "type folder = app.folders\n  owner : user = owner_uid\n  can view = owner\n",
        "type folder = app.folders\n  owner : user = owner_id\n  can view = owner\n",
        when="apply",
    ),
    "AZ602": Code(
        "A key of another type",
        "Keys are `bigint` unless written: `type doc = app.docs (id uuid)`. The table's column has another type, "
        "which the message names with what to write: `(id integer)` for a key Prisma made an `Int`.",
        "type doc = app.docs\n  owner : user = owner_id\n  can view = owner\n",
        "type doc = app.docs (id uuid)\n  owner : user = owner_id\n  can view = owner\n",
        when="apply",
    ),
    "AZ603": Code(
        "An inheritance condition that isn't the same for everyone at any time",
        "What limits inheritance is stored in the tree, so Postgres must agree that it depends only on the row: "
        "the functions it calls are IMMUTABLE, and nothing depends on the time zone or the session. To read "
        "another table, use a subquery (its changes are then tracked), not a function that reads it.",
        "type folder = app.folders\n  owner  : user = owner_id\n  parent : folder = parent_id\n"
        "  can view = owner or (parent.view and {app.is_open(id)})\n",
        "type folder = app.folders\n  owner  : user = owner_id\n  parent : folder = parent_id\n"
        "  can view = owner or (parent.view and {not exists (select 1 from app.locks l where l.folder_id = id)})\n",
        when="apply",
    ),
    "AZ604": Code(
        "An inheritance condition reading a view",
        "rowstile watches the tables an inheritance condition reads, so it can keep the tree up to date. A view "
        "can't be watched: read its tables directly.",
        "type folder = app.folders\n  owner  : user = owner_id\n  parent : folder = parent_id\n"
        "  can view = owner or (parent.view and {not exists (select 1 from app.locked_v l where l.folder_id = id)})\n",
        "type folder = app.folders\n  owner  : user = owner_id\n  parent : folder = parent_id\n"
        "  can view = owner or (parent.view and {not exists (select 1 from app.locks l where l.folder_id = id)})\n",
        when="apply",
    ),
    "AZ605": Code(
        "Links used for inheritance can't expire",
        "A shared relation that inheritance follows (`shortcut : folder shared`, `can view = ... or "
        "shortcut.view`) is part of a stored tree, so its shares can't expire, start later or carry a caveat. "
        "Remove those shares' expiry (or the shares) before applying. Once the policy is applied, such a share is "
        "refused with this code too (SQLSTATE 23514): by `authz.share`, and by a change to a share that is there.",
        "",
        "",
        when="apply",
    ),
    "AZ606": Code(
        "authz.uid() returns another type",
        "`authz.uid()` returns the user type's key type. The database has one returning another type, from an "
        "earlier policy whose users had other ids. Drop it, and what uses it, then apply: "
        "`DROP FUNCTION authz.uid() CASCADE`.",
        "",
        "",
        when="apply",
    ),
    "AZ607": Code(
        "A migration applied out of order",
        "Each policy migration starts from the policy the one before it left, recorded in "
        "`authz.policy_versions`. This database is somewhere else: a migration was skipped, or the database was "
        "changed with `rowstile push` or `apply` since. Apply the migrations in order; a database changed by "
        "`push` takes the migrations from the start, or `rowstile apply` of the policy the previous migration "
        "left. A development database that `rowstile dev` or `push` brought to the newest policy already holds "
        'what this migration brings, and the migration says so ("this database already holds what this '
        'migration brings"): tell the migration tool it is applied (Prisma: `prisma migrate resolve '
        "--applied <name>`, which also clears the failed migration Prisma kept; Alembic: `alembic stamp head`), "
        "or make the database again from the migrations.",
        "",
        "",
        when="deploy",
    ),
    "AZ608": Code(
        "A tree swapped in that wasn't built",
        "Two-phase migrations build a changed tree beside the one in use, then swap it in. The second one ran "
        "without the first: apply the migration before it.",
        "",
        "",
        when="deploy",
    ),
    "AZ609": Code(
        "No policy is applied",
        "The command asks the policy in force (tests, why, lint, snapshots, ...), and this database has none, or "
        "it was removed. Apply it first: `rowstile push` on a development database, the migrations elsewhere.",
        "",
        "",
        when="command",
    ),
    "AZ610": Code(
        "Not a development database",
        "`rowstile push` (and `rowstile dev`, and the MCP server's `push`) changes a policy straight away, so it "
        "only changes a development database: one marked as one. The first push to a database that never had a "
        "policy marks it. This one has a policy and no mark (or had one: `rowstile remove` leaves it as it was, "
        "marked or not): if it is production, it takes migrations "
        "(`rowstile migrate`, then your migration tool); if it is a development database (say, one your "
        "migrations set up), mark it once with `rowstile push --development`.",
        "",
        "",
        when="command",
    ),
    "AZ611": Code(
        "Masked columns still readable",
        "A masked column is read through the policy's view, so applying takes SELECT on the table's masked columns "
        "away from the app role. Something still grants it: SELECT on the table or those columns to PUBLIC, or to a "
        "role the app role belongs to. Revoke that grant, then apply again.",
        "",
        "",
        when="apply",
    ),
    "AZ612": Code(
        "A schema on the search path others may create in",
        "The functions that evaluate the policy's own SQL (its `{...}` conditions, the trees' triggers) run as the "
        "owner, and resolve names on the search path of the session that applied the policy. Another role may create "
        "objects in one of its schemas (often `public`: a database upgraded from Postgres 14 or older keeps "
        "`CREATE` for everyone), and a function made there can take the place of a built-in one, so it would run "
        "as the owner. Superusers, the owner, the database's owner and the roles that can become them are trusted. "
        "Revoke that `CREATE` (`REVOKE CREATE ON SCHEMA public FROM PUBLIC`), or apply with a search path "
        "without that schema (`ALTER ROLE <owner> SET search_path = app`): the policy's names are usually "
        "written with their schema anyway. `authz.lint()` reports it when the grant comes after.",
        "",
        "",
        when="apply",
    ),
    "AZ613": Code(
        "A condition that doesn't run",
        "The SQL in a `{...}` condition is checked by Postgres when the policy is applied, not when it is "
        "compiled: a column that isn't there (`{nme = 'x'}`), a function it can't find, a syntax error. The "
        "message names the condition's line and gives Postgres's reason (and its hint, such as the column it "
        "meant). Fix the condition. Conditions on a relation's table (`where {...}`) name that table's columns; "
        "a `shared if {...}`, the share's (`object_id`, `subject_type`, `subject_id`, `subject_relation`); the "
        "others, the columns of the type's own table. A signing-in type's `where` and a `shared if` are read by "
        "a function, which nothing in the catalog ties to the columns they read: the app may drop one after "
        "applying, and then its queries fail. Apply and push read those conditions again each time, and refuse "
        "one that no longer runs even when the policy didn't change: put the column back, or change the "
        "condition.",
        "",
        "",
        when="apply",
    ),
    "AZ614": Code(
        "Something uses a function this policy no longer makes",
        "A view or a function of yours may call the `authz.*` functions (`authz.can`, `authz.list`, ...): applying "
        "replaces them in place, and what uses them goes on working. This one is no longer made with those "
        "arguments (another version of rowstile, usually), so it can't be replaced, and Postgres won't drop a "
        "function something depends on. The message names the function and what uses it: drop that view or "
        "function, apply, and create it again with the function as it is now. (When only the function's result "
        "changed, Postgres says so itself, `cannot change return type of existing function`: the same fix.)",
        "",
        "",
        when="apply",
    ),
    "AZ615": Code(
        "A migration run outside a transaction",
        "A policy migration is one transaction: it uses temporary tables and settings that end with it, and its "
        "statements only make sense together. This one was run a statement at a time, each committed on its own "
        "(`psql -f` does that), where a change to inheritance would stop half way with the old trees dropped. So "
        "it refused before changing anything, and made the session read-only, since psql goes on after an error "
        "unless told to stop. Run it with your migration tool, which wraps each migration in a transaction, or "
        "`psql -1 -v ON_ERROR_STOP=1 -f <file>`.",
        "",
        "",
        when="deploy",
    ),
    "AZ616": Code(
        "An older command, a newer database",
        "The database (or the lock file) was last written by a newer version of rowstile than this command. Going "
        "on would put this older version's functions back, with everything fixed since undone, and a migration "
        "written now would be that step back, though it would read like an upgrade. An old global install, a CI "
        "image pinned to an older version or one machine that wasn't upgraded are the usual causes: upgrade the "
        "command there. To go back to the older version on purpose, add `--downgrade` (`rowstile apply`, `push` "
        "and `migrate` take it). Development builds of the same version can't be told apart, and are never refused.",
        "",
        "",
        when="command",
    ),
    "AZ617": Code(
        "Something is built on a masked view that can't be replaced in place",
        "A masked view (`rules app.docs view app.docs_visible`) is what the app reads the table through, so a view "
        "or a function of yours may be built on it. Applying, and a migration, replace it in place and what is "
        "built on it goes on working. That needs the view to keep its columns: here the table's columns changed "
        "(one was renamed, say), or the policy no longer has the masked view at all, and Postgres "
        "won't drop a view something depends on. The message names what is built on it: drop that, apply (or run "
        "the migration) again, then make it again.",
        "",
        "",
        when="apply",
    ),
    "AZ618": Code(
        "The owner may not switch to the app role",
        "`rowstile test` (its `as user ...` checks), `sql --as`, `explain-rule`, `plans`, `bench` and Studio look "
        "at the data as the app does: they switch to the app role with `SET ROLE`, in a transaction that is rolled "
        "back. The role the command connects as has to hold the app role for that. A superuser always does. Since "
        "PostgreSQL 16 a role that makes another (`CREATE ROLE app_user`) only administers it, so an owner that "
        "isn't a superuser, as on managed Postgres, gives itself the role once: `GRANT app_user TO app_owner`. It "
        "may, because it made the role. Where another role made both (a superuser setting up by hand), that "
        "role runs the grant. Nothing changes for the app, which connects as the app role itself.",
        "",
        "",
        when="command",
    ),
    "AZ619": Code(
        "A lock file rowstile can't read",
        "`rowstile migrate` writes the lock file (`db/policy.lock`): the policy's lines, then what the migrations "
        "made so far, each with a hash. A line of another kind is refused, by its number: most often a conflict "
        "marker (`<<<<<<<`, `=======`, `>>>>>>>`). Two branches each wrote a migration, and a merge left both lock "
        "files in one. Keep the lock file and the migrations of the branch merged into, and leave out the other "
        "branch's new migration, then run `rowstile migrate` again: it writes one migration from there to the merged "
        "policy. `rowstile review` says its Deploy part can't be computed from such a lock at the base.",
        "",
        "",
        when="command",
    ),
    "AZ701": Code(
        "Nobody signed in",
        "A query needed to know who is asking, and nobody signed in in this transaction. Every transaction starts "
        "with `SELECT authz.act_as('user', '42')` (or `authz.act_as(NULL, NULL)` for nobody, or a login); the SDKs "
        "do it for you, so a query outside them (a raw connection, a transaction begun elsewhere) is the usual "
        "cause. It is a bug in the app, not the user's doing. SQLSTATE 28000; the SDKs raise `NotSignedIn`, which "
        "their frameworks leave a 500. A transaction signed in as nobody on purpose is signed in: a call there that "
        "needs someone says AZ714.",
        when="runtime",
    ),
    "AZ702": Code(
        "Who is signed in was changed",
        "Who is signed in is signed by `authz.act_as()` for the transaction. Setting `authz.user_id` (or the other "
        "`authz.*` settings) directly, or changing them after signing in, isn't believed: the app role can't choose "
        "its own user. Sign in with `authz.act_as()`, `authz.login_key()` or `authz.login_jwt()` instead. SQLSTATE "
        "28000. It is a bug in the app: the SDKs leave it an error, a 500.",
        when="runtime",
    ),
    "AZ703": Code(
        "Login refused",
        "`authz.login_key()` or `authz.login_jwt()` didn't sign anyone in: the API key is unknown or revoked, the "
        "token's signature, time, issuer or audience is wrong, it names nobody who is active or a type that doesn't "
        "sign in, or JWT login isn't set up (`jwt_secret` in `authz.settings`). SQLSTATE 28000; answer 401, as the "
        "SDKs do, with the database's words.",
        when="runtime",
    ),
    "AZ704": Code(
        "A read-only session",
        "The session views as someone else (`authz.view_as`) or signed in with a token limited by scopes, so it may "
        "read but not change anything, sign other people in, view as someone again, or make a key with more scopes "
        "than it has. SQLSTATE 42501; answer 403, as the SDKs do (`Refused`, with this code).",
        when="runtime",
    ),
    "AZ705": Code(
        "Not allowed",
        "The signed-in person asked an `authz.*` function for something the policy doesn't let them do: share or "
        "unshare this object, share it with this subject (the relation's `shared if`), give a role, manage roles or "
        "keys, see who has access, the shares or the links, turn a link off, decide a request or a review, break "
        "the glass. The message says what; `authz.explain(type, id, perm)` says why. SQLSTATE 42501; answer 403, "
        "as the SDKs do (`Refused`, with this code).",
        when="runtime",
    ),
    "AZ706": Code(
        "The policy doesn't allow this share",
        "The share asked for isn't one the policy declares: the relation isn't `shared` with that kind of subject "
        "(say, a team where only users may be given it), the role isn't one of the object's, or a role would grant "
        "a permission roles can't grant. Change the call, or the policy's relation. SQLSTATE P0001. It is the "
        "app's mistake, not the user's: the SDKs leave it an error, a 500.",
        when="runtime",
    ),
    "AZ707": Code(
        "Not in the policy",
        "An `authz.*` function was called with a name the policy in force doesn't have: a type, a permission, a "
        "scope, a caveat, a table with rules, a type that signs in, custom roles on a type, or the `manage_roles` "
        "/ `manage_keys` permission it needs. Often the app and the database disagree on the policy: apply the "
        "migrations. SQLSTATE P0001. It is the app's mistake, not the user's: the SDKs leave it an error, a 500.",
        when="runtime",
    ),
    "AZ708": Code(
        "No such thing",
        "The call names something that isn't there: the subject to share with, an active user to view as, a "
        "pending request, an item of a review, an API key of yours, a link on the object. SQLSTATE P0001; answer "
        "404, as the SDKs do, with the database's words.",
        when="runtime",
    ),
    "AZ709": Code(
        "A write refused by a rule",
        "The table's rule for this insert or update doesn't hold for the signed-in principal on this row: SQLSTATE "
        "42501, the constraint `authz_insert` or `authz_update`, and the DETAIL says why, one reason per line. The "
        "SDKs raise `Refused` (403, with the reason). An update or delete the rules hide changes 0 rows instead, "
        "without an error: `authz.explain_rule(table, command, id)` says why (the SDKs' `expect`).",
        when="runtime",
    ),
    "AZ710": Code(
        "A missing or wrong argument",
        "A call is missing something it needs (a reason, kept in the audit trail; approve or deny) or has a value "
        "out of range (a duration that isn't positive, emergency access longer than a day, a command "
        "`authz.explain_rule` doesn't explain, a row it can't find without an id, a page cursor for `authz.list` "
        "that isn't an id of the type, a negative page size). SQLSTATE 22023; answer 400, as the SDKs do, with the "
        "database's words.",
        when="runtime",
    ),
    "AZ711": Code(
        "The audit trail can't be changed",
        "`authz.audit` only grows: rows can't be updated or deleted, even by the owner, except by "
        "`authz.trim_audit(interval)`, which removes what is older than the interval. SQLSTATE 42501: a refusal, "
        "which the SDKs would answer 403. Apps don't meet it: the app role may not write to `authz.audit` at all.",
        when="runtime",
    ),
    "AZ712": Code(
        "The change feed was trimmed",
        "A consumer asked for changes from a position older than what the feed still keeps. Read everything again "
        "(rebuild the cache or index), then follow the feed from its current position. SQLSTATE 55000. It is for "
        "the reader of the feed, not an answer to a request: the SDKs leave it an error, a 500.",
        when="runtime",
    ),
    "AZ713": Code(
        "Moved inside itself",
        "A move or a link would put an object inside itself (a folder into one of its own subfolders), which would "
        "make the tree a loop. SQLSTATE 23514; answer 409 (a conflict with where things are now), as the SDKs do, "
        "with the database's words.",
        when="runtime",
    ),
    "AZ714": Code(
        "Sign in first",
        "A call that needs someone signed in ran in a transaction signed in as nobody (`authz.act_as(NULL, NULL)`, "
        "a visitor who hasn't signed in): an access request, or an API key made for oneself. SQLSTATE 42501; "
        "answer 401, as the SDKs do, with the database's words. A transaction that never signed in says AZ701.",
        when="runtime",
    ),
    "AZ715": Code(
        "For users only",
        "A call that is for users ran while a service (a principal type other than the user type) was signed in: "
        "the custom roles API (`create_role`, `set_role_permissions`, `delete_role`, `roles_of`), access requests "
        "(`request_access`, `pending_requests`, `decide_request`, `cancel_request`), access reviews "
        "(`start_review`, `review_items`, `review_decide`, `close_review`), `break_glass`, a key for oneself "
        "(`create_api_key` without a principal) and `view_as`. It is refused even when the policy gives the service "
        "the permission the call asks for. A service may share and unshare, and a user holding "
        "`manage_keys` on it makes its keys (`authz.create_api_key('deploy', '', NULL, 'service', '7')`). "
        "SQLSTATE 42501; answer 403, as the SDKs do (`Refused`, with this code).",
        when="runtime",
    ),
}


def example(text: str) -> str:
    """An example as the page shows it and the tests compile it: with PRELUDE, unless it has its own."""
    return text if "type user " in text or text.startswith("app role ") else PRELUDE + text


def split(message: str) -> tuple[str, str | None]:
    """'line 4: ... [AZ201]' -> ('line 4: ...', 'AZ201'); a message without a code -> (message, None)."""
    m = CODE.search(message)
    return (message[: m.start()], m.group(1)) if m else (message, None)


def said(text: str, files: dict[str, str], when: str) -> PolicyError | None:
    """What compiling an example says: its mistake (in the policy, or in its tests on a page about tests), or None
    when it compiles (as each page's fix does: the unit tests ask)."""
    from . import Compiler, PolicyError, parse_policy

    try:
        comp = Compiler(parse_policy(example(text), None, files=files))
        comp.compile("x", transaction=False)
        if when == "tests":
            comp.compile_tests("x")
    except PolicyError as e:
        return e
    return None


def message(code: str) -> str | None:
    """What the compiler says about the page's mistake (None for mistakes only a database finds)."""
    c = CODES[code]
    if not c.wrong or c.when not in ("compile", "tests"):
        return None
    e = said(c.wrong, {} if code == "AZ108" else dict(c.files), c.when)
    return str(e) if e else None


def page(code: str) -> str:
    """The code's page, in markdown (docs/errors/AZ201.md, and `rowstile help AZ201`)."""
    c = CODES[code]
    out = [f"# {code}: {c.title}", "", c.text, ""]
    found = {
        "compile": "when the policy is compiled: `rowstile check`, the editor, `rowstile dev`",
        "tests": "when the tests are compiled: `rowstile test`, the editor, `rowstile dev`",
        "apply": "when the policy is applied (`rowstile push`, `apply`, a migration), against the database",
        "deploy": "when a policy migration runs",
        "command": "by the command, against a database",
        "runtime": "to the app, by the `authz.*` functions and the policy's rules: the code is in the error's HINT "
        f"(`rowstile help {code}`), and the SDKs' errors carry it as `code`",
    }[c.when]
    out += [f"Reported {found}.", ""]
    if c.wrong:
        out += ["## The mistake", "", "```authz", example(c.wrong).rstrip("\n"), "```", ""]
        said = message(code)
        if said:
            out += ["```", said, "```", ""]
    if c.right:
        out += ["## Fixed", "", "```authz", example(c.right).rstrip("\n"), "```", ""]
    for name, text in c.files:
        out += [f"With `{name}`:", "", "```authz", text.rstrip("\n"), "```", ""]
    return "\n".join(out)


def index() -> str:
    out = [
        "# Error codes",
        "",
        "Every mistake rowstile reports ends with its code: `line 4: folder.owner: unknown type 'person' "
        "[AZ201]`. `rowstile help AZ201` prints its page in the terminal.",
        "",
    ]
    for prefix, name in GROUPS:
        out += [f"## {name}", ""]
        out += [f"- [{code}]({code}.md): {c.title}" for code, c in CODES.items() if code.startswith(prefix)]
        out.append("")
    out.append(
        "These pages are written from `core/authzlib/errors.py`; edit it, then "
        "`python3 core/tests/unit_test.py --update`."
    )
    return "\n".join(out) + "\n"
