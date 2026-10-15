#!/usr/bin/env python3
"""policy_errors: mistakes in a policy are reported clearly, with a line number.

    python3 tests/policy_errors.py [--db authz_errors]

Compile-time cases need nothing else. Apply-time cases (the database is the only
one who knows) run against tests/alt_schema.sql in a scratch database.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import re  # noqa: E402

from authzlib import Compiler, PolicyError, parse_policy  # noqa: E402
from authzlib.errors import CODES, split  # noqa: E402


def coded(message: str) -> bool:
    """The message ends with a known code (authzlib/errors.py)."""
    return split(message.strip())[1] in CODES


BASE = """app role app_user
type user = alt.users
type grp = alt.groups (gid)
  member : user = alt.group_members(group_id -> user_id)
type doc = alt.docs (doc_no)
  owner  : user = owner_id
  parent : doc  = up
  reader : user, grp#member  shared
  can share = owner or parent.owner
"""

# (what, policy text appended to BASE, expected piece of the message, expected line or None)
COMPILE = [
    (
        "a dollar-quote tag in a condition",
        "  can see = owner and {up <> 0 or '$f$' = ''}\n",
        "contains $f$, which ends the generated function it goes in",
        10,
    ),
    (
        "a name that starts with authz__ in a condition",
        '  can see = owner and {not exists (select 1 from alt.holds "authz__h" where "authz__h".target = this.doc_no)}\n',
        'names "authz__h": names that start with authz__ are rowstile\'s own',
        10,
    ),
    (
        "a character that doesn't print, shown escaped",
        "  can see = owner \x01\n",
        "unexpected '\\x01' in expression",
        10,
    ),
    (
        "a typo in a relation's only use: the typo is named, not the relation as unused",
        "  editor : user = owner_id\n  can edit = editr\n",
        "doc has no relation or permission 'editr'",
        11,
    ),
    (
        "custom roles from a shared relation",
        "  roles : user from reader\n  can view = owner or roles\n",
        "custom roles on doc come from 'reader', which must be a relation of doc kept in a column or a table",
        10,
    ),
    (
        "custom roles from a relation that isn't there",
        "  roles : user from org\n  can view = owner or roles\n",
        "custom roles on doc come from 'org'",
        10,
    ),
    (
        "roles under a not",
        "  roles : user\n  can view = owner and not roles\n",
        "doc.view: `not roles` would take a permission away",
        11,
    ),
    ("a roles line no permission uses", "  roles : user\n", "no permission writes `roles`", 10),
    (
        "roles in a type without a roles line",
        "  can view = owner or roles\n",
        "doc.view writes `roles`, but doc has no `roles : ...` line",
        10,
    ),
    (
        "roles in a rule",
        "  roles : user\n  can view = owner or roles\nrules alt.docs\n  select : view or roles\n",
        "`roles` goes in a permission, which says what a custom role gives",
        13,
    ),
    (
        "roles in an invariant",
        "  roles : user\n  can view = owner or roles\ninvariants\n  never doc: roles\n",
        "`roles` goes in a permission",
        13,
    ),
    (
        "roles followed by a dot",
        "  roles : user\n  can view = owner or roles.view\n",
        "doc.view: `roles` gives the permission it is written in; it isn't a relation to follow",
        11,
    ),
    (
        "a relation named roles",
        "  roles : user = owner_id\n",
        "`roles : ...` says who may hold custom roles; name the relation something else",
        10,
    ),
    ("a permission named roles", "  can roles = owner\n", "'roles' is where custom roles give a permission", 10),
    (
        "a relation named like a word that continues a line",
        "  where : user = owner_id\n",
        "'where' is a word of the language",
        10,
    ),
    ("a relation named and", "  and : user = owner_id\n", "'and' is a word of the language", 10),
    ("a permission named or", "  can or = owner\n", "'or' is a word of the language", 10),
    (
        "a plain update rule written with before",
        "rules alt.docs\n  update before : share\n",
        "a plain update rule is checked on the row before and after",
        11,
    ),
    (
        "anyone or link with a relation",
        "type thing = alt.docs (doc_no)" + chr(10) + "  viewer : user, link#member  shared" + chr(10),
        "link stands alone",
        11,
    ),
    ("a type named like a special subject", "type anyone = alt.docs (doc_no)" + chr(10), "subject of its own", 10),
    ("unknown subject type", "  editor : robot = owner_id\n", "unknown type 'robot'", 10),
    ("unknown group relation", "  editor : grp#admin shared\n", "grp has no relation or permission 'admin'", 10),
    (
        "unknown name in a permission",
        "  can view = owner or viewer\n",
        "doc has no relation or permission 'viewer'",
        10,
    ),
    (
        "following a permission with a dot",
        "  can view = owner\n  can edit = view.x\n",
        "'view' is a permission; only relations can be followed",
        11,
    ),
    (
        "following a relation to users, to something they don't have",
        "  can view = owner.view\n",
        "user has no relation or permission 'view'",
        10,
    ),
    (
        "following a relation to groups",
        "  can view = reader.member\n",
        "doc.reader links to groups, anyone or links, so there is nothing to follow",
        10,
    ),
    (
        "following a relation shared with anyone",
        "  pub : anyone shared by share\n  can see = owner\n  can view = pub.see\n",
        "doc.pub links to groups, anyone or links, so there is nothing to follow",
        12,
    ),
    (
        "... with a link",
        "  pub : link shared by share\n  can see = owner\n  can view = pub.see\n",
        "doc.pub links to groups, anyone or links, so there is nothing to follow",
        12,
    ),
    (
        "... with every signed-in user",
        "  pub : user:* shared by share\n  can see = owner\n  can view = pub.see\n",
        "doc.pub links to groups, anyone or links, so there is nothing to follow",
        12,
    ),
    (
        "using a link as if it held users",
        "  can view = parent\n",
        "doc.parent links to doc objects, not users; follow it with a dot",
        10,
    ),
    ("permissions that depend on each other", "  can a = owner or b\n  can b = a\n", "depends on itself", None),
    (
        "inheritance with no starting point",
        "  can view = parent.view\n",
        "doc.view needs a starting point besides inheritance",
        10,
    ),
    (
        "inheritance narrowed by something other than a condition",
        "  can view = owner or (parent.view and reader)\n",
        "inheritance through parent can only be narrowed with {conditions}",
        10,
    ),
    (
        "inheritance that depends on the time",
        "  can view = owner or (parent.view and {created_at > now() - interval '1 day'})\n",
        "can't limit inheritance: it depends on now",
        10,
    ),
    (
        "inheritance that depends on the user",
        "  can view = owner or (parent.view and {owner_id <> authz.uid()})\n",
        "can't limit inheritance: it depends on authz.uid",
        10,
    ),
    (
        "a group made only of itself",
        "type team = alt.groups (gid)\n  member : team#member shared by x\n  can x = member\n",
        "team.member only contains itself; add a source of users",
        11,
    ),
    (
        "a relation defined as a permission too",
        "  can view = owner\n  view : user = owner_id\n",
        "doc.view is already a permission",
        11,
    ),
    (
        "two kinds of subject on a column",
        "  editor : user, grp#member = owner_id\n",
        "a column or table source links to exactly one kind of subject",
        10,
    ),
    (
        "a rule for a table with no type",
        "rules alt.nothing\n  select : view\n",
        "rules for alt.nothing, but no type maps to that table",
        11,
    ),
    (
        "update after without update",
        "  can view = owner\nrules alt.docs\n  select : view\n  update after : view\n",
        "'update after' refines updates, so alt.docs needs an 'update' rule too",
        13,
    ),
    (
        "a relation named like a word of the language",
        "  nobody : user = owner_id\n  can view = nobody\n",
        "'nobody' is a word of the language",
        10,
    ),
    ("a permission named anyone", "  can anyone = owner\n", "'anyone' is a word of the language", 10),
    (
        "and next to or",
        "  can view = owner or parent.owner and {not locked}\n",
        "`and` and `or` meet without parentheses, which reads two ways: write owner or (parent.owner and {not locked})",
        10,
    ),
    (
        "and next to or, the other way",
        "  can view = not {locked} and owner or anyone\n",
        "write (not {locked} and owner) or anyone",
        10,
    ),
    (
        "and next to or across a continuation line",
        "  can view = owner\n           or parent.owner and {not locked}\n",
        "write owner or (parent.owner and {not locked})",
        10,
    ),
    (
        "the old 'check' keyword",
        "  can view = owner\nrules alt.docs\n  select : view\n  update : view\n  update up check : view\n",
        "write 'after' instead of 'check' (checked on the row after the change): update up after : ...",
        14,
    ),
    (
        "before or after on a command other than update",
        "  can view = owner\nrules alt.docs\n  select after : view\n",
        "only update rules can name columns, 'before' or 'after'",
        12,
    ),
    (
        "a relation nothing uses (a typo for a second source)",
        "  reader : grp#member = alt.doc_groups(doc_no -> gid)\n  raeder : user = alt.doc_readers(doc_no -> user_id)\n"
        "  can view = owner or reader\n",
        "doc.raeder is declared but nothing uses it",
        11,
    ),
    (
        "shared without a share permission to share it",
        "type memo = alt.docs (doc_no)\n  owner : user = owner_id\n  reader : user  shared\n  can view = owner or reader\n",
        "memo.reader is shared, which needs a share permission on memo",
        12,
    ),
    (
        "a column rule on select",
        "  can view = owner\nrules alt.docs\n  select owner_id : view\n",
        "only update rules can name columns",
        12,
    ),
    (
        "the same rule twice",
        "  can view = owner\nrules alt.docs\n  select : view\n  select : owner\n",
        "alt.docs has two 'select' rules",
        13,
    ),
    ("an expression that doesn't parse", "  can view = owner or (parent.view and {x}\n", "missing )", 10),
    ("an unclosed condition", "  can view = owner or {x = 1\n", "a { condition is missing its closing }", 10),
    ("a badly written relation", "  editor user = owner_id\n", "write relations as", 10),
    (
        "a name with the separator generated names use",
        "type my__doc = alt.docs (doc_no)\n",
        "names can't contain '__'",
        10,
    ),
    (
        "brackets for a key of one column",
        "  dp : grp = [owner_id, up]\n",
        "the subject is a grp, whose key is one column, but this source gives 2 columns [AZ206]",  # (no brackets)
        10,
    ),
    (
        "one column for a composite key",
        "type pair = alt.doc_links (child, parent)\ntype thing = alt.docs (doc_no)\n  p : pair = up\n  can view = p.x\n",
        "the subject is a pair, whose key is [child, parent], but this source gives 1 column: write them in square brackets",
        12,
    ),
    (
        "a composite key with a timestamp",
        "type ev = alt.docs (doc_no, created timestamptz)\n",
        "created is timestamptz: a composite key's columns must be",
        10,
    ),
    ("a badly written key", "type ev = alt.docs (doc_no bigint uuid)\n", "write the key as (column [type])", 10),
    (
        "type:* of a type that doesn't sign in",
        "  sh : user, grp:*  shared\n  can view = owner or sh\n",
        "grp:* means any signed-in grp, but grp doesn't sign in",
        10,
    ),
    (
        "a principal type with a composite key",
        "type svc = alt.doc_links (child, parent) principal\n",
        "the svc type signs in, so it needs a key of one column",
        10,
    ),
    (
        "referring to a generated name",
        "  can view = owner or parent.view__base\n",
        "names with '__' are generated ones",
        10,
    ),
    (
        "a deny that doesn't cover what is below",
        "  can denied = owner\n  can view = (reader or parent.view) and not denied\n",
        "`not denied` must cover everything below, so denied must inherit through parent",
        11,
    ),
    (
        "a deny by a relation",
        "  blocked : user = owner_id\n  can view = (reader or parent.view) and not blocked\n",
        "blocked is a relation: make a permission that inherits",
        11,
    ),
    (
        "a deny that has a deny of its own",
        "  can gone = owner or parent.gone\n  can denied = (reader or parent.denied) and not gone\n"
        "  can view = (owner or parent.view) and not denied\n",
        "denied has a deny of its own, which can cut it below a denied object",
        12,
    ),
    (
        "rules for a table two types map to",
        "type doc2 = alt.docs (doc_no)\n  owner : user = owner_id\n  can see = owner\nrules alt.docs\n  select : see\n",
        "rules for alt.docs, which types doc and doc2 both map to",
        14,
    ),
    (
        "a scope naming a generated permission",
        "  can view = (owner or parent.view) and not share\nscope s = doc.view__base\n",
        "names with '__' are generated ones",
        11,
    ),
    (
        "a deny through a link, not a permission",
        "  can denied = owner or parent.denied\n  can view = (reader or parent.view) and not parent.denied\n",
        "a deny on it is `not <permission of doc>`",
        11,
    ),
    (
        "inheritance joined with another permission",
        "  can view = (reader or parent.view) and owner\n",
        "can only join its inheritance with {conditions} and `not <permission>`",
        10,
    ),
    (
        "inheritance limited by the literal 'now'",
        "  can view = owner or (parent.view and {'now'::timestamptz > created})\n",
        "'now' means the current time",
        10,
    ),
    (
        "an inheritance link table filtered by time",
        "  linked : doc = alt.doc_links(child -> parent) where {now() > '2000-01-01'}\n  can view = owner or linked.view\n",
        "can't limit inheritance: it depends on now",
        10,
    ),
    (
        "following a relation to two types when one lacks the permission",
        "  holder : doc, grp = (holder_type, holder_id)\n  can view = owner or holder.view\n",
        "grp has no relation or permission 'view'",
        11,
    ),
    (
        "user:* on a column",
        "  editor : user:* = owner_id\n",
        "user:* (or another type:*), anyone and link can only be used with 'shared'",
        10,
    ),
    (
        "inheritance through a relation shared with anyone",
        "  shortcut : doc, anyone shared\n  can view = owner or shortcut.view\n",
        "doc.shortcut links to groups, anyone or links, so there is nothing to follow",
        11,
    ),
    (
        "a type whose where depends on the time, with inheritance",
        "  can view = owner or parent.view\ntype doc2 = alt.docs (doc_no) where {created > now()}\n"
        "  up : doc2 = up\n  owner : user = owner_id\n  can see = owner or up.see\n",
        "can't decide who inherits (the type's where): it depends on now",
        11,
    ),
    (
        "sharing by a permission that does not exist",
        "  writer : user shared by edit\n",
        "doc.writer is shared by 'edit', but doc has no such permission",
        10,
    ),
    (
        "two permissions of one type inheriting through each other",
        "  can a = owner or parent.b\n  can b = parent.a\n",
        "inherit through each other",
        None,
    ),
    (
        "an inheritance link table filtered by another table",
        "  linked : doc = alt.doc_links(child -> parent) where {exists (select 1 from alt.holds)}\n"
        "  can view = owner or linked.view\n",
        "doc.linked is used for inheritance, so its where {...} can only use the columns of alt.doc_links",
        10,
    ),
    (
        "a mask without a view",
        "  can view = owner\nrules alt.docs\n  select : view\n  mask title : owner\n",
        "masks are applied by a view: write 'rules alt.docs view <schema.view_name>'",
        13,
    ),
    (
        "a masked view without a select rule",
        "  can view = owner\nrules alt.docs view alt.docs_v\n  update : view\n",
        "the view alt.docs_v shows the rows 'select' allows, so alt.docs needs a select rule",
        11,
    ),
    (
        "a column masked twice",
        "  can view = owner\nrules alt.docs view alt.docs_v\n  select : view\n  mask title : owner\n  mask title : view\n",
        "alt.docs.title is masked twice",
        14,
    ),
    (
        "an invariant on an unknown type",
        "  can view = owner\ninvariants\n  never robot: view\n",
        "unknown type 'robot'",
        12,
    ),
    ("the app role named twice", "app role other_app\n", "the app role is named twice (app_user and other_app)", 10),
    (
        "impersonate on a type other than user",
        "  can impersonate = owner\n",
        "doc.impersonate: authz.view_as asks for `impersonate` on the user type",
        10,
    ),
    (
        "manage_keys on a type that doesn't sign in",
        "  can manage_keys = owner\n",
        "doc.manage_keys: API keys are made for types that sign in, and doc doesn't",
        10,
    ),
    (
        "break_glass with nothing to give",
        "type grp2 = alt.groups (gid)\n  boss : user = owner_id\n  can break_glass = boss\n",
        "grp2.break_glass: authz.break_glass gives its holder a relation of grp2 shared with a user",
        12,
    ),
    (
        "manage_roles with no roles to make",
        "  can manage_roles = owner\n",
        "doc.manage_roles lets people create custom roles owned by a doc, but no roles line counts them",
        10,
    ),
    (
        "roles from an owner nobody may make roles for",
        "  roles : user from parent\n  can view = owner or roles\n",
        "custom roles on doc are the roles of its parent, which people with manage_roles on a doc create, and doc has "
        "no `can manage_roles`",
        10,
    ),
    ("this in a caveat", "caveat near = {this.up = 1}\n", "caveat near: a caveat is checked with each request", 10),
    (
        "this as a table's name in a condition",
        "  can view = owner or {exists (select 1 from alt.holds this where this.target = doc_no)}\n",
        "`this` is the row the condition is about (this.column); call the table something else",
        10,
    ),
    (
        "roles nobody may make",
        "  roles : user\n  can view = owner or roles\n",
        "custom roles on doc are made by people with manage_roles on their owner, and no type has `can manage_roles`",
        10,
    ),
    # mistakes the parser reports that no case met (the coverage report)
    ("an empty condition", "  can see = owner and {   }\n", "empty {} condition", 10),
    ("a key column named twice", "type t2 = alt.docs (doc_no, doc_no)\n", "a key column is named twice", 10),
    (
        "a link table's object side named as two columns",
        "  x : user = alt.group_members(object: (a, b), subject: user_id)\n",
        "the object side is one column",
        10,
    ),
    (
        "a link table's sides named, but not one object and one subject",
        "  x : user = alt.group_members(object: group_id, object: user_id)\n",
        "name one 'object' column and one 'subject' column",
        10,
    ),
    (
        "a table given a second view",
        "rules alt.docs view alt.v1\n  select : share\nrules alt.docs view alt.v2\n  select : share\n",
        "alt.docs already has the view alt.v1",
        12,
    ),
    (
        "two tables given the same view (applying would make it twice)",
        "rules alt.docs view alt.v\n  select : share\nrules alt.groups view alt.v\n  select : member\n",
        "alt.v is already the view of alt.docs (line 10): give alt.groups a view of its own",
        12,
    ),
    ("a caveat defined twice", "caveat c = {true}\ncaveat c = {true}\n", "caveat c is defined twice", 11),
    ("a test's given without a statement", 'test "t"\n  given x = { }\n', "given {...} needs a statement", 11),
    ("a test's as without a statement", 'test "t"\n  as user 1 allowed { }\n', "as ... {...} needs a statement", 11),
    (
        "a test named twice, once in single quotes and once in double",
        "test 'a'\n  user 1 can share doc 1\ntest \"a\"\n  user 1 can share doc 1\n",
        "there is already a test named 'a'",
        12,
    ),
    (
        "a test named without quotes is the same test as one in quotes",
        'test "sharers see docs"\n  user 1 can share doc 1\ntest sharers see docs\n  user 1 can share doc 1\n',
        "there is already a test named 'sharers see docs'",
        12,
    ),
    ("a scope's command without its table", "scope s = docs.select\n", "commands are qualified by a table", 10),
    ("a scope's permission under a schema", "scope s = alt.doc.share\n", "permissions are qualified by a type", 10),
    ("custom roles declared twice", "  roles : user\n  roles : user\n", "doc declares custom roles twice", 11),
    ("custom roles naming no one", "  roles :\n", "write custom roles as: roles : user, team#member [from org]", 10),
    (
        "a pair of columns naming a group",
        "  x : grp#member = (kind, owner_id)\n",
        "a (type_col, id_col) source links to objects, not groups",
        10,
    ),
    ("a mask without columns", "rules alt.docs\n  select : share\n  mask : share\n", "write masks as: mask col1", 12),
    (
        "a deny on a permission that inherits through another type",
        "  project : project = project_id\n  can hidden = {locked} or parent.hidden\n"
        "  can view = (owner or parent.view or project.view) and not hidden\n"
        "type project = alt.projects\n  lead : user = lead_id\n  docs : doc = alt.doc_projects(proj_id -> doc_no)\n"
        "  can view = lead or docs.view\n",
        "doc.view has a deny, so it can only inherit within doc (like parent.view), not through permissions of other "
        "types",
        12,
    ),
    (
        "a deny on a permission that inherits through a relation to another type too",
        "  above : doc, grp = (above_type, above_id)\n  can hidden = {locked} or above.hidden\n"
        "  can view = (owner or above.view) and not hidden\n",
        "doc.view has a deny and inherits through above, which also points at other types; give those their own "
        "relation",
        12,
    ),
    (
        "a permission that depends on itself only through a not",
        "  can view = {locked} and not parent.view\n",
        "doc.view depends on itself; a permission can only recurse as 'or rel.perm' (optionally 'and {condition}')",
        10,
    ),
    (
        "inheritance narrowed by a relation, after a condition",
        "  can view = owner or ({locked} and parent.view and reader)\n",
        "inheritance through parent can only be narrowed with {conditions}",
        10,
    ),
    (
        "inheritance narrowed by a permission through another relation, written before it: the inheritance is named",
        "  also : doc = also_up\n  can view = owner or (also.share and parent.view)\n",
        "inheritance through parent can only be narrowed with {conditions} on the row, e.g. (parent.view and {inherit})",
        11,
    ),
    (
        "inheritance inside an or, inside an and",
        "  can view = owner or (reader and (parent.view or {locked}))\n",
        "doc.view depends on itself; a permission can only recurse as 'or rel.perm' (optionally 'and {condition}')",
        10,
    ),
    (
        "a group named by the permission it gives",
        "  viewer : user, doc#view  shared\n  can view = owner or viewer\n",
        "doc.view depends on itself; a permission can only recurse as 'or rel.perm' (optionally 'and {condition}')",
        11,
    ),
    (
        "two groups nested in each other",
        "type team = alt.projects\n  lead : user, team#helper shared by see\n  helper : user, team#lead shared by see\n"
        "  can see = lead or helper\n",
        "team.lead depends on itself; a permission can only recurse as 'or rel.perm' through a relation to objects, "
        "and a group only as 'member : group#member'",
        11,
    ),
    (
        "a rule following a permission with a dot, among other items",
        "rules alt.docs\n  select : owner or share.view\n",
        "'share' is a permission; only relations can be followed with a dot",
        11,
    ),
    (
        "a rule using a link as if it held users",
        "rules alt.docs\n  select : owner or parent\n",
        "doc.parent links to doc objects, not users; follow it with a dot",
        11,
    ),
    (
        "... also when the link has a column and a link table",
        "  parent : doc = alt.doc_links(child -> parent)\nrules alt.docs\n  select : owner and not parent\n",
        "doc.parent links to doc objects, not users; follow it with a dot",
        12,
    ),
    (
        "a masked view named as the table",
        "rules alt.docs view alt.docs\n  select : share\n",
        "alt.docs is a table of the policy; name a new view",
        10,
    ),
    (
        "a masked view named as another type's table",
        "rules alt.docs view alt.groups\n  select : share\n",
        "alt.groups is a table of the policy; name a new view",
        10,
    ),
    (
        "a scope's command on a table no type maps",
        "scope s = alt.things.select\n",
        "scope s: no type maps to alt.things",
        10,
    ),
    ("a scope's permission of a type that isn't there", "scope s = robot.view\n", "scope s: unknown type 'robot'", 10),
    (
        "a scope's permission no type has",
        "scope s = frobnicate\n",
        "scope s: no type has a permission 'frobnicate'",
        10,
    ),
]

# whole policies, without BASE: (what, policy, expected piece of the message, expected line)
WHOLE = [
    ("no app role", "type user = alt.users\n", "name the app role, the Postgres role your app connects as", 1),
    ("PUBLIC as the app role", "app role public\ntype user = alt.users\n", "not PUBLIC", 1),
]

APPLY = [
    (
        "a table that doesn't exist",
        "type thing = alt.things\n  owner : user = owner_id\n  can view = owner\n",
        "line 10: table alt.things not found",
    ),
    (
        "... said first: the policy names what the database lacks",
        "type thing = alt.things\n  owner : user = owner_id\n  can view = owner\n",
        "the policy does not match this database:",
    ),
    (
        "a column that doesn't exist",
        "  editor : user = editor_id\n  can view = editor\n",
        "line 10: column editor_id not found in alt.docs",
    ),
    (
        "inheritance reading a view",
        "  can view = owner or (parent.view and {not exists (select 1 from alt.held h where h.target = doc_no)})\n",
        "reads alt.held, which is not a table",
    ),
    (
        "inheritance calling a function that isn't IMMUTABLE",
        "  can view = owner or (parent.view and {alt.is_open(doc_no)})\n",
        "line 10: a condition used for inheritance calls alt.is_open(bigint), which is not IMMUTABLE",
    ),
    (
        "a key declared with the wrong type",
        "type doc3 = alt.docs (doc_no uuid)\n  owner : user = owner_id\n  can see = owner\n",
        "line 10: alt.docs.doc_no is bigint, not uuid: write its type after the key, (doc_no bigint) [AZ602]",
    ),
    (
        "inheritance limited by a time-zone dependent expression",
        "  can view = owner or (parent.view and {created + interval '1 day' > '2020-01-01'})\n",
        "line 10: a condition that limits inheritance must give the same answer for every user at any time",
    ),
    (
        "inheritance across two types through a link table whose where depends on the time zone",
        "  project : project = alt.proj_links(doc_no -> proj_id) where {since + interval '1 day' > '2020-01-01'}\n"
        "  can view = owner or parent.view or project.view\n"
        "type project = alt.projects\n  lead : user = lead_id\n  docs : doc = alt.doc_projects(proj_id -> doc_no)\n"
        "  can view = lead or docs.view\n",
        "line 10: a condition that limits inheritance must give the same answer for every user at any time",
    ),
]

# Answers worked out by hand, asked of the database as each user ('' is nobody): expect() says which ids
# authz.list gives and which of the ids authz.can allows, sees() which rows the app role reads through the rules.
ANSWERS = """
CREATE FUNCTION pg_temp.expect(p_user text, p_type text, p_perm text, p_ids text[], p_want text[]) RETURNS void
LANGUAGE plpgsql AS $f$
DECLARE v_want text[] := ARRAY(SELECT x FROM unnest(p_want) x ORDER BY x); v_list text[]; v_can text[];
BEGIN
  PERFORM set_config('authz.user_id', p_user, false);
  v_list := ARRAY(SELECT x FROM authz.list(p_type, p_perm) x ORDER BY x);
  v_can := ARRAY(SELECT x FROM unnest(p_ids) x WHERE authz.can(p_type, x, p_perm) ORDER BY x);
  IF v_list <> v_want OR v_can <> v_want THEN
    RAISE EXCEPTION '%.% as user %: authz.list gives %, authz.can allows %, by hand %',
      p_type, p_perm, p_user, v_list, v_can, v_want;
  END IF;
END $f$;
CREATE FUNCTION pg_temp.sees(p_user text, p_query text, p_want text[]) RETURNS void
LANGUAGE plpgsql AS $f$
DECLARE v_got text[];
BEGIN
  PERFORM set_config('authz.user_id', p_user, true);
  SET LOCAL ROLE app_user;
  EXECUTE 'SELECT ARRAY(' || p_query || ')' INTO v_got;
  RESET ROLE;
  IF v_got <> ARRAY(SELECT x FROM unnest(p_want) x ORDER BY x) THEN
    RAISE EXCEPTION 'as user %, the app role reads % (%), by hand %', p_user, v_got, p_query, p_want;
  END IF;
END $f$;
"""

# policies that must apply cleanly although their names are awkward (a whole policy if it starts with its app role)
APPLY_OK = [
    (
        "names longer than Postgres allows (63 bytes) are shortened consistently",
        "type a_type_with_a_really_quite_extraordinarily_long_name_for_testing = alt.docs (doc_no)\n"
        "  an_equally_long_relation_name_that_goes_on_and_on_and_on : a_type_with_a_really_quite_extraordinarily_long_name_for_testing = up\n"
        "  owner : user = owner_id\n"
        "  can a_permission_whose_name_is_also_far_too_long_to_fit = owner\n"
        "     or an_equally_long_relation_name_that_goes_on_and_on_and_on.a_permission_whose_name_is_also_far_too_long_to_fit\n",
        {},
    ),
    (
        "two types whose names differ only in case, on one table, both signing in: their functions and triggers apart",
        "app role app_user\ntype user = alt.users\n"
        + "".join(
            f"type {name} = alt.groups (gid) principal\n  owner  : user = owner_id\n  reader : user shared\n"
            "  can share = owner\n  can manage_keys = owner\n"
            for name in ("Agent", "agent")
        ),
        {},
    ),
    ("an empty search_path while applying", "  can view = owner\n", {"PGOPTIONS": "-c search_path="}),
    (
        "a table named with a reserved word",
        "type grp2 = alt.group (gid)\n  owner : user = owner_id\n  can see = owner\nrules alt.group\n  select : see\n",
        {},
    ),
    (
        "memberships read from a view (not audited, but usable)",
        "type grp4 = alt.groups (gid)\n  member : user = alt.member_view(group_id -> user_id)\n  can see = member\n",
        {},
        "INSERT INTO alt.users VALUES (1); INSERT INTO alt.groups VALUES (1, 1); INSERT INTO alt.group_members VALUES (1, 1);"
        "SET authz.user_id = 1; DO $$ BEGIN IF NOT authz.can('grp4', '1', 'see') THEN RAISE EXCEPTION 'no'; END IF; END $$;",
    ),
    (
        "a link table's where calling a function found on the search_path; writes to the table still work",
        "type grp3 = alt.groups (gid)\n  member : user = alt.group_members(group_id -> user_id) where {is_active(active)}\n"
        "  can see = member\n",
        {"PGOPTIONS": "-c search_path=alt,public"},
        "INSERT INTO alt.users VALUES (1); INSERT INTO alt.groups VALUES (1, 1); INSERT INTO alt.group_members VALUES (1, 1);"
        "UPDATE alt.group_members SET active = false; DELETE FROM alt.group_members; TRUNCATE alt.group_members;",
    ),
    # forms of the language that must give, in the database, the answers worked out by hand from the reference
    # (docs/reference/language.md), asked with ANSWERS
    (
        "a group named by a permission (team#manage): shared to it, those who hold the permission hold the relation",
        "  watcher : user, team#manage  shared\n  can view = owner or reader or watcher\n"
        "type team = alt.groups (gid)\n  boss : user = owner_id\n  can manage = boss\n",
        {},
        ANSWERS + "INSERT INTO alt.users VALUES (1), (2), (3), (4); INSERT INTO alt.groups VALUES (1, 1), (2, 3);"
        "INSERT INTO alt.group_members (group_id, user_id) VALUES (1, 2), (2, 4);"
        "INSERT INTO alt.docs (doc_no) VALUES (10), (11), (12);"
        "INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id, subject_relation) VALUES"
        " ('doc', '10', 'watcher', 'team', '1', 'manage'), ('doc', '11', 'reader', 'grp', '1', 'member'),"
        " ('doc', '12', 'watcher', 'team', '2', 'manage');"
        "SELECT pg_temp.expect('1', 'doc', 'view', '{10,11,12}', '{10}');"
        "SELECT pg_temp.expect('2', 'doc', 'view', '{10,11,12}', '{11}');"
        "SELECT pg_temp.expect('3', 'doc', 'view', '{10,11,12}', '{12}');"
        "SELECT pg_temp.expect('4', 'doc', 'view', '{10,11,12}', '{}');"
        "SELECT pg_temp.expect('', 'doc', 'view', '{10,11,12}', '{}');"
        "SELECT pg_temp.expect('1', 'team', 'manage', '{1,2}', '{1}');",
    ),
    (
        "a relation declared again for another type (a doc's parent is a doc, or its project), inheriting through it",
        "  parent : doc = alt.doc_links(child -> parent)\n  parent : project = project_id\n"
        "  can view = (owner and not {locked}) or parent.view\nrules alt.docs\n  select : view\n"
        "type project = alt.projects\n  owner : user = lead_id\n  can view = owner\n",
        {},
        # (doc 3's parent is doc 1 through the column, and the project has the id of a doc)
        ANSWERS + "INSERT INTO alt.users VALUES (1), (2), (3); INSERT INTO alt.projects VALUES (1, 3);"
        "INSERT INTO alt.docs (doc_no, owner_id, locked, project_id) VALUES (1, 1, false, NULL), (2, 1, true, NULL),"
        " (4, NULL, false, NULL), (5, NULL, false, 1), (6, NULL, false, NULL), (7, 2, false, 1);"
        "INSERT INTO alt.docs (doc_no, up) VALUES (3, 1); INSERT INTO alt.doc_links VALUES (4, 2), (6, 5);"
        "SELECT pg_temp.expect('1', 'doc', 'view', '{1,2,3,4,5,6,7}', '{1,3}');"
        "SELECT pg_temp.expect('2', 'doc', 'view', '{1,2,3,4,5,6,7}', '{7}');"
        "SELECT pg_temp.expect('3', 'doc', 'view', '{1,2,3,4,5,6,7}', '{5,6,7}');"
        "SELECT pg_temp.expect('', 'doc', 'view', '{1,2,3,4,5,6,7}', '{}');"
        "SELECT pg_temp.expect('1', 'doc', 'share', '{1,2,3,4,5,6,7}', '{1,2,3,4}');"
        "SELECT pg_temp.expect('3', 'doc', 'share', '{1,2,3,4,5,6,7}', '{5,7}');"
        "SELECT pg_temp.sees('3', 'SELECT doc_no::text FROM alt.docs ORDER BY 1', '{5,6,7}');"
        "DELETE FROM alt.doc_links WHERE child = 6; INSERT INTO alt.doc_links VALUES (6, 1);"
        "SELECT pg_temp.expect('1', 'doc', 'view', '{1,2,3,4,5,6,7}', '{1,3,6}');"
        "SELECT pg_temp.expect('3', 'doc', 'view', '{1,2,3,4,5,6,7}', '{5,7}');"
        "SELECT pg_temp.sees('1', 'SELECT doc_no::text FROM alt.docs ORDER BY 1', '{1,3,6}');",
    ),
    (
        "inheritance across two types whose only condition is a link table's where: a link it leaves out passes nothing",
        "  project : project = alt.proj_links(doc_no -> proj_id) where {active}\n"
        "  can view = owner or parent.view or project.view\n"
        "type project = alt.projects\n  lead : user = lead_id\n  docs : doc = alt.doc_projects(proj_id -> doc_no)\n"
        "  can view = lead or docs.view\n",
        {},
        ANSWERS + "INSERT INTO alt.users VALUES (1), (2), (3); INSERT INTO alt.projects VALUES (1, 3), (2, NULL);"
        "INSERT INTO alt.docs (doc_no, owner_id) VALUES (1, 1), (2, NULL), (3, NULL), (4, NULL);"
        "INSERT INTO alt.doc_projects VALUES (1, 2);"
        "INSERT INTO alt.proj_links (doc_no, proj_id, active) VALUES (2, 1, true), (3, 1, false), (4, 2, true);"
        "SELECT pg_temp.expect('1', 'doc', 'view', '{1,2,3,4}', '{1,4}');"
        "SELECT pg_temp.expect('1', 'project', 'view', '{1,2}', '{2}');"
        "SELECT pg_temp.expect('3', 'doc', 'view', '{1,2,3,4}', '{2}');"
        "SELECT pg_temp.expect('3', 'project', 'view', '{1,2}', '{1}');"
        "SELECT pg_temp.expect('2', 'doc', 'view', '{1,2,3,4}', '{}');"
        "UPDATE alt.proj_links SET active = true WHERE doc_no = 3;"
        "SELECT pg_temp.expect('3', 'doc', 'view', '{1,2,3,4}', '{2,3}');",
    ),
    (
        "every type keyed by text",
        "app role app_user\ntype user = alt.tusers (id text)\ntype doc = alt.tdocs (id text)\n"
        "  owner  : user = owner_id\n  parent : doc = parent_id\n  viewer : user  shared\n"
        "  can share = owner or parent.share\n  can view = share or viewer or parent.view\n"
        "rules alt.tdocs\n  select : view\n",
        {},
        ANSWERS + "INSERT INTO alt.tusers VALUES ('ann'), ('bo');"
        "INSERT INTO alt.tdocs VALUES ('a', 'ann', NULL), ('c', 'bo', NULL), ('d', NULL, NULL), ('b', NULL, 'a'),"
        " ('e', NULL, 'd');"
        "SET authz.user_id = 'bo'; SELECT authz.share('doc', 'c', 'viewer', 'user', 'ann'); RESET authz.user_id;"
        "INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id)"
        " VALUES ('doc', 'd', 'viewer', 'user', 'bo');"
        "SELECT pg_temp.expect('ann', 'doc', 'view', '{a,b,c,d,e}', '{a,b,c}');"
        "SELECT pg_temp.expect('bo', 'doc', 'view', '{a,b,c,d,e}', '{c,d,e}');"
        "SELECT pg_temp.expect('', 'doc', 'view', '{a,b,c,d,e}', '{}');"
        "SELECT pg_temp.expect('ann', 'doc', 'share', '{a,b,c,d,e}', '{a,b}');"
        "SELECT pg_temp.sees('ann', 'SELECT id FROM alt.tdocs ORDER BY 1', '{a,b,c}');",
    ),
    (
        "no permission at all, and a rule on a relation to users and to objects: its users",
        "app role app_user\ntype user = alt.users\ntype doc = alt.docs (doc_no)\n  watcher : user = owner_id\n"
        "  watcher : doc = alt.doc_links(child -> parent)\nrules alt.docs\n  select : watcher\n",
        {},
        ANSWERS + "INSERT INTO alt.users VALUES (1), (2);"
        "INSERT INTO alt.docs (doc_no, owner_id) VALUES (1, 1), (2, NULL), (3, 2);"
        "INSERT INTO alt.doc_links VALUES (2, 1), (3, 1);"
        "SELECT pg_temp.sees('1', 'SELECT doc_no::text FROM alt.docs ORDER BY 1', '{1}');"
        "SELECT pg_temp.sees('2', 'SELECT doc_no::text FROM alt.docs ORDER BY 1', '{3}');"
        "SELECT pg_temp.sees('', 'SELECT doc_no::text FROM alt.docs ORDER BY 1', '{}');",
    ),
    (
        "a link table naming objects of two types keyed by two columns: the audit names each by its key",
        "  pinned : space, room = alt.pins(doc_no -> (kind, [org, ref]))\n  can view = owner or pinned.see\n"
        "type space = alt.spaces (org, id)\n  keeper : user = keeper_id\n  can see = keeper\n"
        "type room = alt.rooms (org, id)\n  keeper : user = keeper_id\n  can see = keeper\n",
        {},
        ANSWERS + "INSERT INTO alt.users VALUES (1), (2);"
        "INSERT INTO alt.spaces VALUES (1, 2, 1); INSERT INTO alt.rooms VALUES (1, 2, 2);"
        "INSERT INTO alt.docs (doc_no) VALUES (10), (11);"
        "INSERT INTO alt.pins VALUES (10, 'space', 1, 2), (11, 'room', 1, 2);"
        "SELECT pg_temp.expect('1', 'doc', 'view', '{10,11}', '{10}');"
        "SELECT pg_temp.expect('2', 'doc', 'view', '{10,11}', '{11}');"
        "DO $$ BEGIN IF ARRAY(SELECT concat_ws(' ', action, object_id, relation, subject_type, subject_id)"
        " FROM authz.audit WHERE relation = 'pinned' ORDER BY 1)"
        ' <> \'{"relate 10 pinned space (1,2)","relate 11 pinned room (1,2)"}\' THEN'
        " RAISE EXCEPTION 'the audit of alt.pins: %', ARRAY(SELECT concat_ws(' ', action, object_id, relation,"
        " subject_type, subject_id) FROM authz.audit WHERE relation = 'pinned'); END IF; END $$;",
    ),
]

# shares of a relation inheritance follows (doc.shortcut), once applied: (what, statement, refused as a link that
# would expire, start later or carry a caveat (AZ605)); `AS USER 1; ` signs in the owner of docs 1 and 2
LINKS = [
    (
        "one that expires",
        "AS USER 1; SELECT authz.share('doc', 1, 'shortcut', 'doc', 2, '', now() + interval '1 day')",
        True,
    ),
    (
        "one that starts later",
        "AS USER 1; SELECT authz.share('doc', 1, 'shortcut', 'doc', 2, '', NULL, now() + interval '1 day')",
        True,
    ),
    (
        "one with a caveat",
        "AS USER 1; SELECT authz.share('doc', 1, 'shortcut', 'doc', 2, '', NULL, NULL, 'business')",
        True,
    ),
    ("one that doesn't is given", "AS USER 1; SELECT authz.share('doc', 1, 'shortcut', 'doc', 2)", False),
    (
        "... and an expiry put on it later is refused too",
        "UPDATE authz.shares SET expires_at = now() + interval '1 day' WHERE relation = 'shortcut'",
        True,
    ),
    (
        "a share that is no link may expire",
        "AS USER 1; SELECT authz.share('doc', 1, 'reader', 'user', 1, '', now() + interval '1 day')",
        False,
    ),
]

APPLY_SETUP = """
CREATE VIEW alt.held AS SELECT target FROM alt.holds;
CREATE FUNCTION alt.is_open(bigint) RETURNS boolean LANGUAGE sql STABLE AS 'SELECT true';
CREATE TABLE alt."group" (gid bigint PRIMARY KEY, owner_id bigint);
GRANT SELECT ON alt."group" TO app_user;
CREATE VIEW alt.member_view AS SELECT group_id, user_id FROM alt.group_members;
CREATE FUNCTION alt.is_active(boolean) RETURNS boolean LANGUAGE sql IMMUTABLE AS 'SELECT $1';
CREATE TABLE alt.proj_links (doc_no bigint REFERENCES alt.docs, proj_id bigint REFERENCES alt.projects,
  active boolean NOT NULL DEFAULT true, since timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (doc_no, proj_id));
CREATE TABLE alt.tusers (id text PRIMARY KEY);
CREATE TABLE alt.tdocs (id text PRIMARY KEY, owner_id text REFERENCES alt.tusers, parent_id text REFERENCES alt.tdocs);
CREATE TABLE alt.spaces (org bigint, id bigint, keeper_id bigint, PRIMARY KEY (org, id));
CREATE TABLE alt.rooms (org bigint, id bigint, keeper_id bigint, PRIMARY KEY (org, id));
CREATE TABLE alt.pins (doc_no bigint REFERENCES alt.docs, kind text, org bigint, ref bigint);
GRANT SELECT ON alt.proj_links, alt.tusers, alt.tdocs, alt.spaces, alt.rooms, alt.pins TO app_user;
"""


# Included files passed as a map, the way the rowstile command passes them: never read from disk.
# (what, main policy, files, expected start of the message)
INCLUDES = [
    ("an include missing from the files", 'include "roles.authz"\n', {}, "line 1: can't find roles.authz"),
    (
        "a server file",
        'include "/etc/passwd"\n',
        {"/etc/passwd": BASE},
        "line 1: /etc/passwd: an included file is in the policy's folder",
    ),
    (
        "a file above the policy's folder",
        'include "sub/../../x.authz"\n',
        {"../x.authz": BASE},
        "line 1: sub/../../x.authz: an included file is in the policy's folder",
    ),
    (
        "a file above, from an included file",
        'include "sub/a.authz"\n',
        {"sub/a.authz": 'include "../../x.authz"\n', "../x.authz": BASE},
        "sub/a.authz line 1: ../../x.authz: an included file is in the policy's folder",
    ),
    (
        "a backslash",
        'include "sub\\x.authz"\n',
        {"sub\\x.authz": BASE},
        "line 1: sub\\x.authz: an included file is in the policy's folder",
    ),
    (
        "a drive",
        'include "C:x.authz"\n',
        {"C:x.authz": BASE},
        "line 1: C:x.authz: an included file is in the policy's folder",
    ),
    (
        "a mistake in an included file names that file",
        'include "sub/x.authz"\n',
        {"sub/x.authz": BASE + "  can view = no_such_name\n"},
        "sub/x.authz line 10:",
    ),
    (
        "an include resolved from the including file's folder",
        'include "sub/a.authz"\n',
        {"sub/a.authz": 'include "b.authz"\n', "b.authz": BASE},
        "sub/a.authz line 1: can't find b.authz",
    ),
    (
        "the same file twice",
        'include "a.authz"\ninclude "a.authz"\n',
        {"a.authz": BASE},
        "line 2: a.authz is included twice",
    ),
]


# named tests (compiled with their SQL): (what, text appended to BASE, expected piece of the message, expected line)
TESTS = [
    ("a $name used before a given names it", 'test "t"\n  user $ann can share doc 1\n', "$ann is not named yet", 11),
    (
        "... also inside a statement",
        'test "t"\n  as user 1 refused {INSERT INTO alt.docs VALUES ($doc)}\n',
        "$doc is not named yet",
        11,
    ),
    (
        "acting as a type that doesn't sign in",
        'test "t"\n  given g = {SELECT 1}\n  grp $g can share doc 1\n',
        "'grp' doesn't sign in",
        12,
    ),
    ("a line that is none of a test's", 'test "t"\n  user 1 maybe share doc 1\n', "a test's lines are", 11),
    (
        "a scope the policy doesn't have",
        'test "t"\n  user 1 with scope files can share doc 1\n',
        "no scope 'files' in the policy (it has: read)",
        11,
    ),
    (
        "... also on a statement",
        'test "t"\n  as user 1 with scope read, files sees 0 {SELECT 1}\n',
        "no scope 'files' in the policy",
        11,
    ),
    (
        "a scope for nobody",
        'test "t"\n  anyone with scope read can share doc 1\n',
        "`anyone` is nobody signed in",
        11,
    ),
    ("with scope and no scope", 'test "t"\n  user 1 with scope can share doc 1\n', "a test's lines are", 11),
    ("a test with no lines", 'test "t"\n', "test 't' has no lines", 10),
    (
        "two tests with one name",
        'test "a"\n  user 1 can share doc 1\ntest "a"\n  user 1 can share doc 1\n',
        "already a test named 'a'",
        12,
    ),
    (
        "a permission that doesn't exist, in a named test",
        'test "t"\n  user 1 can edit doc 1\n',
        "doc has no permission 'edit'",
        11,
    ),
    (
        "the test section acting as a type that doesn't sign in",
        "test\n  grp 1 can share doc 1\n",
        "'grp' doesn't sign in",
        11,
    ),
    (
        "the test section acting as a type that isn't there",
        "test\n  bot 1 can share doc 1\n",
        "'bot' doesn't sign in",
        11,
    ),
    (
        "a statement in the test section",
        "test\n  as user 1 allowed {SELECT 1}\n",
        "the test section checks the data already there",
        11,
    ),
    ("a $name in the test section", "test\n  user $ann can share doc 1\n", "$ann is not named yet", 11),
    (
        "sees N on a statement that writes",
        'test "t"\n  as user 1 sees 0 {UPDATE alt.docs SET up = NULL RETURNING doc_no}\n',
        "`sees N` counts the rows of a SELECT, and this statement writes",
        11,
    ),
]


def compile_policy(text: str, tests: bool = False, files: dict[str, str] | None = None) -> str:
    c = Compiler(parse_policy(text, files=files))
    return c.compile_tests("t") if tests else c.compile("t")


def main() -> None:
    db = sys.argv[sys.argv.index("--db") + 1] if "--db" in sys.argv else "authz_errors"
    os.chdir(os.path.dirname(HERE))
    fails = 0
    for what, extra, want, line in COMPILE:
        try:
            compile_policy(BASE + extra)
            got = "(compiled without error)"
        except PolicyError as e:
            got = str(e)
        ok = want in got and (line is None or got.startswith(f"line {line}:")) and coded(got)
        fails += not ok
        print(f"{'ok  ' if ok else 'FAIL'}  {what}: {got}")
    for what, text, want, line in WHOLE:
        try:
            compile_policy(text)
            got = "(compiled without error)"
        except PolicyError as e:
            got = str(e)
        ok = want in got and got.startswith(f"line {line}:") and coded(got)
        fails += not ok
        print(f"{'ok  ' if ok else 'FAIL'}  {what}: {got}")

    try:
        compile_policy(BASE + "  can view = owner\ntest\n  user 1 can edit doc 1\n", tests=True)
        got = "(compiled without error)"
    except PolicyError as e:
        got = str(e)
    ok = "doc has no permission 'edit'" in got and coded(got)
    fails += not ok
    print(f"{'ok  ' if ok else 'FAIL'}  a test of a permission that doesn't exist: {got}")

    for what, extra, want, line in TESTS:
        try:
            compile_policy(BASE + extra, tests=True)
            got = "(compiled without error)"
        except PolicyError as e:
            got = str(e)
        ok = want in got and got.startswith(f"line {line}:") and coded(got)
        fails += not ok
        print(f"{'ok  ' if ok else 'FAIL'}  named tests: {what}: {got}")
    try:
        c = Compiler(parse_policy(BASE))
        c.add_test_files({"more.authz": "type x = alt.x\n"})
        got = "(compiled without error)"
    except PolicyError as e:
        got = str(e)
    ok = got.startswith("more.authz: a test file holds only named tests") and coded(got)
    fails += not ok
    print(f"{'ok  ' if ok else 'FAIL'}  named tests: a test file with a type in it: {got}")
    try:
        c = Compiler(parse_policy(BASE))
        c.add_test_files({"more.authz": 'test "t"\n  user 1 can view doc 1\n'})
        c.tests_function_sql()
        got = "(compiled without error)"
    except PolicyError as e:
        got = str(e)
    ok = got.startswith("more.authz line 2: doc has no permission 'view'") and coded(got)
    fails += not ok
    print(f"{'ok  ' if ok else 'FAIL'}  named tests: a mistake in a test file names the file: {got}")

    for what, main_text, files, want in INCLUDES:
        try:
            compile_policy(main_text, files=files)
            got = "(compiled without error)"
        except PolicyError as e:
            got = str(e)
        ok = got.startswith(want) and coded(got)
        fails += not ok
        print(f"{'ok  ' if ok else 'FAIL'}  included files: {what}: {got}")
    try:
        compile_policy('include "sub/a.authz"\n', files={"sub/a.authz": 'include "b.authz"\n', "sub/b.authz": BASE})
        got = ""
    except PolicyError as e:
        got = str(e)
    fails += bool(got)
    print(f"{'ok  ' if not got else 'FAIL'}  included files: nested includes compile{': ' + got if got else ''}")

    subprocess.run(["dropdb", "--if-exists", db], capture_output=True)
    subprocess.run(["createdb", db], check=True, capture_output=True)
    for what, extra, want in APPLY:
        subprocess.run(
            ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", db, "-f", "tests/alt_schema.sql"],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", db, "-c", APPLY_SETUP], check=True, capture_output=True
        )
        sql = compile_policy(BASE + extra)
        p = subprocess.run(
            ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", db], input=sql, capture_output=True, text=True
        )
        err = next((ln for ln in p.stderr.splitlines() if "ERROR" in ln), "(applied without error)")
        ok = p.returncode != 0 and want in p.stderr and re.search(r"\[AZ6\d\d\]", p.stderr) is not None
        fails += not ok
        print(f"{'ok  ' if ok else 'FAIL'}  applying {what}: {err.split('ERROR:', 1)[-1].strip()}")
    for what, extra, env, *after in APPLY_OK:
        subprocess.run(
            ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", db, "-f", "tests/alt_schema.sql"],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", db, "-c", APPLY_SETUP], check=True, capture_output=True
        )
        try:
            sql = compile_policy(extra if extra.startswith("app role ") else BASE + extra)
            p = subprocess.run(
                ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", db],
                input=sql + "\nSELECT authz.verify();\n" + "".join(after),
                capture_output=True,
                text=True,
                env={**os.environ, **env},
            )
            err = next((ln for ln in p.stderr.splitlines() if "ERROR" in ln), "")
            ok = p.returncode == 0
        except PolicyError as e:
            ok, err = False, str(e)
        fails += not ok
        print(f"{'ok  ' if ok else 'FAIL'}  {what}{': ' + err if err else ''}")
    # a shared relation with expiring shares can't later become a link for inheritance
    reset = lambda: [
        subprocess.run(
            ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", db, "-f", "tests/alt_schema.sql"],
            check=True,
            capture_output=True,
        )
    ]
    v1 = compile_policy(BASE + "  shortcut : doc shared\n  can view = owner or shortcut.owner\n")
    v2 = compile_policy(BASE + "  shortcut : doc shared\n  can view = owner or shortcut.view\n")
    # beside a share that never ends nor starts later (which may become a link), one that expires, or one that starts
    # later: only that one is counted
    for what, when in (
        ("expiring", "now() + interval '1 day', NULL"),
        ("starting later", "NULL, now() + interval '1 day'"),
    ):
        reset()
        setup = (
            "INSERT INTO alt.users VALUES (1); INSERT INTO alt.docs (doc_no, owner_id) VALUES (1, 1), (2, 1), (3, 1);"
            "INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id, subject_relation,"
            f" expires_at, starts_at) VALUES ('doc', 1, 'shortcut', 'doc', 2, '', {when}),"
            " ('doc', 3, 'shortcut', 'doc', 2, '', NULL, NULL);"
        )
        subprocess.run(
            ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", db],
            input=v1 + setup,
            check=True,
            capture_output=True,
            text=True,
        )
        p = subprocess.run(
            ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", db], input=v2, capture_output=True, text=True
        )
        want = (
            "1 existing shares of doc.shortcut have an expiry, a start time or a caveat, but links used for inheritance"
            " cannot"
        )
        ok = p.returncode != 0 and want in p.stderr and "[AZ605]" in p.stderr
        fails += not ok
        err = next((ln for ln in p.stderr.splitlines() if "ERROR" in ln), "(applied without error)")
        print(
            f"{'ok  ' if ok else 'FAIL'}  turning {what} shares into inheritance links: "
            f"{err.split('ERROR:', 1)[-1].strip()}"
        )
    # ... and once they are links, giving one that would expire, start later or carry a caveat is refused (a
    # trigger on authz.shares), at the share API and when a share that is there is changed; other shares may
    v3 = compile_policy(
        BASE
        + "  shortcut : doc shared\n  can view = owner or shortcut.view\ncaveat business = {authz.ctx('mode') = 'b'}\n"
    )
    subprocess.run(
        ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", db],
        input="DELETE FROM authz.shares WHERE relation = 'shortcut';\n" + v3,
        check=True,
        capture_output=True,
        text=True,
    )
    # what an app meets: the words, and the code in the HINT (as every error the runtime raises)
    link = "23514: doc.shortcut links are used for inheritance, so they cannot expire, start later or have a caveat"
    signed = "SET ROLE app_user; SET authz.user_id = '1'; "  # the owner of both docs
    for what, sql, want in LINKS:
        p = subprocess.run(
            ["psql", "-X", "-q", "-v", "VERBOSITY=verbose", "-d", db, "-c", sql.replace("AS USER 1; ", signed)],
            capture_output=True,
            text=True,
        )
        err = next((ln.split("ERROR:", 1)[1].strip() for ln in p.stderr.splitlines() if "ERROR:" in ln), "")
        hint = next((ln.split("HINT:", 1)[1].strip() for ln in p.stderr.splitlines() if "HINT:" in ln), "")
        ok = (err, hint) == ((link, "rowstile help AZ605") if want else ("", ""))
        fails += not ok
        print(
            f"{'ok  ' if ok else 'FAIL'}  inheritance links: {what}: {err or '(no error)'}{f' (HINT: {hint})' * bool(hint)}"
        )

    subprocess.run(["dropdb", db], capture_output=True)
    total = (
        len(COMPILE) + len(WHOLE) + 1 + len(TESTS) + 2 + len(INCLUDES) + 1 + len(APPLY) + len(APPLY_OK) + 2 + len(LINKS)
    )
    print(f"policy errors: {total - fails} of {total} cases behave as expected")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
