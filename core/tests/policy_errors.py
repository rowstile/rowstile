#!/usr/bin/env python3
"""policy_errors: mistakes in a policy are reported clearly. Each case asks for the message's words, the line it
names and its code, the one whose page `rowstile help` shows.

    python3 tests/policy_errors.py [--db authz_errors]

Compile-time cases need nothing else. Apply-time cases (the database is the only
one who knows) run against tests/alt_schema.sql in a scratch database, and so do policies that must apply although
their names are awkward. Answers worked out by hand from the reference are in tests/hand/, not here.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import re  # noqa: E402

from authzlib import Compiler, PolicyError, parse_policy  # noqa: E402
from authzlib.errors import CODES, split  # noqa: E402
from authzlib.governance import trigger_if_table  # noqa: E402


def coded(message: str, code: str) -> bool:
    """The message ends with the code the case is about (authzlib/errors.py): `rowstile help` sends the user to that
    code's page."""
    assert code in CODES, code
    return split(message.strip())[1] == code


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

# (what, policy text appended to BASE, expected piece of the message, the line it names, its code)
COMPILE = [
    (
        "custom roles held by a group through a relation named shared: read as the relation, which isn't there",
        "  roles : grp#shared\n  can edit = roles\n",
        "doc.roles:edit: grp has no relation or permission 'shared'",
        10,
        "AZ203",
    ),
    (
        "custom roles with `from` written against a comma: no from, a subject that isn't one",
        "  roles : user,from grp\n  can edit = roles\n",
        "bad subject 'from grp'",
        10,
        "AZ103",
    ),
    (
        "a relation shared by no subjects, two spaces after its colon",
        "  watcher :  shared\n  can edit = watcher\n",
        "bad subject ''",
        10,
        "AZ103",
    ),
    (
        "a dollar-quote tag in a condition",
        "  can see = owner and {up <> 0 or '$f$' = ''}\n",
        "contains $f$, which ends the generated function it goes in",
        10,
        "AZ110",
    ),
    (
        "a name that starts with authz__ in a condition",
        '  can see = owner and {not exists (select 1 from alt.holds "authz__h" where "authz__h".target = this.doc_no)}\n',
        'names "authz__h": names that start with authz__ are rowstile\'s own',
        10,
        "AZ113",
    ),
    (
        "a character that doesn't print, shown escaped",
        "  can see = owner \x01\n",
        "unexpected '\\x01' in expression",
        10,
        "AZ102",
    ),
    (
        "a typo in a relation's only use: the typo is named, not the relation as unused",
        "  editor : user = owner_id\n  can edit = editr\n",
        "doc has no relation or permission 'editr'",
        11,
        "AZ203",
    ),
    (
        "custom roles from a shared relation",
        "  roles : user from reader\n  can view = owner or roles\n",
        "custom roles on doc come from 'reader', which must be a relation of doc kept in a column or a table",
        10,
        "AZ211",
    ),
    (
        "custom roles from a relation that isn't there",
        "  roles : user from org\n  can view = owner or roles\n",
        "custom roles on doc come from 'org'",
        10,
        "AZ211",
    ),
    (
        "roles under a not",
        "  roles : user\n  can view = owner and not roles\n",
        "doc.view: `not roles` would take a permission away",
        11,
        "AZ210",
    ),
    ("a roles line no permission uses", "  roles : user\n", "no permission writes `roles`", 10, "AZ210"),
    (
        "roles in a type without a roles line",
        "  can view = owner or roles\n",
        "doc.view writes `roles`, but doc has no `roles : ...` line",
        10,
        "AZ210",
    ),
    (
        "roles in a rule",
        "  roles : user\n  can view = owner or roles\nrules alt.docs\n  select : view or roles\n",
        "`roles` goes in a permission, which says what a custom role gives",
        13,
        "AZ210",
    ),
    (
        "roles in an invariant",
        "  roles : user\n  can view = owner or roles\ninvariants\n  never doc: roles\n",
        "`roles` goes in a permission",
        13,
        "AZ210",
    ),
    (
        "roles followed by a dot",
        "  roles : user\n  can view = owner or roles.view\n",
        "doc.view: `roles` gives the permission it is written in; it isn't a relation to follow",
        11,
        "AZ210",
    ),
    (
        "a relation named roles",
        "  roles : user = owner_id\n",
        "`roles : ...` says who may hold custom roles; name the relation something else",
        10,
        "AZ107",
    ),
    (
        "a permission named roles",
        "  can roles = owner\n",
        "'roles' is where custom roles give a permission",
        10,
        "AZ107",
    ),
    (
        "a relation named like a word that continues a line",
        "  where : user = owner_id\n",
        "'where' is a word of the language",
        10,
        "AZ107",
    ),
    ("a relation named and", "  and : user = owner_id\n", "'and' is a word of the language", 10, "AZ107"),
    ("a permission named or", "  can or = owner\n", "'or' is a word of the language", 10, "AZ107"),
    (
        "a plain update rule written with before",
        "rules alt.docs\n  update before : share\n",
        "a plain update rule is checked on the row before and after",
        11,
        "AZ105",
    ),
    (
        "anyone or link with a relation",
        "type thing = alt.docs (doc_no)" + chr(10) + "  viewer : user, link#member  shared" + chr(10),
        "link stands alone",
        11,
        "AZ204",
    ),
    (
        "a type named like a special subject",
        "type anyone = alt.docs (doc_no)" + chr(10),
        "subject of its own",
        10,
        "AZ204",
    ),
    ("unknown subject type", "  editor : robot = owner_id\n", "unknown type 'robot'", 10, "AZ201"),
    (
        "unknown group relation",
        "  editor : grp#admin shared\n",
        "grp has no relation or permission 'admin'",
        10,
        "AZ203",
    ),
    (
        "unknown name in a permission",
        "  can view = owner or viewer\n",
        "doc has no relation or permission 'viewer'",
        10,
        "AZ203",
    ),
    (
        "following a permission with a dot",
        "  can view = owner\n  can edit = view.x\n",
        "'view' is a permission; only relations can be followed",
        11,
        "AZ301",
    ),
    (
        "a permission with a deny that depends on itself through another of its type: named as written",
        "  blocked : user = owner_id\n  can edit = owner or parent.view\n"
        "  can view = (owner or edit or parent.view) and not blocked\n",
        "doc.view depends on itself; a permission can only recurse as 'or rel.perm'",
        12,
        "AZ302",
    ),
    (
        "following a relation to users, to something they don't have (they have nothing)",
        "  can view = owner.view\n",
        "user has no relation or permission 'view' (it has none)",
        10,
        "AZ203",
    ),
    (
        "following a relation to groups",
        "  can view = reader.member\n",
        "doc.reader links to groups, anyone or links, so there is nothing to follow",
        10,
        "AZ301",
    ),
    (
        "following a relation shared with anyone",
        "  pub : anyone shared by share\n  can see = owner\n  can view = pub.see\n",
        "doc.pub links to groups, anyone or links, so there is nothing to follow",
        12,
        "AZ301",
    ),
    (
        "... with a link",
        "  pub : link shared by share\n  can see = owner\n  can view = pub.see\n",
        "doc.pub links to groups, anyone or links, so there is nothing to follow",
        12,
        "AZ301",
    ),
    (
        "... with every signed-in user",
        "  pub : user:* shared by share\n  can see = owner\n  can view = pub.see\n",
        "doc.pub links to groups, anyone or links, so there is nothing to follow",
        12,
        "AZ301",
    ),
    (
        "using a link as if it held users",
        "  can view = parent\n",
        "doc.parent links to doc objects, not users; follow it with a dot",
        10,
        "AZ301",
    ),
    (
        "permissions that depend on each other",
        "  can a = owner or b\n  can b = a\n",
        "doc.b depends on itself",
        11,
        "AZ302",
    ),
    (
        "inheritance with no starting point",
        "  can view = parent.view\n",
        "doc.view needs a starting point besides inheritance",
        10,
        "AZ303",
    ),
    (
        "inheritance narrowed by something other than a condition",
        "  can view = owner or (parent.view and reader)\n",
        "inheritance through parent can only be narrowed with {conditions}",
        10,
        "AZ304",
    ),
    (
        "inheritance that depends on the time",
        "  can view = owner or (parent.view and {created_at > now() - interval '1 day'})\n",
        "can't limit inheritance: it depends on now",
        10,
        "AZ305",
    ),
    (
        "inheritance that depends on the time, after a $$ string holding an apostrophe",
        "  can view = owner or (parent.view and {title <> $$it's$$ and created_at > now() and title <> 'x'})\n",
        "can't limit inheritance: it depends on now",
        10,
        "AZ305",
    ),
    (
        "inheritance that depends on the time, after an E'' string holding an escaped quote",
        "  can view = owner or (parent.view and {title <> E'it\\'s' and created_at > now() and title <> 'x'})\n",
        "can't limit inheritance: it depends on now",
        10,
        "AZ305",
    ),
    (
        "inheritance that depends on the time, after names and a dollar quote past ASCII",
        "  can view = owner or (parent.view and {titré$$ <> $é$it's$é$ and créé > now() and titré$$ <> 'x'})\n",
        "can't limit inheritance: it depends on now",
        10,
        "AZ305",
    ),
    (
        "inheritance that depends on the time, written as a $$ string",
        "  can view = owner or (parent.view and {created_at > $$ today $$::date})\n",
        "can't limit inheritance: 'today' means the current time",
        10,
        "AZ305",
    ),
    (
        "inheritance that depends on the user",
        "  can view = owner or (parent.view and {owner_id <> authz.uid()})\n",
        "can't limit inheritance: it depends on authz.uid",
        10,
        "AZ305",
    ),
    (
        "inheritance that depends on the time through age(), beside a subquery, where applying wouldn't find it",
        "  can view = owner or (parent.view and {age(created) < interval '1 year' and not exists "
        "(select 1 from alt.holds h where h.target = this.doc_no)})\n",
        "can't limit inheritance: it depends on age() with one argument, which counts from today",
        10,
        "AZ305",
    ),
    (
        "a group made only of itself",
        "type team = alt.groups (gid)\n  member : team#member shared by x\n  can x = member\n",
        "team.member only contains itself; add a source of users",
        11,
        "AZ209",
    ),
    (
        "a relation defined as a permission too",
        "  can view = owner\n  view : user = owner_id\n",
        "doc.view is already a permission",
        11,
        "AZ109",
    ),
    (
        "two kinds of subject on a column",
        "  editor : user, grp#member = owner_id\n",
        "a column or table source links to exactly one kind of subject",
        10,
        "AZ205",
    ),
    (
        "a rule for a table with no type",
        "rules alt.nothing\n  select : view\n",
        "rules for alt.nothing, but no type maps to that table",
        11,
        "AZ401",
    ),
    (
        "update after without update",
        "  can view = owner\nrules alt.docs\n  select : view\n  update after : view\n",
        "'update after' refines updates, so alt.docs needs an 'update' rule too",
        13,
        "AZ403",
    ),
    (
        "a relation named like a word of the language",
        "  nobody : user = owner_id\n  can view = nobody\n",
        "'nobody' is a word of the language",
        10,
        "AZ107",
    ),
    ("a permission named anyone", "  can anyone = owner\n", "'anyone' is a word of the language", 10, "AZ107"),
    (
        "and next to or",
        "  can view = owner or parent.owner and {not locked}\n",
        "`and` and `or` meet without parentheses, which reads two ways: write owner or (parent.owner and {not locked})",
        10,
        "AZ102",
    ),
    (
        "and next to or, the other way",
        "  can view = not {locked} and owner or anyone\n",
        "write (not {locked} and owner) or anyone",
        10,
        "AZ102",
    ),
    (
        "and next to or across a continuation line",
        "  can view = owner\n           or parent.owner and {not locked}\n",
        "write owner or (parent.owner and {not locked})",
        10,
        "AZ102",
    ),
    (
        "a word after an update rule's column that is neither before nor after",
        "  can view = owner\nrules alt.docs\n  select : view\n  update : view\n  update up check : view\n",
        "write column rules as: update col1, col2 : expression   (or: update col after : expression)",
        14,
        "AZ105",
    ),
    (
        "custom roles with grant after their subjects: a subject that isn't one",
        "  roles : user grant view\n  can view = owner or roles\n",
        "bad subject 'user grant view'",
        10,
        "AZ103",
    ),
    (
        "before or after on a command other than update",
        "  can view = owner\nrules alt.docs\n  select after : view\n",
        "only update rules can name columns, 'before' or 'after'",
        12,
        "AZ105",
    ),
    (
        "a relation nothing uses (a typo for a second source)",
        "  reader : grp#member = alt.doc_groups(doc_no -> gid)\n  raeder : user = alt.doc_readers(doc_no -> user_id)\n"
        "  can view = owner or reader\n",
        "doc.raeder is declared but nothing uses it",
        11,
        "AZ208",
    ),
    (
        "shared without a share permission to share it",
        "type memo = alt.docs (doc_no)\n  owner : user = owner_id\n  reader : user  shared\n  can view = owner or reader\n",
        "memo.reader is shared, which needs a share permission on memo",
        12,
        "AZ207",
    ),
    (
        "a column rule on select",
        "  can view = owner\nrules alt.docs\n  select owner_id : view\n",
        "only update rules can name columns",
        12,
        "AZ105",
    ),
    (
        "the same rule twice",
        "  can view = owner\nrules alt.docs\n  select : view\n  select : owner\n",
        "alt.docs has two 'select' rules",
        13,
        "AZ109",
    ),
    ("an expression that doesn't parse", "  can view = owner or (parent.view and {x}\n", "missing )", 10, "AZ102"),
    ("an unclosed condition", "  can view = owner or {x = 1\n", "a { condition is missing its closing }", 10, "AZ102"),
    ("a badly written relation", "  editor user = owner_id\n", "write relations as", 10, "AZ103"),
    (
        "a name with the separator generated names use",
        "type my__doc = alt.docs (doc_no)\n",
        "'my__doc': names with '__' are generated ones, which a policy can't use",
        10,
        "AZ107",
    ),
    (
        "brackets for a key of one column",
        "  dp : grp = [owner_id, up]\n",
        "the subject is of type grp, whose key is one column, but this source gives 2 columns [AZ206]",  # (no brackets)
        10,
        "AZ206",
    ),
    (
        "one column for a composite key",
        "type pair = alt.doc_links (child, parent)\ntype thing = alt.docs (doc_no)\n  p : pair = up\n  can view = p.x\n",
        "the subject is of type pair, whose key is [child, parent], but this source gives 1 column: write them in square brackets",
        12,
        "AZ206",
    ),
    (
        "a composite key with a timestamp",
        "type ev = alt.docs (doc_no, created timestamptz)\n",
        "created is timestamptz: a composite key's columns must be",
        10,
        "AZ206",
    ),
    (
        "a badly written key",
        "type ev = alt.docs (doc_no bigint uuid)\n",
        "write the key as (column [type])",
        10,
        "AZ206",
    ),
    (
        "type:* of a type that doesn't sign in",
        "  sh : user, grp:*  shared\n  can view = owner or sh\n",
        "grp:* means any signed-in grp, but grp doesn't sign in",
        10,
        "AZ204",
    ),
    (
        "a principal type with a composite key",
        "type svc = alt.doc_links (child, parent) principal\n",
        "the svc type signs in, so it needs a key of one column",
        10,
        "AZ206",
    ),
    (
        "referring to a generated name",
        "  can view = owner or parent.view__base\n",
        "names with '__' are generated ones",
        10,
        "AZ107",
    ),
    (
        "a deny that doesn't cover what is below",
        "  can denied = owner\n  can view = (reader or parent.view) and not denied\n",
        "`not denied` must cover everything below, so denied must inherit through parent",
        11,
        "AZ306",
    ),
    (
        "a deny that inherits through the same relation on another condition",
        "  can denied = owner or (parent.denied and {INHERIT})\n"
        "  can view = (reader or (parent.view and {inherit})) and not denied\n",
        "so denied must inherit through parent wherever view does, and its conditions there are not view's: "
        "view inherits with {inherit}, denied with {INHERIT}. Write them as view's are written, or leave them out",
        11,
        "AZ306",
    ),
    (
        "a deny that inherits through the same relation on more conditions",
        "  can denied = owner or (parent.denied and {inherit} and {up > 0})\n"
        "  can view = (reader or (parent.view and {inherit})) and not denied\n",
        "view inherits with {inherit}, denied with {inherit} and {up > 0}",
        11,
        "AZ306",
    ),
    (
        "a deny by a relation",
        "  blocked : user = owner_id\n  can view = (reader or parent.view) and not blocked\n",
        "blocked is a relation: make a permission that inherits",
        11,
        "AZ306",
    ),
    (
        "a deny that has a deny of its own",
        "  can gone = owner or parent.gone\n  can denied = (reader or parent.denied) and not gone\n"
        "  can view = (owner or parent.view) and not denied\n",
        "denied has a deny of its own, which can cut it below a denied object",
        12,
        "AZ306",
    ),
    (
        "rules for a table two types map to",
        "type doc2 = alt.docs (doc_no)\n  owner : user = owner_id\n  can see = owner\nrules alt.docs\n  select : see\n",
        "rules for alt.docs, which types doc and doc2 both map to",
        14,
        "AZ401",
    ),
    (
        "a scope naming a generated permission",
        "  can view = (owner or parent.view) and not share\nscope s = doc.view__base\n",
        "names with '__' are generated ones",
        11,
        "AZ107",
    ),
    (
        "a deny through a link, not a permission",
        "  can denied = owner or parent.denied\n  can view = (reader or parent.view) and not parent.denied\n",
        "a deny on it is `not <permission of doc>`",
        11,
        "AZ306",
    ),
    (
        "inheritance joined with another permission",
        "  can view = (reader or parent.view) and owner\n",
        "can only join its inheritance with {conditions} and `not <permission>`",
        10,
        "AZ304",
    ),
    (
        "inheritance limited by the literal 'now'",
        "  can view = owner or (parent.view and {'now'::timestamptz > created})\n",
        "'now' means the current time",
        10,
        "AZ305",
    ),
    (
        "an inheritance link table filtered by time",
        "  linked : doc = alt.doc_links(child -> parent) where {now() > '2000-01-01'}\n  can view = owner or linked.view\n",
        "can't limit inheritance: it depends on now",
        10,
        "AZ305",
    ),
    (
        "following a relation to two types when one lacks the permission",
        "  holder : doc, grp = (holder_type, holder_id)\n  can view = owner or holder.view\n",
        "grp has no relation or permission 'view'",
        11,
        "AZ203",
    ),
    (
        "user:* on a column",
        "  editor : user:* = owner_id\n",
        "user:* (or another type:*), anyone and link can only be used with 'shared'",
        10,
        "AZ204",
    ),
    (
        "inheritance through a relation shared with anyone",
        "  shortcut : doc, anyone shared\n  can view = owner or shortcut.view\n",
        "doc.shortcut links to groups, anyone or links, so there is nothing to follow",
        11,
        "AZ301",
    ),
    (
        "a type whose where depends on the time, with inheritance",
        "  can view = owner or parent.view\ntype doc2 = alt.docs (doc_no) where {created > now()}\n"
        "  up : doc2 = up\n  owner : user = owner_id\n  can see = owner or up.see\n",
        "can't decide who inherits (the type's where): it depends on now",
        11,
        "AZ305",
    ),
    (
        "sharing by a permission that does not exist",
        "  writer : user shared by edit\n",
        "doc.writer is shared by 'edit', but doc has no such permission",
        10,
        "AZ207",
    ),
    (
        "two permissions of one type inheriting through each other",
        "  can a = owner or parent.b\n  can b = parent.a\n",
        "permissions doc.a, doc.b inherit through each other",
        11,
        "AZ302",
    ),
    (
        "an inheritance link table filtered by another table",
        "  linked : doc = alt.doc_links(child -> parent) where {exists (select 1 from alt.holds)}\n"
        "  can view = owner or linked.view\n",
        "doc.linked is used for inheritance, so its where {...} can only use the columns of alt.doc_links",
        10,
        "AZ305",
    ),
    (
        "a mask without a view",
        "  can view = owner\nrules alt.docs\n  select : view\n  mask title : owner\n",
        "masks are applied by a view: write 'rules alt.docs view <schema.view_name>'",
        13,
        "AZ402",
    ),
    (
        "a masked view without a select rule",
        "  can view = owner\nrules alt.docs view alt.docs_v\n  update : view\n",
        "the view alt.docs_v shows the rows 'select' allows, so alt.docs needs a select rule",
        11,
        "AZ402",
    ),
    (
        "a column masked twice",
        "  can view = owner\nrules alt.docs view alt.docs_v\n  select : view\n  mask title : owner\n  mask title : view\n",
        "alt.docs.title is masked twice",
        14,
        "AZ109",
    ),
    (
        "an invariant on an unknown type",
        "  can view = owner\ninvariants\n  never robot: view\n",
        "unknown type 'robot'",
        12,
        "AZ201",
    ),
    (
        "the app role named twice",
        "app role other_app\n",
        "the app role is named twice (app_user and other_app)",
        10,
        "AZ109",
    ),
    ("a scope named twice", "scope s = select\nscope s = delete\n", "scope s is defined twice", 11, "AZ109"),
    (
        "a test's name with no closing quote",
        'test "owners\n  user 1 can share doc 1\n',
        'the test\'s name has no closing ": test "owners"',
        10,
        "AZ106",
    ),
    (
        "impersonate on a type other than user",
        "  can impersonate = owner\n",
        "doc.impersonate: authz.view_as asks for `impersonate` on the user type",
        10,
        "AZ307",
    ),
    (
        "manage_keys on a type that doesn't sign in",
        "  can manage_keys = owner\n",
        "doc.manage_keys: API keys are made for types that sign in, and doc doesn't",
        10,
        "AZ307",
    ),
    (
        "break_glass with nothing to give",
        "type grp2 = alt.groups (gid)\n  boss : user = owner_id\n  can break_glass = boss\n",
        "grp2.break_glass: authz.break_glass gives its holder a relation of grp2 shared with a user",
        12,
        "AZ307",
    ),
    (
        "manage_roles with no roles to make",
        "  can manage_roles = owner\n",
        "doc.manage_roles lets people create custom roles owned by the doc, but no roles line counts them",
        10,
        "AZ307",
    ),
    (
        "roles from an owner nobody may make roles for",
        "  roles : user from parent\n  can view = owner or roles\n",
        "custom roles on doc are the roles of its parent, which people with manage_roles on it create, and doc has "
        "no `can manage_roles`",
        10,
        "AZ307",
    ),
    (
        "this in a caveat",
        "caveat near = {this.up = 1}\n",
        "caveat near: a caveat is checked with each request",
        10,
        "AZ112",
    ),
    (
        "this as a table's name in a condition",
        "  can view = owner or {exists (select 1 from alt.holds this where this.target = doc_no)}\n",
        "`this` is the row the condition is about (this.column); call the table something else",
        10,
        "AZ112",
    ),
    (
        "roles nobody may make",
        "  roles : user\n  can view = owner or roles\n",
        "custom roles on doc are made by people with manage_roles on their owner, and no type has `can manage_roles`",
        10,
        "AZ307",
    ),
    # mistakes the parser reports that no case met (the coverage report)
    ("an empty condition", "  can see = owner and {   }\n", "empty {} condition", 10, "AZ102"),
    # ... and wherever else a condition goes: left empty, a where or an if would read as none, which allows more
    ("an empty where on a type", "type t3 = alt.docs where {}\n", "empty {} condition", 10, "AZ102"),
    (
        "an empty where on a link table",
        "  viewer : user = alt.group_members(group_id -> user_id) where { }\n",
        "empty {} condition",
        10,
        "AZ102",
    ),
    ("an empty shared if", "  helper : user shared if {}\n", "empty {} condition", 10, "AZ102"),
    ("an empty caveat", "caveat c = {  }\n", "empty {} condition", 10, "AZ102"),
    ("a key column named twice", "type t2 = alt.docs (doc_no, doc_no)\n", "a key column is named twice", 10, "AZ206"),
    (
        "a link table's object side named as two columns",
        "  x : user = alt.group_members(object: (a, b), subject: user_id)\n",
        "the object side is one column",
        10,
        "AZ103",
    ),
    (
        "a link table's sides named, but not one object and one subject",
        "  x : user = alt.group_members(object: group_id, object: user_id)\n",
        "name one 'object' column and one 'subject' column",
        10,
        "AZ103",
    ),
    (
        "a table given a second view",
        "rules alt.docs view alt.v1\n  select : share\nrules alt.docs view alt.v2\n  select : share\n",
        "alt.docs already has the view alt.v1",
        12,
        "AZ109",
    ),
    (
        "two tables given the same view (applying would make it twice)",
        "rules alt.docs view alt.v\n  select : share\nrules alt.groups view alt.v\n  select : member\n",
        "alt.v is already the view of alt.docs (line 10): give alt.groups a view of its own",
        12,
        "AZ109",
    ),
    ("a caveat defined twice", "caveat c = {true}\ncaveat c = {true}\n", "caveat c is defined twice", 11, "AZ109"),
    ("a test's given without a statement", 'test "t"\n  given x = { }\n', "given {...} needs a statement", 11, "AZ106"),
    (
        "a test's as without a statement",
        'test "t"\n  as user 1 allowed { }\n',
        "as ... {...} needs a statement",
        11,
        "AZ106",
    ),
    (
        "a test named in single quotes",
        "test 'sharers'\n  user 1 can share doc 1\n",
        'line 10: write a test\'s name in double quotes: test "sharers" [AZ101]',
        10,
        "AZ101",
    ),
    (
        "a test named without quotes",
        "test sharers see docs\n  user 1 can share doc 1\n",
        'line 10: write a test\'s name in double quotes: test "sharers see docs" [AZ101]',
        10,
        "AZ101",
    ),
    (
        "a scope's command without its table",
        "scope s = docs.select\n",
        "commands are qualified by a table",
        10,
        "AZ404",
    ),
    (
        "a scope's permission under a schema",
        "scope s = alt.doc.share\n",
        "permissions are qualified by a type",
        10,
        "AZ404",
    ),
    ("custom roles declared twice", "  roles : user\n  roles : user\n", "doc declares custom roles twice", 11, "AZ109"),
    (
        "custom roles naming no one",
        "  roles :\n",
        "write custom roles as: roles : user, team#member [from org]",
        10,
        "AZ103",
    ),
    (
        "a pair of columns naming a group",
        "  x : grp#member = (kind, owner_id)\n",
        "a (type_col, id_col) source links to objects, not groups",
        10,
        "AZ205",
    ),
    (
        "a mask without columns",
        "rules alt.docs\n  select : share\n  mask : share\n",
        "write masks as: mask col1",
        12,
        "AZ105",
    ),
    (
        "a cascade line without from",
        "rules alt.docs\n  select : share\n  cascade alt.users\n",
        "write a cascade as: cascade from schema.table   (or, to say which of several keys: cascade from schema.table "
        "(column, ...)) [AZ105]",
        12,
        "AZ105",
    ),
    (
        "a cascade line whose columns don't close",
        "rules alt.docs\n  select : share\n  cascade from alt.users (owner_id\n",
        "write a cascade as: cascade from schema.table",
        12,
        "AZ105",
    ),
    (
        "a cascade line naming a column twice",
        "rules alt.docs\n  select : share\n  cascade from alt.users (owner_id, owner_id)\n",
        "cascade from alt.users: a column is named twice [AZ105]",
        12,
        "AZ105",
    ),
    (
        "a cascade line written twice, its columns in another order",
        "rules alt.docs\n  select : share\n  cascade from alt.users (owner_id, blocked_id)\n"
        "  cascade from alt.users (blocked_id, owner_id)\n",
        "cascade from alt.users is written twice under rules alt.docs [AZ109]",
        13,
        "AZ109",
    ),
    (
        "a deny on a permission that inherits through another type",
        "  project : project = project_id\n  can hidden = {locked} or parent.hidden\n"
        "  can view = (owner or parent.view or project.view) and not hidden\n"
        "type project = alt.projects\n  lead : user = lead_id\n  docs : doc = alt.doc_projects(proj_id -> doc_no)\n"
        "  can view = lead or docs.view\n",
        "doc.view has a deny, so it can only inherit within doc (like parent.view), not through permissions of other "
        "types",
        12,
        "AZ306",
    ),
    (
        "a deny on a permission that inherits through a relation to another type too",
        "  above : doc, grp = (above_type, above_id)\n  can hidden = {locked} or above.hidden\n"
        "  can view = (owner or above.view) and not hidden\n",
        "doc.view has a deny and inherits through above, which also points at other types; give those their own "
        "relation",
        12,
        "AZ306",
    ),
    (
        "a permission that depends on itself only through a not",
        "  can view = {locked} and not parent.view\n",
        "doc.view depends on itself; a permission can only recurse as 'or rel.perm' (optionally 'and {condition}')",
        10,
        "AZ302",
    ),
    (
        "inheritance narrowed by a relation, after a condition",
        "  can view = owner or ({locked} and parent.view and reader)\n",
        "inheritance through parent can only be narrowed with {conditions}",
        10,
        "AZ304",
    ),
    (
        "inheritance narrowed by a permission through another relation, written before it: the inheritance is named",
        "  also : doc = also_up\n  can view = owner or (also.share and parent.view)\n",
        "inheritance through parent can only be narrowed with {conditions} on the row, e.g. (parent.view and {inherit})",
        11,
        "AZ304",
    ),
    (
        "inheritance inside an or, inside an and",
        "  can view = owner or (reader and (parent.view or {locked}))\n",
        "doc.view depends on itself; a permission can only recurse as 'or rel.perm' (optionally 'and {condition}')",
        10,
        "AZ302",
    ),
    (
        "a group named by the permission it gives",
        "  viewer : user, doc#view  shared\n  can view = owner or viewer\n",
        "doc.view depends on itself; a permission can only recurse as 'or rel.perm' (optionally 'and {condition}')",
        11,
        "AZ302",
    ),
    (
        "two groups nested in each other",
        "type team = alt.projects\n  lead : user, team#helper shared by see\n  helper : user, team#lead shared by see\n"
        "  can see = lead or helper\n",
        "team.lead depends on itself; a permission can only recurse as 'or rel.perm' (optionally 'and {condition}') "
        "through a relation to objects, and a group only as 'member : group#member'",
        11,
        "AZ302",
    ),
    (
        "a rule following a permission with a dot, among other items",
        "rules alt.docs\n  select : owner or share.view\n",
        "'share' is a permission; only relations can be followed with a dot",
        11,
        "AZ301",
    ),
    (
        "a rule using a link as if it held users",
        "rules alt.docs\n  select : owner or parent\n",
        "doc.parent links to doc objects, not users; follow it with a dot",
        11,
        "AZ301",
    ),
    (
        "... also when the link has a column and a link table",
        "  parent : doc = alt.doc_links(child -> parent)\nrules alt.docs\n  select : owner and not parent\n",
        "doc.parent links to doc objects, not users; follow it with a dot",
        12,
        "AZ301",
    ),
    (
        "a masked view named as the table",
        "rules alt.docs view alt.docs\n  select : share\n",
        "alt.docs is a table of the policy; name a new view",
        10,
        "AZ402",
    ),
    (
        "a masked view named as another type's table",
        "rules alt.docs view alt.groups\n  select : share\n",
        "alt.groups is a table of the policy; name a new view",
        10,
        "AZ402",
    ),
    (
        "a word after a rules line's table",
        "rules alt.docs extra\n",
        "write rules as: rules schema.table [view schema.view]",
        10,
        "AZ101",
    ),
    ("a caveat without braces", "caveat c = x\n", "write caveats as: caveat name = {sql}", 10, "AZ101"),
    ("a scope without =", "scope s doc.share\n", "write scopes as: scope name = select, view", 10, "AZ101"),
    (
        "a word after invariants",
        "invariants now\n",
        "invariants is alone on its line; each invariant goes below it, indented: never folder: share",
        10,
        "AZ101",
    ),
    (
        "a scope's command on a table no type maps",
        "scope s = alt.things.select\n",
        "scope s: no type maps to alt.things",
        10,
        "AZ404",
    ),
    (
        "a scope's permission of a type that isn't there",
        "scope s = robot.view\n",
        "scope s: unknown type 'robot'",
        10,
        "AZ201",
    ),
    (
        "a scope's permission no type has",
        "scope s = frobnicate\n",
        "scope s: no type has a permission 'frobnicate'",
        10,
        "AZ404",
    ),
    (
        "a permission without its =: says how a permission is written",
        "  can view owner\n",
        "line 10: write permissions as: can name = expression [AZ104]",
        10,
        "AZ104",
    ),
    ("... nor its name", "  can = owner\n", "write permissions as: can name = expression", 10, "AZ104"),
    (
        "a block's word misspelt: the words a block starts with",
        "tpye thing = alt.things\n",
        "line 10: expected 'app role', 'type', 'rules', 'scope', 'caveat', 'sync', 'invariants', 'test', 'test \"name\"' or "
        "'include', got: tpye thing = alt.things [AZ101]",
        10,
        "AZ101",
    ),
    # the sync index (a preview)
    (
        "a sync line naming a table no type maps to",
        "sync role eng\nsync alt.nothing : share\n",
        "no type maps to alt.nothing",
        11,
        "AZ801",
    ),
    (
        "a sync line naming a table two types map to",
        "type d2 = alt.docs (doc_no)\nsync role eng\nsync alt.docs : share\n",
        "two types map to alt.docs",
        12,
        "AZ801",
    ),
    (
        "a sync line naming a permission its type hasn't",
        "sync role eng\nsync alt.docs : view\n",
        "doc has no permission view (it has: share)",
        11,
        "AZ801",
    ),
    (
        "a sync line naming no permission, for a table without a select rule",
        "sync role eng\nsync alt.docs\n",
        "the table has no select rule",
        11,
        "AZ801",
    ),
    (
        "a synced type whose key column is called key",
        "type t3 = alt.projects (key)\n  lead : user = lead_id\n  can view = lead\nsync role eng\nsync alt.projects : view\n",
        "can't be called key too",
        14,
        "AZ801",
    ),
    (
        "sync lines and no sync role",
        "sync alt.docs : share\n",
        "sync lines need the sync engine's Postgres role",
        10,
        "AZ802",
    ),
    ("a sync role and nothing synced", "sync role eng\n", "a sync role and nothing synced", 10, "AZ802"),
    (
        "the app role as the sync role",
        "sync role app_user\nsync alt.docs : share\n",
        "so it can't be the app role",
        10,
        "AZ803",
    ),
    ("PUBLIC as the sync role", "sync role Public\nsync alt.docs : share\n", "so it can't be PUBLIC", 10, "AZ803"),
    (
        "the sync role named twice",
        "sync role a\nsync role b\nsync alt.docs : share\n",
        "the sync role is named twice (a and b)",
        11,
        "AZ109",
    ),
    (
        "a table synced twice",
        "sync role a\nsync alt.docs : share\nsync alt.docs : share\n",
        "alt.docs is synced twice",
        12,
        "AZ109",
    ),
    (
        "a sync line without its colon",
        "sync role a\nsync alt.docs share\n",
        "write sync lines as: sync role name, sync after commit, or sync schema.table",
        11,
        "AZ101",
    ),
    ("a sync role line without its role", "sync role\nsync alt.docs : share\n", "write sync lines as", 10, "AZ101"),
    (
        "a sync line's by without its type",
        "sync role a\nsync alt.docs : share by\n",
        "write sync lines as: sync role name, sync after commit, or sync schema.table [: permission] [by type] [mirrored]",
        11,
        "AZ101",
    ),
    (
        "sync after commit and nothing synced",
        "sync after commit\n",
        "sync after commit and nothing synced",
        10,
        "AZ802",
    ),
    (
        "sync after commit said twice",
        "sync role a\nsync after commit\nsync after commit\nsync alt.docs : share\n",
        "sync after commit is said twice",
        12,
        "AZ109",
    ),
    (
        "a sync line keyed by a type there isn't",
        "sync role eng\nsync alt.docs : share by fodler\n",
        "there is no type fodler",
        11,
        "AZ810",
    ),
    (
        "a sync line keyed by a type whose inheritance it doesn't reach",
        "  can view = owner or parent.view\nsync role eng\nsync alt.docs : share by doc\n",
        "reaches no permission of doc that inherits",
        12,
        "AZ810",
    ),
    (
        "a sync line keyed by an inheritance worked out with and / not",
        "  can view = (owner and reader) or parent.view\nsync role eng\nsync alt.docs : view by doc\n",
        "doc.view inherits, and who holds it joins parts that depend on who asks with and / not",
        12,
        "AZ810",
    ),
    (
        "a mirrored sync line keyed by a type",
        "  can view = owner or parent.view\nsync role eng\nsync alt.docs : view by doc mirrored\n",
        "a mirror's readers are the keys each row is read by, and keyed by doc they would be doc's keys",
        12,
        "AZ811",
    ),
    (
        "a sync line with a word after mirrored",
        "sync role eng\nsync alt.docs : share mirrored twice\n",
        "sync schema.table [: permission] [by type] [mirrored]",
        11,
        "AZ101",
    ),
    (
        "a synced permission reading the clock",
        "  can view = owner and {now() > '2020-01-01'}\nsync role eng\nsync alt.docs : view\n",
        "reads now(), which changes without a write",
        10,
        "AZ804",
    ),
    (
        "a synced permission reading 'today'",
        "  can view = owner and {up < 'today'}\nsync role eng\nsync alt.docs : view\n",
        "reads 'today', the current time",
        10,
        "AZ804",
    ),
    (
        "a synced permission reading chance",
        "  can view = owner or {random() < 0.5}\nsync role eng\nsync alt.docs : view\n",
        "reads random()",
        10,
        "AZ804",
    ),
    (
        "a synced permission reading age() of one argument",
        "  can view = owner and {age(up::text::date) < interval '1 day'}\nsync role eng\nsync alt.docs : view\n",
        "age() with one argument",
        10,
        "AZ804",
    ),
    (
        "a synced permission reading who asks",
        "  can view = {owner_id = authz.uid()}\nsync role eng\nsync alt.docs : view\n",
        "reads authz.uid(): who asks, or the session",
        10,
        "AZ805",
    ),
    (
        "a synced permission reading the session",
        "  can view = owner and {current_setting('app.x') = 'y'}\nsync role eng\nsync alt.docs : view\n",
        "reads current_setting()",
        10,
        "AZ805",
    ),
    (
        "a synced permission reading the user's role",
        "  can view = owner and not {current_user = 'x'}\nsync role eng\nsync alt.docs : view\n",
        "reads current_user",
        10,
        "AZ805",
    ),
    (
        "a synced permission reading other rows",
        "  can view = owner and {not exists (select 1 from alt.holds h where h.target = this.doc_no)}\nsync role eng\nsync alt.docs : view\n",
        "reads more than its row",
        10,
        "AZ806",
    ),
    (
        "a synced type whose where reads other rows",
        "type t2 = alt.projects where {exists (select 1 from alt.holds)}\n  lead : user = lead_id\n  can view = lead\nsync role eng\nsync alt.projects : view\n",
        "(the where of t2, which is synced) reads more than its row",
        10,
        "AZ806",
    ),
    (
        "a synced permission through a link table whose where reads other rows",
        "  helper : user = alt.group_members(group_id -> user_id) where {exists (select 1 from alt.holds)}\n  can view = helper\nsync role eng\nsync alt.docs : view\n",
        "(the where of alt.group_members) reads more than its row",
        10,
        "AZ806",
    ),
    (
        "a principal type whose where reads other rows, with sync",
        "type svc = alt.users principal where {exists (select 1 from alt.holds)}\nsync role eng\nsync alt.docs : share\n",
        "(the where of svc, which says who holds keys) reads more than its row",
        10,
        "AZ806",
    ),
    (
        "a nested group whose members are worked out with and / not, synced",
        "type org = alt.orgs\n  member : user = alt.org_members(org_id -> user_id)\n"
        "  banned : user = alt.org_bans(org_id -> user_id)\n  can good = member and not banned\n"
        "type team = alt.teams\n  member : user = alt.team_members(team_id -> user_id)\n"
        "  member : org#good = alt.team_orgs(team_id -> org_id)\n  member : team#member = alt.teams(parent_id -> id)\n"
        "type d2 = alt.projects\n  team : team = lead_id\n  can view = team.member\nsync role eng\nsync alt.projects : view\n",
        "team.member is a group in itself",
        15,
        "AZ807",
    ),
]

# whole policies, without BASE: (what, policy, expected piece of the message, the line it names, its code)
WHOLE = [
    ("no app role", "type user = alt.users\n", "name the app role, the Postgres role your app connects as", 1, "AZ111"),
    (
        "a type line without its =: says how a type is written",
        "app role app_user\ntype user alt.users\n",
        "line 2: write types as: type name = schema.table [(key)] [principal] [where {sql}] [AZ101]",
        2,
        "AZ101",
    ),
    (
        "principal after where: the order a type line takes",
        "app role app_user\ntype user = alt.users where {true} principal\n",
        "write types as: type name = schema.table [(key)] [principal] [where {sql}]",
        2,
        "AZ101",
    ),
    (
        "the app role in two words",
        "app role app user\n",
        "line 1: write the app role as: app role name [AZ101]",
        1,
        "AZ101",
    ),
    (
        "an include without quotes",
        "include roles.authz\napp role app_user\n",
        'line 1: write includes as: include "file.authz" (the file\'s name in double quotes) [AZ101]',
        1,
        "AZ101",
    ),
    ("PUBLIC as the app role", "app role public\ntype user = alt.users\n", "not PUBLIC", 1, "AZ111"),
    (
        "the app role named without app",
        "role app_user\ntype user = alt.users\n",
        "expected 'app role', 'type', 'rules', 'scope', 'caveat', 'sync', 'invariants', 'test', 'test \"name\"' or 'include', "
        "got: role app_user",
        1,
        "AZ101",
    ),
    (
        "no user type",
        "app role app_user\ntype doc = alt.docs (doc_no)\n  can view = signed_in\n",
        "line 1: declare the user type, e.g.: type user = app.users [AZ202]",
        1,
        "AZ202",
    ),
    (
        "an indented line with no block above it",
        "app role app_user\n  owner : user = owner_id\ntype user = alt.users\n",
        "line 2: indented line outside a type, rules, invariants or test block [AZ101]",
        2,
        "AZ101",
    ),
]

# (what, policy text appended to BASE, expected piece of the message, its code: every mistake the message lists
# carries it)
APPLY = [
    (
        "a table that doesn't exist",
        "type thing = alt.things\n  owner : user = owner_id\n  can view = owner\n",
        "line 10: table alt.things not found",
        "AZ601",
    ),
    (
        "... said first: the policy names what the database lacks",
        "type thing = alt.things\n  owner : user = owner_id\n  can view = owner\n",
        "ERROR:  the policy does not match this database:\n  line 10: table alt.things not found [AZ601]\n",
        "AZ601",
    ),
    (
        "a column that doesn't exist",
        "  editor : user = editor_id\n  can view = editor\n",
        "line 10: column editor_id not found in alt.docs",
        "AZ601",
    ),
    (
        "inheritance reading a view",
        "  can view = owner or (parent.view and {not exists (select 1 from alt.held h where h.target = doc_no)})\n",
        "line 10: a condition used for inheritance reads alt.held, which is not a table",
        "AZ604",
    ),
    (
        "inheritance calling a function that isn't IMMUTABLE",
        "  can view = owner or (parent.view and {alt.is_open(doc_no)})\n",
        "line 10: a condition used for inheritance calls alt.is_open(bigint), which is not IMMUTABLE",
        "AZ603",
    ),
    (
        "a cascade line that names no foreign key that acts: the keys of docs to users are NO ACTION",
        "rules alt.docs\n  select : share\n  cascade from alt.users\n",
        "line 12: cascade from alt.users: no foreign key of alt.docs to alt.users deletes or changes rows of alt.docs "
        "(ON DELETE CASCADE, SET NULL or SET DEFAULT, ON UPDATE SET NULL or SET DEFAULT): remove the line [AZ625]",
        "AZ625",
    ),
    (
        "... nor one that acts only ON UPDATE CASCADE (docs.up), which needs no line",
        "rules alt.docs\n  select : share\n  cascade from alt.docs (up)\n",
        "line 12: cascade from alt.docs: no foreign key of alt.docs to alt.docs on (up) deletes or changes rows",
        "AZ625",
    ),
    (
        "a cascade line naming a column the table doesn't have",
        "rules alt.docs\n  select : share\n  cascade from alt.docs (upp)\n",
        "line 12: column upp not found in alt.docs [AZ601]",
        "AZ601",
    ),
    (
        "a key declared with the wrong type",
        "type doc3 = alt.docs (doc_no uuid)\n  owner : user = owner_id\n  can see = owner\n",
        "line 10: alt.docs.doc_no is bigint, not uuid: write its type after the key, (doc_no bigint) [AZ602]",
        "AZ602",
    ),
    (
        "inheritance limited by a time-zone dependent expression",
        "  can view = owner or (parent.view and {created + interval '1 day' > '2020-01-01'})\n",
        "line 10: a condition that limits inheritance must give the same answer for every user at any time",
        "AZ603",
    ),
    (
        "inheritance across two types through a link table whose where depends on the time zone",
        "  project : project = alt.proj_links(doc_no -> proj_id) where {since + interval '1 day' > '2020-01-01'}\n"
        "  can view = owner or parent.view or project.view\n"
        "type project = alt.projects\n  lead : user = lead_id\n  docs : doc = alt.doc_projects(proj_id -> doc_no)\n"
        "  can view = lead or docs.view\n",
        "line 10: a condition that limits inheritance must give the same answer for every user at any time",
        "AZ603",
    ),
]

# a file name SQL text must quote ('), and a RAISE's message too (%)
QUOTED_FILE = "o'brien 50%.authz"

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
        "a deny and a condition both joining the inheritance with and",
        "  can hidden = reader or parent.hidden\n  can view = (owner or parent.view) and {not locked} and not hidden\n",
        {},
    ),
    (
        "a deny without conditions, where the permission inherits through one relation in two ways, each on its own",
        "  can hidden = reader or parent.hidden\n"
        "  can view = (owner or (parent.view and {locked}) or (parent.view and {not locked})) and not hidden\n",
        {},
    ),
    (
        "a condition with /* comments */ holding an apostrophe and braces, and a name ending in $$: read as Postgres "
        "reads them",
        "  can see = owner and {/* the owner's, /* nested } */ unless { */ up is null"
        " and 1 = (select one$$ from (select 1 as one$$) s)}\nrules alt.docs\n  select : see\n",
        {},
        "INSERT INTO alt.users VALUES (1); INSERT INTO alt.docs (doc_no, owner_id) VALUES (1, 1), (2, 1);"
        "UPDATE alt.docs SET up = 1 WHERE doc_no = 2; SET authz.user_id = 1;"
        "DO $$ BEGIN IF NOT authz.can('doc', '1', 'see') OR authz.can('doc', '2', 'see') THEN"
        " RAISE EXCEPTION 'the condition misread'; END IF; END $$;"
        "SET ROLE app_user; DO $$ BEGIN IF (SELECT array_agg(doc_no) FROM alt.docs) IS DISTINCT FROM '{1}' THEN"
        " RAISE EXCEPTION 'the rule misread'; END IF; END $$;",
    ),
    (
        "a column named check, in a rule on it: an editor may change the body, not check",
        "type note = alt.notes\n  owner : user = owner_id\n  editor : user = editor_id\n  can edit = owner or editor\n"
        "  can seal = owner\nrules alt.notes\n  select : edit\n  update : edit\n  update check : seal\n",
        {},
        "INSERT INTO alt.users VALUES (1), (2); INSERT INTO alt.notes VALUES (1, 1, 2, 'open', 'a');"
        "SET ROLE app_user; SET authz.user_id = '2'; UPDATE alt.notes SET body = 'b';"
        "DO $$ BEGIN BEGIN UPDATE alt.notes SET \"check\" = 'sealed';"
        " EXCEPTION WHEN insufficient_privilege THEN"
        "  IF SQLERRM = 'changing check of alt.notes 1 needs: seal' THEN RETURN; END IF; RAISE; END;"
        " RAISE EXCEPTION 'an editor changed check'; END $$;",
    ),
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
    (
        "a link table naming objects of two types keyed by two columns: the audit names each by its key",
        "  pinned : space, room = alt.pins(doc_no -> (kind, [org, ref]))\n  can view = owner or pinned.see\n"
        "type space = alt.spaces (org, id)\n  keeper : user = keeper_id\n  can see = keeper\n"
        "type room = alt.rooms (org, id)\n  keeper : user = keeper_id\n  can see = keeper\n",
        {},
        "INSERT INTO alt.users VALUES (1), (2);"
        "INSERT INTO alt.spaces VALUES (1, 2, 1); INSERT INTO alt.rooms VALUES (1, 2, 2);"
        "INSERT INTO alt.docs (doc_no) VALUES (10), (11);"
        "INSERT INTO alt.pins VALUES (10, 'space', 1, 2), (11, 'room', 1, 2);"
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
CREATE TABLE alt.notes (id bigint PRIMARY KEY, owner_id bigint, editor_id bigint, "check" text, body text);
GRANT SELECT ON alt.proj_links, alt.tusers, alt.tdocs, alt.spaces, alt.rooms, alt.pins TO app_user;
GRANT SELECT, UPDATE ON alt.notes TO app_user;
"""


# Included files passed as a map, the way the rowstile command passes them: never read from disk.
# (what, main policy, files, expected start of the message, its code)
INCLUDES = [
    (
        "an include missing from the files",
        'include "roles.authz"\n',
        {},
        "line 1: can't find roles.authz in the policy's folder [AZ108]",
        "AZ108",
    ),
    (
        "a server file",
        'include "/etc/passwd"\n',
        {"/etc/passwd": BASE},
        "line 1: /etc/passwd: an included file is in the policy's folder",
        "AZ108",
    ),
    (
        "a file above the policy's folder",
        'include "sub/../../x.authz"\n',
        {"../x.authz": BASE},
        "line 1: sub/../../x.authz: an included file is in the policy's folder",
        "AZ108",
    ),
    (
        "a file above, from an included file",
        'include "sub/a.authz"\n',
        {"sub/a.authz": 'include "../../x.authz"\n', "../x.authz": BASE},
        "sub/a.authz line 1: ../../x.authz: an included file is in the policy's folder",
        "AZ108",
    ),
    (
        "a backslash",
        'include "sub\\x.authz"\n',
        {"sub\\x.authz": BASE},
        "line 1: sub\\x.authz: an included file is in the policy's folder",
        "AZ108",
    ),
    (
        "a drive",
        'include "C:x.authz"\n',
        {"C:x.authz": BASE},
        "line 1: C:x.authz: an included file is in the policy's folder",
        "AZ108",
    ),
    (
        "a mistake in an included file names that file",
        'include "sub/x.authz"\n',
        {"sub/x.authz": BASE + "  can view = no_such_name\n"},
        "sub/x.authz line 10:",
        "AZ203",
    ),
    (
        "an include resolved from the including file's folder",
        'include "sub/a.authz"\n',
        {"sub/a.authz": 'include "b.authz"\n', "b.authz": BASE},
        "sub/a.authz line 1: can't find sub/b.authz in the policy's folder [AZ108]",
        "AZ108",
    ),
    (
        "a file whose name holds a dollar quote's tag",
        'include "notes$f$.authz"\n',
        {"notes$f$.authz": BASE},
        "line 1: notes$f$.authz: an included file's name can't hold $f$: the generated functions name the file in "
        "their messages, and $f$ would end one; rename the file [AZ108]",
        "AZ108",
    ),
    (
        "the same file twice",
        'include "a.authz"\ninclude "a.authz"\n',
        {"a.authz": BASE},
        "line 2: a.authz is included twice",
        "AZ108",
    ),
    (
        "an included file that starts indented: its lines don't go on with the block above the include",
        BASE + 'include "more.authz"\n',
        {"more.authz": "  can view = owner\n"},
        "more.authz line 1: indented line outside a type, rules, invariants or test block: a block ends at an "
        "include line, and an included file starts blocks of its own [AZ101]",
        "AZ101",
    ),
    (
        "indented lines after an include: they don't go on with the included file's last block",
        'app role app_user\ntype user = alt.users\ninclude "doc.authz"\n  can view = owner\n',
        {"doc.authz": "type doc = alt.docs (doc_no)\n  owner : user = owner_id\n"},
        "line 4: indented line outside a type, rules, invariants or test block: a block ends at an include line",
        "AZ101",
    ),
    (
        "an include line indented",
        BASE + '  include "more.authz"\n',
        {"more.authz": "type more = alt.projects\n"},
        "line 10: an include line starts at the left margin: it includes a whole file, not lines of the block above "
        "[AZ101]",
        "AZ101",
    ),
]


# named tests (compiled with their SQL): (what, text appended to BASE, expected piece of the message, the line it
# names, its code)
TESTS = [
    (
        "a $name used before a given names it",
        'test "t"\n  user $ann can share doc 1\n',
        "$ann is not named yet",
        11,
        "AZ501",
    ),
    (
        "... also inside a statement",
        'test "t"\n  as user 1 refused {INSERT INTO alt.docs VALUES ($doc)}\n',
        "$doc is not named yet",
        11,
        "AZ501",
    ),
    (
        "acting as a type that doesn't sign in",
        'test "t"\n  given g = {SELECT 1}\n  grp $g can share doc 1\n',
        "'grp' doesn't sign in: a test acts as anyone or as a type that signs in (user) [AZ502]",
        12,
        "AZ502",
    ),
    (
        "... where two types sign in",
        'type bot = alt.bots principal\ntest "t"\n  grp 1 can share doc 1\n',
        "'grp' doesn't sign in: a test acts as anyone or as a type that signs in (user, bot) [AZ502]",
        12,
        "AZ502",
    ),
    ("a line that is none of a test's", 'test "t"\n  user 1 maybe share doc 1\n', "a test's lines are", 11, "AZ106"),
    (
        "a scope the policy doesn't have",
        'test "t"\n  user 1 with scope files can share doc 1\n',
        "no scope 'files' in the policy (it has: read)",
        11,
        "AZ503",
    ),
    (
        "... also on a statement",
        'test "t"\n  as user 1 with scope read, files sees 0 {SELECT 1}\n',
        "no scope 'files' in the policy",
        11,
        "AZ503",
    ),
    (
        "a scope for nobody",
        'test "t"\n  anyone with scope read can share doc 1\n',
        "`anyone` is nobody signed in",
        11,
        "AZ106",
    ),
    ("with scope and no scope", 'test "t"\n  user 1 with scope can share doc 1\n', "a test's lines are", 11, "AZ106"),
    ("a test with no lines", 'test "t"\n', "test 't' has no lines", 10, "AZ106"),
    (
        "a test with an empty name",
        'test ""\n  user 1 can share doc 1\n',
        'the test\'s name is empty: say what it checks, test "owners see their folders" [AZ106]',
        10,
        "AZ106",
    ),
    (
        "words after a test's closing quote",
        'test "owners" see\n  user 1 can share doc 1\n',
        "the test's name ends at its closing \": nothing goes after it on the line [AZ106]",
        10,
        "AZ106",
    ),
    (
        "a test written glued to its name",
        'test"t"\n  user 1 can share doc 1\n',
        'write tests as: test "name" (or test alone, for checks on the data already there) [AZ101]',
        10,
        "AZ101",
    ),
    (
        "a scope named with - in a test: read whole, as where it is declared",
        'test "t"\n  user 1 with scope read-only can share doc 1\n',
        "no scope 'read-only' in the policy (it has: read)",
        11,
        "AZ503",
    ),
    (
        "... and with :, on a statement",
        'test "t"\n  as user 1 with scope read, files:write sees 0 {SELECT 1}\n',
        "no scope 'files:write' in the policy (it has: read)",
        11,
        "AZ503",
    ),
    (
        "two tests with one name",
        'test "a"\n  user 1 can share doc 1\ntest "a"\n  user 1 can share doc 1\n',
        "already a test named 'a'",
        12,
        "AZ109",
    ),
    (
        "a permission that doesn't exist, in a named test",
        'test "t"\n  user 1 can edit doc 1\n',
        "doc has no permission 'edit'",
        11,
        "AZ203",
    ),
    (
        "the test section acting as a type that doesn't sign in",
        "test\n  grp 1 can share doc 1\n",
        "'grp' doesn't sign in",
        11,
        "AZ502",
    ),
    (
        "the test section acting as a type that isn't there",
        "test\n  bot 1 can share doc 1\n",
        "'bot' doesn't sign in",
        11,
        "AZ502",
    ),
    (
        "a statement in the test section",
        "test\n  as user 1 allowed {SELECT 1}\n",
        "the test section checks the data already there",
        11,
        "AZ106",
    ),
    ("a $name in the test section", "test\n  user $ann can share doc 1\n", "$ann is not named yet", 11, "AZ501"),
    (
        "sees N on a statement that writes",
        'test "t"\n  as user 1 sees 0 {UPDATE alt.docs SET up = NULL RETURNING doc_no}\n',
        "`sees N` counts the rows of a SELECT, and this statement writes",
        11,
        "AZ106",
    ),
    (
        "sees N on a statement that writes in its WITH",
        'test "t"\n  as user 1 sees 0 {WITH gone AS (DELETE FROM alt.docs RETURNING doc_no) SELECT * FROM gone}\n',
        "`sees N` counts the rows of a SELECT, and this statement writes",
        11,
        "AZ106",
    ),
    (
        "sees N on a statement that writes after a comment",
        'test "t"\n  as user 1 sees 0 {/* none of them */ DELETE FROM alt.docs WHERE false}\n',
        "`sees N` counts the rows of a SELECT, and this statement writes",
        11,
        "AZ106",
    ),
]


def reset(db: str) -> None:
    """The app's tables afresh, with what the apply cases add to them, and no policy (tests/alt_schema.sql drops
    rowstile's schemas and the app's first)."""
    for source in (["-f", "tests/alt_schema.sql"], ["-c", APPLY_SETUP]):
        subprocess.run(
            ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", db, *source], check=True, capture_output=True
        )


def compile_policy(text: str, tests: bool = False, files: dict[str, str] | None = None) -> str:
    c = Compiler(parse_policy(text, files=files))
    return c.compile_tests("t") if tests else c.compile("t")


def main() -> None:
    db = sys.argv[sys.argv.index("--db") + 1] if "--db" in sys.argv else "authz_errors"
    os.chdir(os.path.dirname(HERE))
    fails = 0
    for what, extra, want, line, code in COMPILE:
        try:
            compile_policy(BASE + extra)
            got = "(compiled without error)"
        except PolicyError as e:
            got = str(e)
        ok = want in got and got.startswith(f"line {line}:") and coded(got, code)
        fails += not ok
        print(f"{'ok  ' if ok else 'FAIL'}  {what}: {got}")
    for what, text, want, line, code in WHOLE:
        try:
            compile_policy(text)
            got = "(compiled without error)"
        except PolicyError as e:
            got = str(e)
        ok = want in got and got.startswith(f"line {line}:") and coded(got, code)
        fails += not ok
        print(f"{'ok  ' if ok else 'FAIL'}  {what}: {got}")

    try:
        compile_policy(BASE + "  can view = owner\ntest\n  user 1 can edit doc 1\n", tests=True)
        got = "(compiled without error)"
    except PolicyError as e:
        got = str(e)
    ok = got.startswith("line 12: doc has no permission 'edit'") and coded(got, "AZ203")
    fails += not ok
    print(f"{'ok  ' if ok else 'FAIL'}  a test of a permission that doesn't exist: {got}")

    for what, extra, want, line, code in TESTS:
        try:
            compile_policy(BASE + extra, tests=True)
            got = "(compiled without error)"
        except PolicyError as e:
            got = str(e)
        ok = want in got and got.startswith(f"line {line}:") and coded(got, code)
        fails += not ok
        print(f"{'ok  ' if ok else 'FAIL'}  named tests: {what}: {got}")
    try:
        c = Compiler(parse_policy(BASE))
        c.add_test_files({"more.authz": "type x = alt.x\n"})
        got = "(compiled without error)"
    except PolicyError as e:
        got = str(e)
    ok = got.startswith("more.authz: a test file holds only named tests") and coded(got, "AZ106")
    fails += not ok
    print(f"{'ok  ' if ok else 'FAIL'}  named tests: a test file with a type in it: {got}")
    try:
        c = Compiler(parse_policy(BASE))
        c.add_test_files({"more.authz": 'test "t"\n  user 1 can view doc 1\n'})
        c.tests_function_sql()
        got = "(compiled without error)"
    except PolicyError as e:
        got = str(e)
    ok = got.startswith("more.authz line 2: doc has no permission 'view'") and coded(got, "AZ203")
    fails += not ok
    print(f"{'ok  ' if ok else 'FAIL'}  named tests: a mistake in a test file names the file: {got}")

    for what, main_text, files, want, code in INCLUDES:
        try:
            compile_policy(main_text, files=files)
            got = "(compiled without error)"
        except PolicyError as e:
            got = str(e)
        ok = got.startswith(want) and coded(got, code)
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
    # each also from an included file named with a quote and a percent sign: the messages hold its name as SQL
    # text, and as a RAISE's message, and say it as written
    for (what, extra, want, code), file in [(a, f) for a in APPLY for f in (None, QUOTED_FILE)]:
        reset(db)
        if file is None:
            sql = compile_policy(BASE + extra)
        else:
            sql = compile_policy(f'include "{file}"\n', files={file: BASE + extra})
            what += f", in {file}"
            want = re.sub(r"^(\s*)line ", "\\g<1>" + file.replace("\\", "\\\\") + " line ", want, flags=re.M)
        p = subprocess.run(
            ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", db], input=sql, capture_output=True, text=True
        )
        err = next((ln for ln in p.stderr.splitlines() if "ERROR" in ln), "(applied without error)")
        # every mistake the message lists carries the case's code
        ok = p.returncode != 0 and want in p.stderr and set(re.findall(r"\[(AZ\d{3})\]", p.stderr)) == {code}
        fails += not ok
        print(f"{'ok  ' if ok else 'FAIL'}  applying {what}: {err.split('ERROR:', 1)[-1].strip()}")
    for what, extra, env, *after in APPLY_OK:
        reset(db)
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
    # a whole policy in an included file named with a quote and a percent sign: it applies, and its named test runs,
    # its line said as written
    reset(db)
    text = (
        BASE + "rules alt.docs\n  select : share\n"
        'test "the owner sees the doc"\n  given u = {INSERT INTO alt.users VALUES (7) RETURNING id}\n'
        "  given d = {INSERT INTO alt.docs (doc_no, owner_id) VALUES (70, $u) RETURNING doc_no}\n"
        "  as user $u sees 1 {SELECT doc_no FROM alt.docs}\n"
    )
    c = Compiler(parse_policy(f'include "{QUOTED_FILE}"\n', files={QUOTED_FILE: text}))
    p = subprocess.run(
        ["psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1", "-d", db],
        input=c.compile("t")
        + c.tests_function_sql()
        + "\nSELECT string_agg(line || ': ' || ok, ', ') FROM pg_temp.authz_policy_tests();\n",
        capture_output=True,
        text=True,
    )
    got = p.stdout.strip().splitlines()[-1] if p.returncode == 0 else p.stderr.strip()
    ok = got == f"{QUOTED_FILE} line 15: true"
    fails += not ok
    print(f"{'ok  ' if ok else 'FAIL'}  a policy in {QUOTED_FILE} applies, and its named test runs: {got}")
    # a relation that is no table gets a notice instead of the trigger, which names it as written, a % in it too (no
    # policy names such a table: trigger_if_table is called alone)
    p = subprocess.run(
        ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", db],
        input='CREATE VIEW alt."50%off" AS SELECT 1 AS x;\n'
        + trigger_if_table(
            "alt.50%off",
            'CREATE TRIGGER "t" AFTER INSERT ON alt."50%off" FOR EACH STATEMENT EXECUTE FUNCTION authz_int.f()',
            "audit",
        ),
        capture_output=True,
        text=True,
    )
    got = p.stderr.strip()
    ok = (
        p.returncode == 0
        and got == 'NOTICE:  "alt"."50%off" is not a table: changes to it are not audited or fed (audit)'
    )
    fails += not ok
    print(f"{'ok  ' if ok else 'FAIL'}  a relation named with a % that is no table: a notice says so: {got}")
    # a shared relation with expiring shares can't later become a link for inheritance
    v1 = compile_policy(BASE + "  shortcut : doc shared\n  can view = owner or shortcut.owner\n")
    v2 = compile_policy(BASE + "  shortcut : doc shared\n  can view = owner or shortcut.view\n")
    # beside a share that never ends nor starts later (which may become a link), one that expires, or one that starts
    # later: only that one is counted (not one of another relation, reader, which no inheritance uses)
    for what, when in (
        ("expiring", "now() + interval '1 day', NULL"),
        ("starting later", "NULL, now() + interval '1 day'"),
    ):
        reset(db)
        setup = (
            "INSERT INTO alt.users VALUES (1); INSERT INTO alt.docs (doc_no, owner_id) VALUES (1, 1), (2, 1), (3, 1);"
            "INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id, subject_relation,"
            f" expires_at, starts_at) VALUES ('doc', 1, 'shortcut', 'doc', 2, '', {when}),"
            " ('doc', 3, 'shortcut', 'doc', 2, '', NULL, NULL),"
            f" ('doc', 1, 'reader', 'user', 1, '', {when});"
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
        len(COMPILE)
        + len(WHOLE)
        + 1
        + len(TESTS)
        + 2
        + len(INCLUDES)
        + 1
        + 2 * len(APPLY)
        + len(APPLY_OK)
        + 4
        + len(LINKS)
    )
    print(f"policy errors: {total - fails} of {total} cases behave as expected")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
