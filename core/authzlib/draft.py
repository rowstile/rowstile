"""A first policy from a database's tables and foreign keys (authz.draft, `rowstile init`).

It compiles, and it is a draft: every place a person has to decide is marked `-- decide:`. Tables become
types; foreign keys become relations (to users: owner, author, ...; to other rows: what the row sits in,
which it inherits view and edit from); tables that link rows to users (their key is the two foreign keys)
become relations from a table, such as members. Every table gets rules.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import NotRequired, TypedDict

from . import parse
from .parse import COMMANDS, KEY_TYPES

# names a relation doesn't get: the language's words, the commands, and the two permissions every drafted type has
RESERVED = (
    set(COMMANDS)
    | set(parse.RESERVED)
    | set(parse.KEYWORDS)
    | {
        "anyone",
        "link",
        "or",
        "and",
        "not",
        "can",
        "signed_in",
        "nobody",
        "mask",
        "type",
        "rules",
        "role",
        "test",
        "given",
        "as",
        "shared",
        "roles",
        "grant",
        "where",
        "user",
        "if",
        "after",
        "before",
        "by",
        "principal",
        "include",
        "scope",
        "caveat",
        "invariants",
        "view",
        "edit",
    }
)
RENAMED = {"view": "viewer", "edit": "editor"}
# the tables migration tools keep for themselves: never part of the policy
TOOL_TABLES = {
    "_prisma_migrations",
    "alembic_version",
    "schema_migrations",
    "ar_internal_metadata",
    "goose_db_version",
    "flyway_schema_history",
    "__drizzle_migrations",
    "knex_migrations",
    "knex_migrations_lock",
    "django_migrations",
}
# words SQL keeps for itself: a column with such a name is written in quotes in a {condition}
SQL_WORDS = {
    "all",
    "and",
    "any",
    "as",
    "asc",
    "both",
    "case",
    "check",
    "column",
    "constraint",
    "current_user",
    "default",
    "desc",
    "distinct",
    "do",
    "else",
    "end",
    "false",
    "for",
    "foreign",
    "from",
    "grant",
    "group",
    "having",
    "in",
    "into",
    "is",
    "limit",
    "not",
    "null",
    "offset",
    "on",
    "only",
    "or",
    "order",
    "primary",
    "references",
    "select",
    "session_user",
    "some",
    "table",
    "then",
    "to",
    "true",
    "union",
    "unique",
    "user",
    "using",
    "when",
    "where",
    "window",
    "with",
}
# the tables that may hold the users, the likeliest first ("members" is more often a link table: not one of them)
USER_TABLES = ("users", "user", "accounts", "account", "people", "persons", "profiles")
# a link table with an id of its own and no unique pair is a membership when it says who does what (one of these),
# and holds nothing else than that and when (LINK_EXTRAS)
ROLE_COLUMNS = ("role", "kind", "level", "access", "permission", "permissions")
# types whose rows hold people, and whose rows inside other rows usually mean nested membership: the members of a
# team inside count as members of the team above (the cookbook's nested teams), not the team above's view passed down
GROUP_WORDS = re.compile(r"(?:^|_)(?:team|group|org|organization|organisation|department|division|unit|squad|circle)$")
LINK_EXTRAS = re.compile(
    r"(role|kind|level|access|permission|permissions|(created|updated|inserted|joined|added)(_at|At|_on|On)?|"
    r"\w+(_at|At)|created_by|invited_by|added_by)"
)
KEY_NAMES = {
    "bigint": "bigint",
    "int8": "bigint",
    "integer": "int",
    "int4": "int",
    "int": "int",
    "smallint": "smallint",
    "int2": "smallint",
    "text": "text",
    "uuid": "uuid",
    "character varying": "varchar",
    "varchar": "varchar",
}


class DraftError(Exception):
    pass


class ForeignKey(TypedDict):
    cols: list[str]
    ref: str  # schema.table
    ref_cols: list[str]


class Table(TypedDict):
    name: str  # schema.table
    columns: list[tuple[str, str]]  # (column, type), in order
    pk: list[str]  # the primary key's columns (not those it INCLUDEs); none: the table has no primary key
    fks: list[ForeignKey]
    uniques: NotRequired[list[list[str]]]  # the key columns of each unique constraint or index besides the key


def names(value: object) -> list[str]:
    """A JSON array of names."""
    assert isinstance(value, list) and all(isinstance(x, str) for x in value), value
    return [str(x) for x in value]


def table_of(row: Mapping[str, object]) -> Table:
    """A row of CATALOG_SQL (its arrays are JSON text) as a Table."""

    def json_of(key: str) -> object:
        text = row.get(key)
        return json.loads(text) if isinstance(text, str) else None

    columns = json_of("columns") or []
    assert isinstance(columns, list), columns
    fks = json_of("fks") or []
    assert isinstance(fks, list), fks
    uniques = json_of("uniques") or []
    assert isinstance(uniques, list), uniques
    return {
        "name": str(row["name"]),
        "columns": [column_of(c) for c in columns],
        "pk": names(json_of("pk") or []),
        "fks": [foreign_key_of(fk) for fk in fks],
        "uniques": [names(u) for u in uniques],
    }


def column_of(value: object) -> tuple[str, str]:
    """[column, type] as JSON."""
    assert isinstance(value, list) and len(value) == 2, value
    return str(value[0]), str(value[1])


def foreign_key_of(value: object) -> ForeignKey:
    """{cols, ref, ref_cols} as JSON."""
    assert isinstance(value, dict), value
    fk: dict[str, object] = {str(k): v for k, v in value.items()}
    return {"cols": names(fk["cols"]), "ref": str(fk["ref"]), "ref_cols": names(fk["ref_cols"])}


def singular(word: str) -> str:
    if word.endswith("ies") and len(word) > 4:
        return word[:-3] + "y"
    if word.endswith(("sses", "xes", "zes", "ches", "shes")):
        return word[:-2]
    if word.endswith("s") and not word.endswith(("ss", "us")):
        return word[:-1]
    return word


def key_type(t: str) -> str | None:
    base = re.sub(r"\(.*\)", "", t).strip()
    return KEY_NAMES.get(base)


def relation_name(column: str) -> str:
    name = re.sub(r"(_(id|key|uuid)|Id|Key|Uuid)$", "", column) or column
    return {"created_by": "creator", "updated_by": "editor", "owned_by": "owner", "user": "person"}.get(name, name)


def writable(name: str) -> bool:
    """Whether the policy language can write this name: letters, digits and _, and no __ (generated names use it)."""
    return bool(re.fullmatch(parse.IDENT, name)) and "__" not in name


def in_sql(column: str) -> str:
    """A column as a {condition} writes it: in quotes when SQL would read the bare name as something else."""
    return (
        column
        if re.fullmatch(r"[a-z_][a-z0-9_]*", column) and column not in SQL_WORDS
        else '"' + column.replace('"', '""') + '"'
    )


def free_name(rel: str, taken: set[str]) -> str:
    """A relation's name: not one of the language's words or the drafted permissions, and not taken."""
    rel = RENAMED.get(rel, rel + "_rel" if rel in RESERVED else rel)
    base, i = rel, 2
    while rel in taken or rel in RESERVED:
        rel, i = f"{base}{i}", i + 1
    return rel


def draft(
    tables: list[Table], users: str | None = None, role: str = "app_user", schemas: Sequence[str] = ("public",)
) -> str:
    """The policy's text, from the tables (table_of gives them from the catalog)."""
    skipped: list[str] = []
    left_out: dict[str, str] = {}  # the tables left out here: why
    kept: list[Table] = []
    for t in tables:
        schema, _, name = t["name"].partition(".")
        if name in TOOL_TABLES:
            left_out[t["name"]] = "the migration tool's own table"
        elif not (writable(schema) and writable(name)):
            left_out[t["name"]] = (
                "a name the policy language can't write (letters, digits and _ only): "
                "give it a view with a plain name, and name the view"
            )
        elif not all(writable(c) for c in t["pk"]):
            left_out[t["name"]] = f"its key has a column name the policy language can't write ({', '.join(t['pk'])})"
        else:
            # the same foreign key declared twice (added again under another name): one relation
            fks = list({(tuple(fk["cols"]), fk["ref"], tuple(fk["ref_cols"])): fk for fk in t["fks"]}.values())
            kept.append({**t, "fks": fks})
            continue
        skipped.append(f"-- {t['name']}: {left_out[t['name']]}")
    tables = kept
    by_name = {t["name"]: t for t in tables}
    keyed = {n: t for n, t in by_name.items() if t["pk"]}
    # --- the user table -------------------------------------------------------------------------
    if users:
        if users not in keyed:
            raise DraftError(f"{users}: no such table with a primary key in {', '.join(schemas)} [AZ621]")
    else:
        named = sorted(
            (n for n in keyed if n.split(".")[1].lower() in USER_TABLES and len(keyed[n]["pk"]) == 1),
            key=lambda n: (USER_TABLES.index(n.split(".")[1].lower()), n),
        )
        if named:
            users = named[0]
        else:
            refs: dict[str, list[str]] = {}  # the table they point to: the columns that name users
            for t in tables:
                for fk in t["fks"]:
                    if len(fk["cols"]) == 1 and re.search(
                        r"(user|owner|author|creator|created_by|sender)", fk["cols"][0]
                    ):
                        refs.setdefault(fk["ref"], []).append(f"{t['name']}.{fk['cols'][0]}")
            if not refs:
                # a users table keyed by two columns (a tenant's and its own): say what it lacks, not "which table"
                wide = sorted(n for n in keyed if n.split(".")[1].lower() in USER_TABLES)
                if wide:
                    raise DraftError(
                        f"{wide[0]}: the user table needs a key of one column (or name another: rowstile init "
                        "--users schema.table) [AZ622]"
                    )
                raise DraftError("which table holds your users? name it: rowstile init --users schema.table [AZ621]")
            users = max(refs, key=lambda n: len(refs[n]))
            if users not in keyed:
                # the keys that name users point to a table the draft can't have as a type: another schema's (as
                # Supabase's auth.users), or one left out above
                cols = refs[users]
                said = f"{users}: {', '.join(cols[:3])}{' and more' if len(cols) > 3 else ''} "
                said += f"point{'' if len(cols) > 1 else 's'} to it, "
                why = left_out.get(users) or ("no primary key" if users in by_name else None)
                if why:
                    raise DraftError(
                        f"{said}and the draft leaves it out: {why}. Name the table that holds your users with "
                        "rowstile init --users schema.table [AZ621]"
                    )
                raise DraftError(
                    f"{said}and it isn't in {', '.join(schemas)}: draft its schema too (--schema "
                    f"{','.join([*schemas, users.split('.')[0]])}), or name the table that holds your users: "
                    "rowstile init --users schema.table [AZ621]"
                )
    if len(keyed[users]["pk"]) != 1:
        raise DraftError(f"{users}: the user table needs a key of one column [AZ622]")
    user_key = dict(keyed[users]["columns"])[keyed[users]["pk"][0]]
    if key_type(user_key) is None:
        raise DraftError(
            f"{users}: its key is {user_key}, and the user type's key must be one of {', '.join(KEY_TYPES)}: "
            f"name another table with --users, or change the key's type [AZ622]"
        )

    # --- types ----------------------------------------------------------------------------------
    type_names: dict[str, str] = {}
    for n, t in sorted(keyed.items()):
        cols = dict(t["columns"])
        if any(key_type(cols[c]) is None for c in t["pk"]):
            skipped.append(f"-- {n}: its key's type isn't one rowstile can use ({', '.join(KEY_TYPES)})")
            continue
        if n == users:
            type_names[n] = "user"
            continue
        base = singular(n.split(".")[1]).lower()
        if not re.fullmatch(r"[a-z_][a-z0-9_]*", base) or base in RESERVED:
            base = base + "_row" if re.fullmatch(r"[a-z_][a-z0-9_]*", base) else "t_" + re.sub(r"\W", "_", base)
        name, i = base, 2
        while name in type_names.values():
            name, i = f"{base}{i}", i + 1
        type_names[n] = name
    for n, t in sorted(by_name.items()):
        if not t["pk"]:
            skipped.append(f"-- {n}: no primary key (rowstile needs one to name its rows)")

    def key_spec(t: Table) -> str:
        cols = dict(t["columns"])
        if len(t["pk"]) == 1:
            c = t["pk"][0]
            ty = key_type(cols[c])
            return "" if (c, ty) == ("id", "bigint") else f" ({c}{'' if ty == 'bigint' else ' ' + (ty or '')})"
        return (
            " ("
            + ", ".join(c + ("" if key_type(cols[c]) == "bigint" else " " + (key_type(cols[c]) or "")) for c in t["pk"])
            + ")"
        )

    def cols_text(cols: list[str]) -> str:
        return cols[0] if len(cols) == 1 else "[" + ", ".join(cols) + "]"

    # --- relations ------------------------------------------------------------------------------
    rels: dict[str, list[tuple[str, str, str, str]]] = {
        n: [] for n in type_names
    }  # table -> [(name, target type, source, kind)]
    notes: dict[str, list[str]] = {n: [] for n in type_names}
    for n in type_names:
        t = by_name[n]
        used: set[str] = set()
        position = {c: i for i, (c, _) in enumerate(t["columns"])}
        # what the row sits in first (a foreign key inside its own key), then in the order of the columns
        ordered = sorted(t["fks"], key=lambda fk: (not set(fk["cols"]) <= set(t["pk"]), position.get(fk["cols"][0], 0)))
        for fk in ordered:
            if fk["ref"] not in type_names or list(fk["ref_cols"]) != list(by_name[fk["ref"]]["pk"]):
                continue
            if not all(writable(c) and c not in RESERVED for c in fk["cols"]):
                notes[n].append(
                    f"  -- left out: {', '.join(fk['cols'])} (to {fk['ref']}): a column name the policy language "
                    f"can't write, or one of its words; a view that names it plainly can be used instead"
                )
                continue
            rel = free_name(relation_name(fk["cols"][0]) if len(fk["cols"]) == 1 else type_names[fk["ref"]], used)
            used.add(rel)
            kind = "user" if fk["ref"] == users else "parent"
            rels[n].append((rel, type_names[fk["ref"]], cols_text(fk["cols"]), kind))
    # link tables: a foreign key to a row and one to a user, and either the pair is the key, or the table has an
    # id of its own (what Rails, Ecto, Django and Prisma make) and the pair is unique, or it holds nothing else
    # than who does what and when (a role, timestamps)
    for n, t in by_name.items():
        # foreign keys to keys: a link through another unique column has another type than the ids it must match
        fks = [
            fk
            for fk in t["fks"]
            if fk["ref"] in type_names
            and list(fk["ref_cols"]) == list(by_name[fk["ref"]]["pk"])
            and all(writable(c) and c not in RESERVED for c in fk["cols"])
        ]
        pk = set(t["pk"])
        to_user = [fk for fk in fks if fk["ref"] == users and len(fk["cols"]) == 1]
        others = [fk for fk in fks if fk["ref"] != users]
        if not (to_user and others and pk):
            continue
        u, o = to_user[0], others[0]
        pair = set(u["cols"]) | set(o["cols"])
        rest = [c for c, _ in t["columns"] if c not in pair | pk]
        roles = [c for c in rest if c in ROLE_COLUMNS]
        own_id = (
            len(pk) == 1
            and not pk & pair
            and (
                any(set(x) == pair for x in t.get("uniques", []))
                or (bool(roles) and all(LINK_EXTRAS.fullmatch(c) for c in rest))
            )
        )
        if pk != pair and not own_id:
            continue
        target = o["ref"]
        rel = singular(n.split(".")[1])
        # the type's own name is left out of it: team_members is member, and so is TeamMember
        prefix, camel = type_names[target] + "_", type_names[target]
        if rel.startswith(prefix) and len(rel) > len(prefix):
            rel = rel[len(prefix) :]
        elif rel.lower().startswith(camel) and rel[len(camel) : len(camel) + 1].isupper():
            rel = rel[len(camel)].lower() + rel[len(camel) + 1 :]
        rel = free_name(rel if writable(rel) else "linked", {r[0] for r in rels[target]})
        source = f"{n}({cols_text(o['cols'])} -> {u['cols'][0]})"
        rels[target].append((rel, "user", source, "link"))
        if pk != pair:
            notes[target].append(
                f"  -- decide: {n} is read as a membership (the people it lists see what it links); "
                f"remove {rel} if it isn't one"
            )
        role_col = next((c for c, _ in t["columns"] if c in ROLE_COLUMNS), None)
        if role_col:
            notes[target].append(
                f"  -- decide: {n}.{role_col} may say who does more, e.g.\n"
                f"  --   admin : user = {n}({cols_text(o['cols'])} -> {u['cols'][0]}) where {{{role_col} = 'admin'}}"
            )

    # --- permissions and rules ------------------------------------------------------------------
    out = [
        f"-- A first policy drafted by rowstile from the tables in {', '.join(schemas)}.",
        "-- It compiles, and it is a draft: read every '-- decide:' and change what isn't so.",
        "-- Then: rowstile dev (applies it on each save, runs the tests, writes the clients).",
        "",
        f"app role {role}                          -- decide: the Postgres role your app connects as",
        "",
    ]
    rules: list[str] = []
    # Which types' edit and view start somewhere: their own users or links, or a parent whose do. A loop of foreign
    # keys with no owner anywhere in it (Cal.com, Mastodon, GitLab have them) gives nobody anything by inheritance,
    # and the compiler refuses inheriting from it (AZ303): such parents are left out, and the type says so.
    by_type = {tn: n for n, tn in type_names.items()}
    parent_of = {n: {r: by_type[target] for r, target, _, k in rels[n] if k == "parent"} for n in type_names}
    edit_base = {n: type_names[n] == "user" or any(k == "user" for _, _, _, k in rels[n]) for n in type_names}
    view_base = {n: edit_base[n] or not parent_of[n] or any(k == "link" for _, _, _, k in rels[n]) for n in type_names}
    changed = True
    while changed:
        changed = False
        for n in type_names:
            for base in (edit_base, view_base):
                if not base[n] and any(base[p] for p in parent_of[n].values()):
                    base[n] = changed = True
            # where edit starts, view does: a parent that gave n edit has view, which the line above gave n too
            assert view_base[n] or not edit_base[n]

    def in_loop(n: str) -> bool:
        """Whether n's foreign keys lead back to it through other tables (a tree of its own type is no loop)."""
        seen: set[str] = set()
        todo = [p for p in parent_of[n].values() if p != n]
        while todo:
            p = todo.pop()
            if p == n:
                return True
            if p not in seen:
                seen.add(p)
                todo += parent_of[p].values()
        return False

    for n in sorted(type_names, key=lambda x: (type_names[x] != "user", type_names[x])):
        t, tname = by_name[n], type_names[n]
        out.append(f"type {tname} = {n}{key_spec(t)}")
        for rel, target, source, _ in rels[n]:
            out.append(f"  {rel} : {target} = {source}")
        users_edit = [r for r, _, _, k in rels[n] if k == "user"]
        linked = [r for r, _, _, k in rels[n] if k == "link"]
        parents = [r for r, _, _, k in rels[n] if k == "parent"]
        # a group of people inside another of its type (a team's parent team): its members are members above too
        nested = [
            (r, source)
            for r, _, source, k in rels[n]
            if k == "parent" and parent_of[n][r] == n and "," not in source and len(t["pk"]) == 1
        ]
        not_down: set[str] = set()  # parents whose view isn't passed down
        if nested and linked and GROUP_WORDS.search(tname):
            p, column = nested[0]
            member = linked[0]
            out.append(
                f"  {member} : {tname}#{member} = {n}({column} -> {cols_text(t['pk'])})"
                f"   -- the {member}s of the {tname}s inside count here too"
            )
            out.append(
                f"  -- decide: {member}s of the {tname}s inside are {member}s of this one. For this {tname}'s view to pass"
            )
            out.append(
                f"  --   down to those inside instead: remove that line, and write can view = {member} or {p}.view"
            )
            not_down.add(p)
        out += notes[n]
        if tname == "user":
            # your own row, as a relation from the key: what the reference says to write, where a condition on
            # authz.uid() would be a fact about the row to prove and the review
            me = free_name("self", {r for r, _, _, _ in rels[n]})
            out.insert(len(out) - len(notes[n]) - len(rels[n]), f"  {me} : user = {t['pk'][0]}  -- your own row")
            edit = [me] + users_edit + [f"{p}.edit" for p in parents]
            out.append(f"  can edit = {' or '.join(edit)}")
            out.append("  can view = signed_in                  -- decide: may everyone signed in see everyone?")
        else:
            edit = users_edit + [f"{p}.edit" for p in parents if edit_base[parent_of[n][p]]]
            # each parent named once: a drafted type's view holds its edit, so parent.view holds parent.edit, and
            # `edit or parent.view` would name the parent twice at each level (lint warns of what that costs)
            view = (
                (
                    users_edit
                    + linked
                    + [f"{p}.view" for p in parents if view_base[parent_of[n][p]] and p not in not_down]
                )
                if parents
                else ["edit"] + linked
            )
            # nobody edits what it is in: a loop of foreign keys with no owner anywhere in it, or a table nobody
            # changes through the app above it (a list of categories)
            no_owner = (
                "   -- decide: the loop of foreign keys it is in has no owner anywhere; "
                if in_loop(n)
                else "   -- decide: nobody edits what it is in; "
            )
            if not edit:
                out.append(
                    f"  can edit = nobody{no_owner}who edits these?"
                    if parents
                    else "  can edit = nobody                      -- decide: nobody changes these through the app"
                )
            else:
                out.append(
                    f"  can edit = {' or '.join(edit)}"
                    + ("   -- decide: owners, and whoever edits what it is in" if parents else "")
                )
            if not view:
                out.append(f"  can view = signed_in{no_owner}may everyone signed in read them?")
            elif not linked and not parents and not users_edit:
                out.append("  can view = signed_in                  -- decide: a list everyone signed in may read?")
            else:
                out.append(f"  can view = {' or '.join(view)}")
        out.append("")
        r = [f"rules {n}", "  select : view"]
        if tname == "user":
            r += [
                "  update : edit",
                "  -- no insert or delete rule: accounts are made and removed outside the app role",
            ]
        else:
            # in the maker's own name: the relation, where one says it (the language page: write the relation
            # rather than its column again)
            mine = [rel for rel, _, src, k in rels[n] if k == "user" and not src.startswith("[")][:1]
            where = [f"{parents[0]}.edit"] if parents else []
            # a tree of the type itself: "inside one you edit" alone lets nobody make the first row, so a row
            # with nothing above it may be made too, in the maker's name
            above = next((src for rel, _, src, _ in rels[n] if parents and rel == parents[0]), "")
            if mine and parents and parent_of[n][parents[0]] == n and not above.startswith("["):
                insert = f"{mine[0]} and ({parents[0]}.edit or {{{in_sql(above)} is null}})"
            else:
                insert = " and ".join(where + mine) or "signed_in"
            r += [
                f"  insert : {insert}" + ("   -- decide: who may add one" if insert == "signed_in" or parents else ""),
                "  update : edit",
                "  delete : edit",
            ]
        # changing a relation's columns changes who has access: say who may, and check where a row moves to
        rel_cols = [c.strip() for _, _, src, k in rels[n] if k != "link" for c in src.strip("[]").split(",")]
        if rel_cols and tname != "user":
            r.append(
                f"  update {', '.join(dict.fromkeys(rel_cols))} : edit   -- decide: who may change who owns it, or where it is"
            )
        for rel, _, src, k in rels[n]:
            if k == "parent":
                r.append(f"  update {', '.join(c.strip() for c in src.strip('[]').split(','))} after : {rel}.edit")
        rules.append("\n".join(r))
    text = "\n".join(out) + "\n" + "\n\n".join(rules) + "\n"
    if skipped:
        text += "\n-- left out:\n" + "\n".join(skipped) + "\n"
    return text


CATALOG_SQL = r"""
SELECT n.nspname || '.' || c.relname AS name,
  (SELECT json_agg(json_build_array(a.attname, format_type(a.atttypid, a.atttypmod)) ORDER BY a.attnum)
     FROM pg_catalog.pg_attribute a WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped)::text AS columns,
  (SELECT json_agg(a.attname ORDER BY k.i)
     FROM pg_catalog.pg_index x CROSS JOIN LATERAL unnest(x.indkey::int2[]) WITH ORDINALITY k(attnum, i)
     JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid AND a.attnum = k.attnum
     WHERE x.indrelid = c.oid AND x.indisprimary AND k.i <= x.indnkeyatts)::text AS pk,
  (SELECT json_agg(json_build_object(
       'cols', (SELECT json_agg(a.attname ORDER BY k.i) FROM unnest(f.conkey) WITH ORDINALITY k(attnum, i)
                JOIN pg_catalog.pg_attribute a ON a.attrelid = f.conrelid AND a.attnum = k.attnum),
       'ref', rn.nspname || '.' || r.relname,
       'ref_cols', (SELECT json_agg(a.attname ORDER BY k.i) FROM unnest(f.confkey) WITH ORDINALITY k(attnum, i)
                    JOIN pg_catalog.pg_attribute a ON a.attrelid = f.confrelid AND a.attnum = k.attnum)) ORDER BY f.conname)
     FROM pg_catalog.pg_constraint f JOIN pg_catalog.pg_class r ON r.oid = f.confrelid
     JOIN pg_catalog.pg_namespace rn ON rn.oid = r.relnamespace
     WHERE f.conrelid = c.oid AND f.contype = 'f')::text AS fks,
  (SELECT json_agg((SELECT json_agg(a.attname ORDER BY k.i)
                    FROM unnest(x.indkey::int2[]) WITH ORDINALITY k(attnum, i)
                    JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid AND a.attnum = k.attnum
                    WHERE k.i <= x.indnkeyatts))
     FROM pg_catalog.pg_index x
     WHERE x.indrelid = c.oid AND x.indisunique AND NOT x.indisprimary AND x.indpred IS NULL
       AND NOT 0 = ANY (x.indkey::int2[]))::text AS uniques
FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'p') AND NOT c.relispartition
  AND (n.nspname = ANY ($1) OR ($1 IS NULL AND n.nspname NOT LIKE 'pg\_%'
       AND n.nspname NOT IN ('information_schema', 'authz', 'authz_gen', 'authz_int', 'authz_keep')))
ORDER BY 1"""
