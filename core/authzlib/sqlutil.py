"""Small helpers for writing SQL."""

from __future__ import annotations

import re

from .parse import Loc, fail

# The comments that mark rowstile's own RLS policies and masked views: applying, removing and lint know them by
# these alone
POLICY_MARKS = "('rowstile')"
VIEW_MARKS = "('rowstile masked view')"
# ... and the triggers given to the tables under a table rowstile watches (CHILD_TRIGGERS below)
CHILD_TRIGGER_MARK = "rowstile: the trigger of the table above, for the rows stored here"
# In a comment before a DO block that makes a trigger (-- @object trigger ...): the trigger is there only where
# the table is partitioned (database.unchanged looks for it there alone)
IF_PARTITIONED = "@if partitioned"

# Postgres runs a table's row triggers for its own rows and for its partitions' (it copies them there), not for
# rows stored in a table that inherits from it (CREATE TABLE ... INHERITS): read and written through the table
# above, those rows would skip a rule on a column and keep their shares when their key changes. And it runs a
# table's statement triggers only for statements on that table, not for one on a partition or on a table that
# inherits: written there directly, rows would leave inheritance, shares, API keys and the audit behind. So each
# table that inherits is given the row triggers rowstile made on the tables above it, and each partition and
# table that inherits their statement triggers (but those for TRUNCATE alone: emptying one partition is not
# emptying the table, which is what they do). This lists the ones missing, each with the statement that makes
# it; applying runs them (CHILD_TRIGGERS), lint reports them (a table made since).
CHILD_TRIGGERS_FN = f"""-- The triggers above that a table under their table lacks, and the statement that makes each
CREATE FUNCTION authz_int.child_triggers() RETURNS TABLE (child regclass, name name, stmt text)
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $f$
  WITH RECURSIVE below(top, oid) AS (
    SELECT i.inhparent, i.inhrelid FROM pg_inherits i
    UNION SELECT b.top, i.inhrelid FROM pg_inherits i JOIN below b ON i.inhparent = b.oid
  )
  SELECT b.oid::regclass, g.tgname,
         overlay(d.def PLACING ' ON ' || c.name || ' ' FROM strpos(d.def, ' ON ' || p.name || ' ')
                 FOR length(' ON ' || p.name || ' '))
  FROM below b
  JOIN pg_class u ON u.oid = b.oid
  JOIN pg_trigger g ON g.tgrelid = b.top AND NOT g.tgisinternal
   AND CASE WHEN g.tgtype & 1 = 1 THEN NOT u.relispartition         -- a row trigger: Postgres copies it to partitions
            ELSE g.tgtype & 28 <> 0 AND u.relkind IN ('r', 'p') END -- a statement trigger: not for TRUNCATE alone
  JOIN pg_proc f ON f.oid = g.tgfoid AND f.pronamespace = 'authz_int'::regnamespace
  CROSS JOIN LATERAL (SELECT pg_get_triggerdef(g.oid) AS def) d
  CROSS JOIN LATERAL (SELECT format('%I.%I', n.nspname, k.relname) AS name
                      FROM pg_class k JOIN pg_namespace n ON n.oid = k.relnamespace WHERE k.oid = b.top) p
  CROSS JOIN LATERAL (SELECT format('%I.%I', n.nspname, k.relname) AS name
                      FROM pg_class k JOIN pg_namespace n ON n.oid = k.relnamespace WHERE k.oid = b.oid) c
  WHERE NOT EXISTS (SELECT 1 FROM pg_description x WHERE x.objoid = g.oid AND x.classoid = 'pg_trigger'::regclass
                    AND x.description = '{CHILD_TRIGGER_MARK}')
    AND NOT EXISTS (SELECT 1 FROM pg_trigger h WHERE h.tgrelid = b.oid AND h.tgname = g.tgname)
$f$;"""
CHILD_TRIGGERS = f"""-- The partitions of a table rowstile watches and the tables that inherit from it: the triggers made above, on
-- each, for the rows stored there and the statements on it
DO $ch$
DECLARE r record;
BEGIN
  FOR r IN SELECT * FROM authz_int.child_triggers() LOOP
    EXECUTE r.stmt;
    EXECUTE pg_catalog.format('COMMENT ON TRIGGER %I ON %s IS %L', r.name, r.child, '{CHILD_TRIGGER_MARK}');
  END LOOP;
END $ch$;"""
# ... and before a migration drops what they call (they are made again by CHILD_TRIGGERS, which every one runs)
DROP_CHILD_TRIGGERS = f"""-- the triggers given to the tables under others: made again below, on what this migration makes
-- @locks ACCESS EXCLUSIVE: the partitions and child tables of the tables rowstile watches
DO $authz_ch$
DECLARE r record;
BEGIN
  FOR r IN SELECT g.tgname, g.tgrelid::regclass AS tbl FROM pg_catalog.pg_trigger g
           JOIN pg_catalog.pg_description d ON d.objoid = g.oid AND d.classoid = 'pg_catalog.pg_trigger'::regclass
           WHERE d.description = '{CHILD_TRIGGER_MARK}' LOOP
    EXECUTE pg_catalog.format('DROP TRIGGER %I ON %s', r.tgname, r.tbl);
  END LOOP;
END $authz_ch$;"""

# What applying (output.py) and removing (database.REMOVE_SQL) both run: here, so that removing doesn't import the
# compiler. The policies the previous version made, its masked views, and the tables left with no rules
DROP_OLD_POLICIES = f"""-- Remove the policies the previous version of this policy made (remembering their tables)
CREATE TEMP TABLE authz_old_tables ON COMMIT DROP AS
  SELECT DISTINCT p.polrelid::regclass AS tbl
  FROM pg_policy p
  JOIN pg_description d ON d.objoid = p.oid AND d.classoid = 'pg_policy'::regclass
  WHERE d.description IN {POLICY_MARKS};
DO $d$
DECLARE old record;
BEGIN
  FOR old IN SELECT pol.polname, pol.polrelid::regclass AS tbl
             FROM pg_policy pol
             JOIN pg_description d ON d.objoid = pol.oid AND d.classoid = 'pg_policy'::regclass
             WHERE d.description IN {POLICY_MARKS} LOOP
    EXECUTE format('DROP POLICY %I ON %s', old.polname, old.tbl);
  END LOOP;
END $d$;"""

DROP_MASKED_VIEWS = f"""-- The masked views the previous version made (views built on them stop this: drop those first)
DO $mv$
DECLARE v record;
BEGIN
  FOR v IN SELECT c.oid::regclass AS name FROM pg_class c JOIN pg_description d ON d.objoid = c.oid
           AND d.classoid = 'pg_class'::regclass WHERE c.relkind = 'v' AND d.description IN {VIEW_MARKS} LOOP
    EXECUTE format('DROP VIEW %s', v.name);
  END LOOP;
END $mv$;"""

LOST_RULES = """-- Tables that had rules before but have none now keep row-level security on
DO $l$
DECLARE t record;
BEGIN
  FOR t IN SELECT o.tbl FROM pg_temp.authz_old_tables o JOIN pg_class c ON c.oid = o.tbl
           WHERE c.relrowsecurity AND NOT EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = o.tbl) LOOP
    RAISE WARNING '% has no rules any more, and row-level security is still on, so the app role sees none of its rows. If that is not what you want: ALTER TABLE % DISABLE ROW LEVEL SECURITY', t.tbl, t.tbl;
  END LOOP;
END $l$;"""


# What a name in SQL may start with: Postgres takes any character past ASCII as a letter (archivé, année). The same
# as statements.LETTER (statements.py is also loaded on its own, by the mutation tests: it imports nothing of ours)
LETTER = r"A-Za-z_\x80-\U0010ffff"
# a name Postgres reads unquoted: a letter, then letters, digits and $
NAME = rf"[{LETTER}][{LETTER}0-9$]*"
# where a name doesn't go on: not after (or before) a character a name holds
NOT_AFTER_NAME = rf"(?<![{LETTER}0-9$])"
NOT_BEFORE_NAME = rf"(?![{LETTER}0-9$])"
ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def fold(name: str) -> str:
    """An unquoted name as Postgres reads it: its ASCII letters in lower case, the others as written (ARCHIVÉ is
    archivÉ; the Kelvin sign, U+212A, stays as written, where Python's lower() makes it k)."""
    return name.translate(ASCII_LOWER)


def ident(name: str) -> str:
    """Generated names longer than Postgres allows (63 bytes) are shortened
    with a hash, the same way every time they appear."""
    if len(name.encode()) > 63:
        import hashlib  # here: a command that only asks the database doesn't load it

        # a short, stable tag for the name, nothing secret: changing it would rename what databases hold
        digest = hashlib.sha1(name.encode(), usedforsecurity=False).hexdigest()[:8]
        name = name.encode()[:54].decode(errors="ignore") + "_" + digest
    return name


def dep_trigger(tree: str) -> str:
    """The name of the triggers a tree puts on the tables its conditions read (trees.deps_sql), which a migration
    that rebuilds the tree drops (migrate.py): shortened as every other generated name."""
    return ident("authz_" + tree + "_dep")


def q(name: str) -> str:
    """Quote an identifier."""
    name = ident(name)
    return '"' + name.replace('"', '""') + '"'


def qt(table: str) -> str:
    """Quote a schema.table name from the policy."""
    return ".".join(q(part) for part in table.split("."))


# Postgres keeps a policy, a view and a BEGIN ATOMIC body as parsed, with a dependency on each column they name, and
# `.*` names every column there: what passes or reads a whole row of the app's table must not spell it out, or no
# column of the table could be dropped, not even one no rule reads.


def from_row(param: str, alias: str) -> str:
    """A function's row argument as a table named alias, in a FROM: only the columns read from it are named."""
    return f"pg_catalog.unnest(ARRAY[{param}]) AS {alias}"


def whole_row(alias: str, table: str) -> str:
    """The row of alias, as the table's type, to pass to a function: no column is named."""
    return f"({alias}.*)::{qt(table)}"


def lit(s: object) -> str:
    return "'" + str(s).replace("'", "''") + "'"


def principal_text(ptype: str, pid: str) -> str:
    """SQL naming a principal as the audit trail, created_by and the SDKs write it: a user by their id ('42'), or
    'user:<id>' when the id holds ':' or is 'nobody' ('user:service:1'), so it can't read as another principal or
    as nobody; another principal as type:id ('service:3'). ptype and pid are SQL: the type ('' or 'user': a user)
    and the id (NULL gives NULL)."""
    return (
        f"CASE WHEN coalesce({ptype}, '') IN ('', 'user') "
        f"THEN CASE WHEN pg_catalog.strpos({pid}, ':') > 0 OR {pid} = 'nobody' THEN 'user:' || {pid} ELSE {pid} END "
        f"ELSE {ptype} || ':' || {pid} END"
    )


def union(parts: list[str]) -> str:
    return parts[0] if len(parts) == 1 else "\n  UNION ALL\n  ".join(f"({p})" for p in parts)


def or_join(parts: list[str]) -> str:
    return parts[0] if len(parts) == 1 else "(" + "\n    OR ".join(parts) + ")"


def strip_literals(sql: str, name: str = '""') -> str:
    """SQL as only its code reads, for keyword checks: a string literal ('...', E'...', $$...$$) as '', a quoted
    name as `name`, a comment as a space. The quotes are read as Postgres reads them (sql_code)."""
    return "".join(
        text if code else name if text.startswith('"') else " " if text.startswith(("/*", "--")) else "''"
        for code, text in sql_code(sql)
    )


# a word that makes a condition read a table: a subquery (select ...) or one written as `table t`
READS_TABLE = re.compile(r"\b(select|table)\b", re.IGNORECASE)


def reads_tables(sql: str) -> bool:
    return bool(READS_TABLE.search(strip_literals(sql)))


# built-in functions that read nothing but their arguments (and the clock or the session): a condition calling only
# these reads only its row, whoever runs it
PURE_FUNCTIONS = frozenset(
    {
        "abs",
        "age",
        "array_length",
        "array_position",
        "array_positions",
        "array_to_string",
        "btrim",
        "cardinality",
        "ceil",
        "ceiling",
        "char_length",
        "character_length",
        "clock_timestamp",
        "concat",
        "concat_ws",
        "current_setting",
        "date_part",
        "date_trunc",
        "floor",
        "format",
        "gen_random_uuid",
        "initcap",
        "isfinite",
        "json_array_length",
        "json_typeof",
        "jsonb_array_length",
        "jsonb_extract_path",
        "jsonb_extract_path_text",
        "jsonb_typeof",
        "left",
        "length",
        "lower",
        "lpad",
        "ltrim",
        "make_date",
        "make_interval",
        "make_timestamp",
        "md5",
        "mod",
        "now",
        "num_nonnulls",
        "num_nulls",
        "octet_length",
        "pg_input_is_valid",
        "power",
        "random",
        "regexp_like",
        "regexp_match",
        "regexp_matches",
        "regexp_replace",
        "repeat",
        "replace",
        "reverse",
        "right",
        "round",
        "rpad",
        "rtrim",
        "sign",
        "split_part",
        "sqrt",
        "starts_with",
        "statement_timestamp",
        "string_to_array",
        "strpos",
        "substr",
        "timeofday",
        "to_char",
        "to_date",
        "to_number",
        "to_timestamp",
        "transaction_timestamp",
        "trunc",
        "upper",
        "authz.uid",
        "authz.ctx",
        "authz.principal",
        "authz.link_hashes",
    }
)
# words followed by ( that are SQL's own, not functions
CALL_WORDS = frozenset(
    {
        "all",
        "and",
        "any",
        "array",
        "between",
        "case",
        "cast",
        "coalesce",
        "else",
        "exists",
        "extract",
        "filter",
        "greatest",
        "in",
        "is",
        "least",
        "not",
        "nullif",
        "or",
        "over",
        "overlay",
        "position",
        "row",
        "some",
        "substring",
        "then",
        "trim",
        "values",
        "when",
        "within",
    }
)
CALL = re.compile(rf"(?<![{LETTER}0-9$.\"])({NAME}(?:\s*\.\s*{NAME})?)\s*\(")
# the operators Postgres has for its own types (comparison, arithmetic, text, patterns, arrays, JSON, ranges, network
# addresses): any other is one an app made, and its function may read anything
BUILTIN_OPERATORS = frozenset(
    {
        "=",
        "<>",
        "!=",
        "<",
        ">",
        "<=",
        ">=",
        "+",
        "-",
        "*",
        "/",
        "%",
        "^",
        "||",
        "|/",
        "||/",
        "@",
        "&",
        "|",
        "#",
        "~",
        "<<",
        ">>",
        "~~",
        "~~*",
        "!~~",
        "!~~*",
        "~*",
        "!~",
        "!~*",
        "^@",
        "@>",
        "<@",
        "&&",
        "?",
        "?|",
        "?&",
        "->",
        "->>",
        "#>",
        "#>>",
        "#-",
        "@?",
        "@@",
        "-|-",
        "&<",
        "&>",
        "<<=",
        ">>=",
        "<->",
    }
)
OPERATOR = re.compile(r"[+\-*/<>=~!@#%^&|`?]+")


def operators(code: str) -> list[str]:
    """The operators in SQL code, cut as Postgres cuts them: a name of several characters doesn't end in + or -
    unless it holds one of ~ ! @ # % ^ & | ` ? (so `a=-1` is `=` then `-`)."""
    out: list[str] = []
    for m in OPERATOR.finditer(code):
        op = m.group(0)
        if len(op) > 1 and not any(c in op for c in "~!@#%^&|`?"):
            tail = len(op) - len(op.rstrip("+-"))
            if tail:
                out += [op[:-tail]] if op[:-tail] else []
                out += list(op[-tail:])
                continue
        out.append(op)
    return out


def reads_more(sql: str) -> bool:
    """Whether a condition reads more than its row's own columns: a subquery, or a function other than a
    built-in that reads nothing, called by name or as an operator. Then who runs it decides what it sees, so the
    policy runs it as its owner."""
    # a quoted name stands as one no built-in has (app."f"(x) and "app".f(x) are calls of a function of the
    # app's), a comment as a space (f /* c */ (x) is a call), a string literal as an empty one
    shown = strip_literals(sql, "_quoted_")
    if READS_TABLE.search(shown):
        return True
    for m in CALL.finditer(shown):
        name = fold(re.sub(r"\s+", "", m.group(1)))
        if name not in PURE_FUNCTIONS and name not in CALL_WORDS:
            return True
    return any(op not in BUILTIN_OPERATORS for op in operators(shown))


# A view emptied in place: the same columns (names, types, collations), reading nothing. What the app built on
# the view stays while what the view read is dropped and made again; CREATE OR REPLACE VIEW then defines it again.
# VIEW is the view's oid, in the SQL around it.
STUB_COLUMNS = """(SELECT string_agg(format('NULL::%s%s AS %I', pg_catalog.format_type(a.atttypid, a.atttypmod),
        CASE WHEN a.attcollation <> 0 AND a.attcollation <> t.typcollation
             THEN format(' COLLATE %I.%I', cn.nspname, co.collname) ELSE '' END, a.attname), ', ' ORDER BY a.attnum)
      FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_type t ON t.oid = a.atttypid
      LEFT JOIN pg_catalog.pg_collation co ON co.oid = a.attcollation
      LEFT JOIN pg_catalog.pg_namespace cn ON cn.oid = co.collnamespace
      WHERE a.attrelid = VIEW AND a.attnum > 0 AND NOT a.attisdropped)"""


def with_uid(sql: str) -> str:
    """authz.uid() inside conditions runs once per query, not once per row."""
    return re.sub(r"\bauthz\s*\.\s*uid\s*\(\s*\)", "(SELECT authz.uid())", sql)


def name_start(c: str) -> bool:
    """Whether a name in SQL may start with c (Postgres takes any character past ASCII as a letter)."""
    return c.isalpha() or c == "_" or c >= "\x80"


def name_part(c: str) -> bool:
    """Whether a name in SQL may go on with c."""
    return c.isalnum() or c in "_$" or c >= "\x80"


# a dollar quote's opening tag, where a token starts: $$, or $tag$
DOLLAR_OPEN = re.compile(rf"\$(?:[{LETTER}][{LETTER}0-9]*)?\$")


def literal_end(sql: str, i: int, escapes: bool) -> int:
    """Where the string literal opened by the quote at sql[i] ends (the index after its closing quote, or the
    text's length if it doesn't close). A quote doubled is part of it; in an E'' string a backslash escapes the
    next character (E'don\\'t')."""
    j, n = i + 1, len(sql)
    while j < n:
        if escapes and sql[j] == "\\":
            j += 2
        elif sql[j] != "'":
            j += 1
        elif sql[j + 1 : j + 2] == "'":
            j += 2
        else:
            return j + 1
    return n


def sql_code(sql: str) -> list[tuple[bool, str]]:
    """sql in pieces, (is it code, text), read token by token as Postgres reads it: string literals ('...',
    E'...' with its backslashes, $$...$$ and $tag$...$tag$), quoted names ("...") and comments (/* ... */, which
    nest, and -- to the line's end) are not code. Each piece of every other kind is read whole, so nothing
    inside one starts a quote: e'...' is an E'' string but name'...' isn't, and a$$b is a name. Every reading
    of a condition's code (reads_tables, reads_more, the stability check, this.) goes through this one."""
    out: list[tuple[bool, str]] = []
    i, start, n = 0, 0, len(sql)
    while i < n:
        c = sql[i]
        end = -1
        if c.isdigit() or name_start(c):  # a number (1e5, 0x1f) or a name: code, read whole
            j = i + 1
            while j < n and (name_part(sql[j]) if name_start(c) else sql[j].isalnum() or sql[j] == "_"):
                j += 1
            if j - i == 1 and c in "eE" and sql[j : j + 1] == "'":
                i, end = j, literal_end(sql, j, True)  # the E stays with the code before
            else:
                i = j
                continue
        elif c == "'":
            end = literal_end(sql, i, False)
        elif c == '"':
            j = sql.find('"', i + 1)
            while j != -1 and sql[j + 1 : j + 2] == '"':
                j = sql.find('"', j + 2)
            end = n if j == -1 else j + 1
        elif c == "$" and (tag := DOLLAR_OPEN.match(sql, i)):
            j = sql.find(tag.group(0), tag.end())
            end = n if j == -1 else j + len(tag.group(0))
        elif sql.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                step = sql[j : j + 2]
                depth += 1 if step == "/*" else -1 if step == "*/" else 0
                j += 2 if step in ("/*", "*/") else 1
            end = j
        elif sql.startswith("--", i):
            j = sql.find("\n", i)
            end = n if j == -1 else j
        if end == -1:
            i += 1
            continue
        if start < i:
            out.append((True, sql[start:i]))
        out.append((False, sql[i:end]))
        i = start = end
    if start < n:
        out.append((True, sql[start:]))
    return out


# `this.` in a condition: the row the condition is about (not a part of a longer name, nor after a dot)
THIS = re.compile(rf"(?<![{LETTER}0-9$.\"])this\s*\.\s*(?=[{LETTER}\"])", re.IGNORECASE)
# `arg('ip')` in a caveat: what the share was made with (Compiler.caveat_sql)
CAVEAT_ARG = re.compile(r"\barg\s*\(\s*'([^']*)'\s*\)")


def this_spans(sql: str) -> list[tuple[int, int]]:
    """Where a condition writes `this.` (in its code, not in quoted text or comments)."""
    if "this" not in sql.lower():
        return []
    code: list[bool] = []
    for is_code, text in sql_code(sql):
        code += [is_code] * len(text)
    return [(m.start(), m.end()) for m in THIS.finditer(sql) if code[m.start()]]


def names_this(sql: str) -> bool:
    """Whether a condition names its row as `this.`."""
    return bool(this_spans(sql))


def this_alone(sql: str) -> bool:
    """Whether a condition writes the word `this` other than as `this.` (a table called this, say)."""
    if "this" not in sql.lower():
        return False
    return any(
        code and re.search(rf"(?<![{LETTER}0-9$.\"])this{NOT_BEFORE_NAME}(?!\s*\.)", text, re.IGNORECASE)
        for code, text in sql_code(sql)
    )


# The alias a condition's row gets where the condition's own SQL could hide the alias of the place it goes in
# (on_row). A condition may write no name that starts with RESERVED (AZ113), so nothing in it can be called that.
RESERVED = "authz__"
ROW_ALIAS = RESERVED + "this"
IDENT_RE = re.compile(NAME)
QUOTED_RE = re.compile(r'"(?:[^"]|"")*"')


def names_in(sql: str) -> set[str]:
    """Every name a piece of SQL writes, in its code or quoted ("..."), in lower case."""
    out: set[str] = set()
    for code, text in sql_code(sql):
        if code:
            out.update(m.group(0).lower() for m in IDENT_RE.finditer(text))
        elif text.startswith('"'):
            out.add(text[1:-1].replace('""', '"').lower())
    return out


def reserved_names(sql: str) -> list[str]:
    """The names a piece of SQL writes that start with RESERVED, as written."""
    out: list[str] = []
    for code, text in sql_code(sql):
        if code:
            out += [m.group(0) for m in IDENT_RE.finditer(text) if m.group(0).lower().startswith(RESERVED)]
        elif text.startswith('"') and text[1:-1].lower().startswith(RESERVED):
            out.append(text)
    return out


def on_row(sql: str, alias: str) -> str:
    """A condition with `this.` written as the alias its row has where the condition is placed: `this.id` is
    `r.id` in a view, `"files".id` in a row-level security policy, `NEW`'s columns in a trigger. Where a query
    of the condition's own could call one of its tables by that alias (`select 1 from app.users u` where the row
    is u, `from app.folders` where it is "folders"), `this.` would name that table there: then the row's columns
    `this.` reads are taken first, under a name no condition writes, `(SELECT ... FROM (SELECT u.id) AS
    authz__this)`. Elsewhere the condition reads the alias itself, as the planner likes best."""
    spans = this_spans(sql)
    if not spans:
        return sql
    name = alias[1:-1].replace('""', '"') if alias.startswith('"') else alias
    hidden = reads_tables(sql) and name.lower() in names_in(sql)
    out, last, cols = [], 0, []
    for start, end in spans:
        m = QUOTED_RE.match(sql, end) or IDENT_RE.match(sql, end)
        if m and m.group(0) not in cols:
            cols.append(m.group(0))
        out += [sql[last:start], (ROW_ALIAS if hidden else alias) + "."]
        last = end
    cond = "".join(out) + sql[last:]
    if not hidden:
        return cond
    return f"(SELECT ({cond}) FROM (SELECT {', '.join(f'{alias}.{c}' for c in cols)}) AS {ROW_ALIAS})"


def row_cond(sql: str, alias: str) -> str:
    """A condition placed where its row is aliased `alias`: `this.` as that alias, authz.uid() once per query."""
    return with_uid(on_row(sql, alias))


# Conditions whose result is stored (inheritance) must give the same answer for
# everyone at any time.
UNSTABLE = re.compile(
    r"\b(now|current_timestamp|current_date|current_time|localtime|localtimestamp|"
    r"clock_timestamp|statement_timestamp|transaction_timestamp|timeofday|random|"
    r"current_setting|current_user|session_user|current_role|user|"
    r"authz\s*\.\s*(uid|ctx|me))\b",
    re.IGNORECASE,
)


# the text of a date or time literal that means the current time ('now', 'today', ...)
TIME_WORDS = re.compile(r"\s*(now|today|tomorrow|yesterday)\s*", re.IGNORECASE)


def literal_text(text: str) -> str:
    """What a string literal sql_code gives holds between its quotes ('...', $$...$$, $tag$...$tag$)."""
    close = text[: text.index("$", 1) + 1] if text.startswith("$") else "'"
    return text[len(close) :].removesuffix(close)


def check_stable_condition(cond: str, loc: Loc, what: str = "limit inheritance") -> None:
    lit_m = next(
        (
            m
            for code, text in sql_code(cond)
            if not code and text[0] in "'$" and (m := TIME_WORDS.fullmatch(literal_text(text)))
        ),
        None,
    )
    if lit_m:
        fail(
            loc,
            f"{{{cond}}} can't {what}: '{lit_m.group(1)}' means the current time, but inherited "
            f"rights are stored, so the condition must give the same answer for every user at any time",
            "AZ305",
        )
    m = UNSTABLE.search(strip_literals(cond))
    if m:
        fail(
            loc,
            f"{{{cond}}} can't {what}: it depends on {m.group(0)}, but inherited "
            f"rights are stored, so the condition must give the same answer for every user "
            f"at any time",
            "AZ305",
        )
