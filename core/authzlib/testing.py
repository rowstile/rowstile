"""Policy tests. Three kinds, compiled into one plpgsql function that returns a row per check:
- the unnamed `test` section: checks against the data already in the database;
- named tests (`test "name"`): their own data (`given`), checks as someone, statements run as the app
  role signed in as someone (`as`); each runs in a subtransaction that is always rolled back;
- the invariants, once, over the data already there.
"""

from __future__ import annotations

import re

from .compiler import Core
from .parse import AsStep, CheckStep, Loc, PolicyError, Scenario, Step, fail, parse_policy
from .sqlutil import lit
from .statements import WORD, split

FN = "pg_temp.authz_policy_tests"
VAR = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)(?!\$)")  # $name, not a $tag$ dollar quote
WRITES = ("insert", "update", "delete", "merge")
COVERAGE = "authz:coverage"  # the test name of coverage rows (tests_function_sql(coverage=True))
SQL_NL = "E'\\n'"  # a newline in SQL (Python 3.11 allows no backslash inside an f-string's braces)


class TestMixin(Core):
    coverage_rows = False  # tests_function_sql(coverage=True): rows for the coverage report

    def add_test_files(self, files: dict[str, str]) -> None:
        """Named tests from separate files (name -> text), which hold nothing but tests."""
        for name, text in sorted(files.items()):
            try:
                pol = parse_policy(text, name, files={})
            except PolicyError as e:
                # a mistake in a test file is named with its file, like an included one (it says `line N: ...`: the
                # file is read as the policy, whose own lines say no file)
                e.args = (f"{name} {e}",)
                raise
            for sc in pol.scenarios:
                assert sc.loc is not None  # (only the unnamed test section has no line of its own)
                for loc in [sc.loc] + [st.loc for st in sc.steps]:
                    loc.file = name
            if (
                pol.types
                or pol.rules
                or pol.tests
                or pol.invariants
                or pol.scopes
                or pol.caveats
                or pol.role is not None
            ):
                raise PolicyError(
                    f'{name}: a test file holds only named tests: test "name" followed by its lines', "AZ106"
                )
            for sc in pol.scenarios:
                if any(x.name == sc.name for x in self.pol.scenarios):
                    fail(sc.loc or 0, f"there is already a test named {sc.name!r}", "AZ109")
                self.pol.scenarios.append(sc)

    def check_scenarios(self) -> None:
        def known(text: str | None, loc: Loc, bound: set[str]) -> None:
            for m in VAR.finditer(text or ""):
                if m.group(1) not in bound:
                    fail(
                        loc,
                        f"${m.group(1)} is not named yet: name it first, with given {m.group(1)} = "
                        f"{{INSERT ... RETURNING id}}",
                        "AZ501",
                    )

        section = Scenario("test section", None, [*self.tests])
        scenarios: list[Scenario] = ([section] if self.tests else []) + self.pol.scenarios
        for sc in scenarios:
            bound: set[str] = set()
            for st in sc.steps:
                if st.kind == "given":
                    known(st.sql, st.loc, bound)
                    if st.var:
                        bound.add(st.var)
                    continue
                known(st.who, st.loc, bound)
                if st.kind == "as":
                    known(st.sql, st.loc, bound)
                if st.ptype != "anyone" and not self.is_principal(st.ptype or ""):
                    signs_in = [t.name for t in self.types.values() if t.principal]
                    fail(
                        st.loc,
                        f"'{st.ptype}' doesn't sign in: a test acts as anyone or as one of {', '.join(signs_in)}",
                        "AZ502",
                    )
                for scope in st.scopes:
                    # 'read' is built in unless the policy says its own
                    if scope not in self.pol.scopes and scope != "read":
                        have = sorted({*self.pol.scopes, "read"})
                        fail(st.loc, f"no scope '{scope}' in the policy (it has: {', '.join(have)})", "AZ503")
                if st.kind == "check":
                    known(st.obj, st.loc, bound)
                    self.check_test_perm(st.type or "", st.perm or "", st.loc)

    def check_test_perm(self, type_: str, perm: str, loc: Loc) -> None:
        if type_ not in self.types:
            fail(loc, f"unknown type '{type_}'", "AZ201")
        perms = self.public_perms(self.T(type_))
        if perm not in perms:
            fail(loc, f"{type_} has no permission '{perm}' (it has: {', '.join(perms)})", "AZ203")

    # --- SQL -------------------------------------------------------------
    def tests_function_sql(self, coverage: bool = False) -> str:
        """CREATE FUNCTION pg_temp.authz_policy_tests(), returning (test, line, ok, detail) per check. With
        coverage, each passing check that someone can do something adds a row (test COVERAGE) whose detail is
        authz.explain's answer: the branches it made true (database.coverage)."""
        self.coverage_rows = coverage
        self.check_scenarios()
        section = Scenario("test section", None, [*self.tests])
        scenarios: list[Scenario] = ([section] if self.tests else []) + self.pol.scenarios
        variables: list[str] = []
        blocks: list[str] = []
        for n, sc in enumerate(scenarios, 1):
            names: dict[str, str] = {}
            for st in sc.steps:
                if st.kind == "given" and st.var:
                    names[st.var] = f"v{n}_{st.var}"
            variables += [f"{v} text;" for v in names.values()]
            steps = "".join(self.step_sql(st, names) for st in sc.steps)
            blocks.append(f"""  -- {sc.name}{f" ({sc.loc})" if sc.loc else ""}
  v_test := {lit(sc.name)};
  BEGIN
    PERFORM set_config('authz.user_id', '', true), set_config('authz.principal_type', '', true),
            set_config('authz.scopes', '', true);
{steps}    RAISE EXCEPTION USING ERRCODE = 'AZT00';     -- a test's data never stays
  EXCEPTION
    WHEN SQLSTATE 'AZT00' THEN NULL;
    WHEN OTHERS THEN
      PERFORM set_config('role', v_role, true);
      {self.add_result("v_line", "false", "v_text || " + SQL_NL + " || 'error: ' || SQLERRM")}
  END;
""")
        invariants = ""
        if self.pol.invariants:
            # who broke it: a user's id, or another principal as the check names it ('service:3')
            others = "".join(
                f"WHEN starts_with(v_inv.user_id, {lit(t.name + ':')}) THEN {lit(t.name + ' ')} || "
                f"substr(v_inv.user_id, {len(t.name) + 2}) "
                for t in self.types.values()
                if t.principal and t.name != "user"
            )
            who = "'user ' || coalesce(v_inv.user_id, '(nobody)')"
            if others:
                who = f"CASE {others}ELSE {who} END"
            invariants = f"""  v_test := 'invariants'; v_line := ''; v_n := 0;
  PERFORM set_config('authz.user_id', '', true), set_config('authz.principal_type', '', true),
          set_config('authz.scopes', '', true);
  FOR v_inv IN SELECT * FROM authz.check_invariants() LOOP
    v_n := v_n + 1;
    {self.add_result("''", "false", "'invariant ' || v_inv.invariant || ': ' || " + who + " || ' can reach ' || v_inv.object_ids::text", "'invariant ' || v_inv.invariant")}
  END LOOP;
  IF v_n = 0 THEN
    {self.add_result("''", "true", lit(f"{len(self.pol.invariants)} invariant(s) hold"))}
  END IF;
"""
        return f"""DROP FUNCTION IF EXISTS {FN}();
CREATE FUNCTION {FN}() RETURNS TABLE (test text, line text, ok boolean, detail text)
LANGUAGE plpgsql AS $authz_tests$
#variable_conflict use_column
DECLARE
  r_test text[] := '{{}}'; r_line text[] := '{{}}'; r_ok boolean[] := '{{}}'; r_detail text[] := '{{}}';
  v_test text; v_line text; v_text text; v_n bigint; v_ok boolean; v_res text; v_msg text; v_json jsonb;
  v_row text; v_detail text; v_inv record; v_write boolean;
  v_role text := current_setting('role');
  v_me text := coalesce(current_setting('authz.user_id', true), '');
  v_pt text := coalesce(current_setting('authz.principal_type', true), '');
  v_scopes text := coalesce(current_setting('authz.scopes', true), '');
  {" ".join(variables)}
BEGIN
{"".join(blocks)}{invariants}  PERFORM set_config('authz.user_id', v_me, true), set_config('authz.principal_type', v_pt, true),
          set_config('authz.scopes', v_scopes, true);
  RETURN QUERY SELECT * FROM unnest(r_test, r_line, r_ok, r_detail);
END $authz_tests$;
"""

    def coverage_sql(self, st: CheckStep, obj: str) -> str:
        if not self.coverage_rows:
            return ""
        explain = f"(SELECT string_agg(l, {SQL_NL}) FROM authz.explain({lit(st.type)}, {obj}, {lit(st.perm)}) l)"
        return "\n      " + self.add_result("v_line", "true", explain, test=lit(COVERAGE))

    @staticmethod
    def add_result(line: str, ok: str, detail: str, test: str = "v_test") -> str:
        return (
            f"r_test := r_test || ({test})::text; r_line := r_line || ({line})::text; "
            f"r_ok := r_ok || {ok}; r_detail := r_detail || ({detail})::text;"
        )

    @staticmethod
    def value_sql(v: str | None, names: dict[str, str]) -> str:
        """A test's id: $name is its variable, anything else a literal."""
        v = v or ""
        return names[v[1:]] if v.startswith("$") else lit(v)

    @staticmethod
    def statement_sql(sql: str | None, names: dict[str, str]) -> str:
        """A statement as a text expression, with each $name replaced by its value, quoted."""
        sql = sql or ""
        parts: list[str] = []
        last = 0
        for m in VAR.finditer(sql):
            parts += [lit(sql[last : m.start()]), f"quote_nullable({names[m.group(1)]})"]
            last = m.end()
        parts.append(lit(sql[last:]))
        return " || ".join(p for p in parts if p != "''") or "''"

    @staticmethod
    def one_statement(sql: str | None) -> str:
        """A statement that goes inside another, without the ';' that may end it."""
        parts = split(sql or "")
        return parts[0][1] if len(parts) == 1 else sql or ""

    def sign_in_sql(self, st: CheckStep | AsStep, names: dict[str, str]) -> str:
        uid = "''" if st.ptype == "anyone" else self.value_sql(st.who, names)
        pt = "''" if st.ptype in ("anyone", "user") else lit(st.ptype)
        # the scopes a key or a token would carry (`with scope read`); none: not limited
        return (
            f"    PERFORM set_config('authz.user_id', coalesce({uid}, ''), true), "
            f"set_config('authz.principal_type', {pt}, true), "
            f"set_config('authz.scopes', {lit(','.join(st.scopes))}, true);\n"
        )

    def step_sql(self, st: Step, names: dict[str, str]) -> str:
        head = f"    v_line := {lit(str(st.loc))}; v_text := {lit(st.text)};\n"
        if st.kind == "given":
            stmt = self.statement_sql(self.one_statement(st.sql) if st.var else st.sql, names)
            reset = (
                "    PERFORM set_config('authz.user_id', '', true), set_config('authz.principal_type', '', true), "
                "set_config('authz.scopes', '', true);\n"
            )
            if not st.var:
                return head + reset + f"    EXECUTE {stmt};\n"
            var = names[st.var]
            return (
                head
                + reset
                + f"""    EXECUTE 'WITH authz_q AS (' || {stmt} || {SQL_NL} || ') SELECT count(*), (array_agg(to_jsonb(authz_q)))[1], '
         || '(array_agg(ROW(authz_q.*)::text))[1] FROM authz_q' INTO v_n, v_json, v_row;
    IF v_n <> 1 THEN
      RAISE EXCEPTION 'given {st.var} = {{...}} returned % rows: it must return one (RETURNING id)', v_n;
    END IF;
    {var} := CASE WHEN (SELECT count(*) FROM jsonb_object_keys(v_json)) = 1
                 THEN (SELECT e.value FROM jsonb_each_text(v_json) e) ELSE v_row END;
"""
            )
        if st.kind == "check":
            obj = self.value_sql(st.obj, names)
            want = "true" if st.expect else "false"
            return (
                head
                + self.sign_in_sql(st, names)
                + f"""    v_ok := authz.can({lit(st.type)}, {obj}, {lit(st.perm)});
    IF v_ok IS DISTINCT FROM {want} THEN
      v_msg := (SELECT string_agg(l, E'\\n') FROM authz.explain({lit(st.type)}, {obj}, {lit(st.perm)}) l);
      {self.add_result("v_line", "false", "v_text || " + SQL_NL + " || coalesce(v_msg, '')")}
    ELSE
      {self.add_result("v_line", "true", "v_text")}{self.coverage_sql(st, obj) if st.expect else ""}
    END IF;
"""
            )
        # as: the statement as the app role, signed in as someone; its own subtransaction
        counting = isinstance(st.expect, int)
        stmt = self.statement_sql(self.one_statement(st.sql) if counting else st.sql, names)
        # A write that changes no row is refused. The row count is the last statement's, so its first word says
        # whether it writes (comments aside); after WITH only its plan says, and Postgres is asked for it.
        parts = [x for _, x in split(st.sql or "")]
        m = WORD.match(parts[-1]) if parts else None
        verb = m.group(0).lower() if m else ""
        write = "true" if verb in WRITES else "v_write" if verb == "with" and len(parts) == 1 else "false"
        plan = (
            f"      EXECUTE 'EXPLAIN (FORMAT JSON) ' || {stmt} INTO v_json;\n"
            "      v_write := v_json->0->'Plan'->>'Node Type' = 'ModifyTable';\n"
            if write == "v_write" and not counting
            else ""
        )
        run = (
            f"      EXECUTE 'SELECT count(*) FROM (' || {stmt} || {SQL_NL} || ') authz_q' INTO v_n;\n"
            if counting
            else f"{plan}      EXECUTE {stmt};\n      GET DIAGNOSTICS v_n = ROW_COUNT;\n"
        )
        outcome = (
            "'allowed'"
            if counting or write == "false"
            else f"CASE WHEN {write} AND v_n = 0 THEN 'refused' ELSE 'allowed' END"
        )
        if counting:
            passed, got = (
                f"v_res = 'allowed' AND v_n = {st.expect}",
                "CASE WHEN v_res = 'allowed' THEN 'sees ' || v_n || ' row(s)' ELSE v_msg END",
            )
        else:
            passed = f"v_res = {lit(st.expect)}"
            got = (
                "CASE v_res WHEN 'allowed' THEN 'allowed' || CASE WHEN v_n > 0 THEN ' (' || v_n || ' row(s))' ELSE '' END "
                "WHEN 'refused' THEN 'refused: ' || v_msg ELSE v_msg END"
            )
        return (
            head
            + self.sign_in_sql(st, names)
            + f"""    BEGIN
      EXECUTE format('SET LOCAL ROLE %I', {lit(self.role)});
{run}      PERFORM set_config('role', v_role, true);
      v_res := {outcome};
      v_msg := CASE WHEN v_res = 'refused' THEN 'it changed no rows' END;
    EXCEPTION
      WHEN insufficient_privilege THEN
        GET STACKED DIAGNOSTICS v_msg = MESSAGE_TEXT, v_detail = PG_EXCEPTION_DETAIL;
        v_res := 'refused'; v_msg := v_msg || coalesce(E'\\n' || nullif(v_detail, ''), '');
      WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS v_msg = MESSAGE_TEXT;
        v_res := 'error'; v_msg := 'error: ' || v_msg;
    END;
    IF {passed} THEN
      {self.add_result("v_line", "true", "v_text")}
    ELSE
      {self.add_result("v_line", "false", "v_text || " + SQL_NL + " || " + got)}
    END IF;
"""
        )

    def compile_tests(self, source_name: str) -> str:
        """For psql: the tests, then a report (NOTICE ok, WARNING FAIL) that fails if any test fails."""
        return (
            f"-- Policy tests generated by rowstile from {source_name}\n{self.tests_function_sql()}\n"
            f"""DO $t$
DECLARE v record; failures int := 0;
BEGIN
  FOR v IN SELECT * FROM {FN}() LOOP
    IF v.ok THEN
      RAISE NOTICE 'ok    %', replace(v.detail, E'\\n', ' ');
    ELSE
      failures := failures + 1;
      RAISE WARNING 'FAIL  %: %', v.test || CASE WHEN v.line <> '' THEN ' (' || v.line || ')' ELSE '' END, v.detail;
    END IF;
  END LOOP;
  IF failures > 0 THEN RAISE EXCEPTION '% policy test(s) failed', failures; END IF;
END $t$;
DROP FUNCTION {FN}();
"""
        )
