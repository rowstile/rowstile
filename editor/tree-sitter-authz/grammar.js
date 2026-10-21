/**
 * Tree-sitter grammar for rowstile policies (.authz), for editors that highlight with Tree-sitter (Zed,
 * Helix, Neovim). It follows core/authzlib/parse.py, which stays the definition of the language: a policy
 * this grammar reads differently is a bug here. Each block (type, rules, invariants, test) holds lines of its
 * own kinds, so blocks nest without reading indentation; newlines are whitespace, as a line starting with
 * `or`, `and`, `where` or `if` continues the one before.
 */
/** @param {RuleOrLiteral} rule */
const commaSep1 = (rule) => seq(rule, repeat(seq(",", rule)));

module.exports = grammar({
  name: "authz",

  extras: ($) => [/\s/, $.comment],

  word: ($) => $.identifier,

  inline: ($) => [$._relation_name],

  // a line that starts with one of the words below, after a type's lines, is a relation of that type if a
  // colon follows, the next block if not: the parser follows both until the next token says which
  conflicts: ($) => [[$.type]],

  rules: {
    source_file: ($) => repeat($._top),

    _top: ($) => choice($.app_role, $.include, $.type, $.rules, $.scope, $.caveat, $.invariants, $.test),

    comment: (_) => token(seq("--", /.*/)),

    identifier: (_) => /[A-Za-z_][A-Za-z0-9_]*/,

    // schema.table
    table_name: ($) => seq(field("schema", $.identifier), ".", field("name", $.identifier)),

    string: (_) => /"[^"\n]*"/,

    // {any SQL}: braces nest, and quoted text may hold braces
    sql: ($) => seq("{", optional($.sql_text), "}"),
    sql_text: ($) => repeat1(choice(/[^{}']+/, /'([^']|'')*'/, $._sql_nested)),
    _sql_nested: ($) => seq("{", optional($.sql_text), "}"),

    // ---- top-level lines -------------------------------------------------------------------------
    // the Postgres role the app connects as
    app_role: ($) => seq("app", "role", field("name", $.identifier)),

    include: ($) => seq("include", field("path", $.string)),

    scope: ($) => seq("scope", field("name", $.scope_name), "=", commaSep1($.scope_item)),
    scope_name: ($) => seq($.identifier, repeat(seq(choice("-", ":"), $.identifier))),
    scope_item: ($) => seq($.identifier, repeat(seq(".", $.identifier))),

    caveat: ($) => seq("caveat", field("name", $.identifier), "=", $.sql),

    // ---- types -----------------------------------------------------------------------------------
    type: ($) =>
      seq(
        "type",
        field("name", $.identifier),
        "=",
        field("table", $.table_name),
        optional($.key),
        optional($.principal),
        optional(seq("where", $.sql)),
        repeat(choice($.relation, $.permission, $.roles)),
      ),
    key: ($) => seq("(", commaSep1($.key_column), ")"),
    key_column: ($) => seq(field("name", $.identifier), optional(field("type", $.identifier))),
    principal: (_) => "principal",

    // a relation may carry a name that starts a line elsewhere: `role : user = owner_id`
    _relation_name: ($) =>
      choice(
        $.identifier,
        alias(
          choice("app", "role", "include", "type", "rules", "scope", "caveat", "invariants", "test", "principal"),
          $.identifier,
        ),
      ),
    relation: ($) =>
      seq(
        field("name", $._relation_name),
        ":",
        commaSep1($.subject),
        choice(seq("=", $._source), $.shared),
      ),
    subject: ($) =>
      choice(
        $.anyone,
        $.link,
        seq(field("type", $.identifier), ":", "*"),
        seq(field("type", $.identifier), optional(seq("#", field("relation", $.identifier)))),
      ),
    anyone: (_) => "anyone",
    link: (_) => "link",
    shared: ($) =>
      seq("shared", optional(seq("by", field("permission", $.identifier))), optional(seq("if", $.sql))),

    _source: ($) => choice($._columns, $.typed_columns, $.table_source),
    // one column, or [a, b]: the columns of a composite key
    _columns: ($) => choice($.column, $.columns),
    column: ($) => $.identifier,
    columns: ($) => seq("[", commaSep1($.column), "]"),
    // (type_col, id_col): the subject's type is in a column
    typed_columns: ($) => seq("(", $.column, ",", $._columns, ")"),
    table_source: ($) =>
      seq(
        field("table", $.table_name),
        "(",
        choice(
          seq($._columns, "->", choice($._columns, $.typed_columns)),
          seq($.side, ",", $.side),
        ),
        ")",
        optional(seq("where", $.sql)),
      ),
    side: ($) => seq(choice("object", "subject"), ":", choice($._columns, $.typed_columns)),

    permission: ($) => seq("can", field("name", $.identifier), "=", field("expression", $._expression)),

    // who may hold custom roles (and whose count); a permission writes `roles` where a role gives it
    roles: ($) => seq("roles", ":", commaSep1($.subject), optional(seq("from", field("owner", $.identifier)))),

    // ---- expressions: or < and < not < (…) / name / rel.perm / {sql} ----------------------------
    _expression: ($) => choice($.or, $.and, $.not, $.parenthesized, $.ref, $.arrow, $.sql),
    or: ($) => prec.left(1, seq($._expression, "or", $._expression)),
    and: ($) => prec.left(2, seq($._expression, "and", $._expression)),
    not: ($) => prec(3, seq("not", $._expression)),
    parenthesized: ($) => seq("(", $._expression, ")"),
    ref: ($) => $.identifier,
    // rel.perm: the permission on the object the relation leads to
    arrow: ($) => seq(field("relation", $.identifier), ".", field("permission", $.identifier)),

    // ---- rules -----------------------------------------------------------------------------------
    rules: ($) =>
      seq(
        "rules",
        field("table", $.table_name),
        optional(seq("view", field("view", $.table_name))),
        repeat(choice($.rule, $.mask, $.cascade)),
      ),
    rule: ($) =>
      seq(
        field("command", $.command),
        optional(commaSep1($.column)),
        optional(choice("before", "after")),
        ":",
        field("expression", $._expression),
      ),
    command: (_) => choice("select", "insert", "update", "delete"),
    mask: ($) => seq("mask", commaSep1($.column), ":", field("expression", $._expression)),
    // a foreign key of the table to another whose action (ON DELETE CASCADE, SET NULL, ...) is meant; the key's
    // columns where several keys of the table point there: `cascade from app.users (owner_id)`
    cascade: ($) =>
      seq("cascade", "from", field("table", $.table_name), optional(seq("(", commaSep1($.column), ")"))),

    // ---- invariants ------------------------------------------------------------------------------
    invariants: ($) => seq("invariants", repeat($.never)),
    never: ($) => seq("never", field("type", $.identifier), ":", field("expression", $._expression)),

    // ---- tests: `test` (checks), or `test "name"` (given, as, checks) ---------------------------
    test: ($) => seq("test", optional(field("name", $.string)), repeat(choice($.check, $.given, $.as))),
    check: ($) =>
      seq(
        $._who,
        choice("can", "cannot"),
        field("permission", $.identifier),
        field("type", $.identifier),
        field("object", $._value),
      ),
    given: ($) => seq("given", optional(seq(field("name", $.identifier), "=")), $.sql),
    as: ($) => seq("as", $._who, choice("allowed", "refused", seq("sees", $.number)), $.sql),
    _who: ($) => choice($.anyone, seq(field("principal", $.identifier), field("who", $._value), optional($.limited))),
    // signed in limited to scopes, as a key that has them: `with scope read, files:write`
    limited: ($) => seq("with", "scope", commaSep1(field("scope", $.scope_name))),
    _value: ($) => choice($.variable, $.literal, $.value),
    variable: (_) => /\$[A-Za-z_][A-Za-z0-9_]*/,
    literal: (_) => /'([^']|'')*'/,
    value: (_) => /[^\s{}'$]+/,
    number: (_) => /\d+/,
  },
});
