; rowstile policies: capture names that Zed, Helix and Neovim all know

(comment) @comment
(string) @string
(literal) @string
(number) @number
(variable) @variable.special
(value) @constant

[
  "app" "role" "include" "type" "where" "can" "roles" "from" "shared" "by" "if"
  "rules" "view" "mask" "cascade" "before" "after" "object" "subject"
  "scope" "caveat" "sync" "commit" "mirrored" "invariants" "never"
  "test" "given" "as" "cannot" "allowed" "refused" "sees" "with"
] @keyword

(principal) @keyword
(command) @keyword

["or" "and" "not"] @keyword.operator

(anyone) @constant.builtin
(link) @constant.builtin
((ref (identifier) @constant.builtin)
  (#any-of? @constant.builtin "signed_in" "anyone" "nobody" "roles"))

; types: the policy's, and the key columns' SQL types
(type name: (identifier) @type)
(subject type: (identifier) @type)
(never type: (identifier) @type)
(check type: (identifier) @type)
(check principal: (identifier) @type)
(as principal: (identifier) @type)
(key_column type: (identifier) @type.builtin)

; relations
(relation name: (identifier) @property)
(subject relation: (identifier) @property)
(arrow relation: (identifier) @property)

; permissions
(permission name: (identifier) @function)
(arrow permission: (identifier) @function)
(shared permission: (identifier) @function)
(check permission: (identifier) @function)
(roles owner: (identifier) @property)

; the app's tables and columns
(table_name) @variable.special
(key_column name: (identifier) @variable)
(column) @variable

(app_role name: (identifier) @constant)
(sync_role name: (identifier) @constant)
(sync permission: (identifier) @function)
(sync by: (identifier) @type)
(scope name: (scope_name) @label)
(caveat name: (identifier) @label)
(given name: (identifier) @variable.special)

["(" ")" "[" "]" "{" "}"] @punctuation.bracket
["," "." ":" "#"] @punctuation.delimiter
["=" "->" "*"] @operator
