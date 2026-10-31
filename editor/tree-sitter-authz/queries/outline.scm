; the outline: types with their relations and permissions, rules by table and command, tests, scopes, caveats, sync lines
(type "type" @context name: (identifier) @name) @item
(relation name: (identifier) @name) @item
(permission "can" @context name: (identifier) @name) @item
(roles "roles" @name) @item
(rules "rules" @context table: (table_name) @name) @item
(rule command: (command) @name (column)* @name) @item
(mask "mask" @context (column) @name) @item
(invariants "invariants" @name) @item
(never "never" @context type: (identifier) @name) @item
(test "test" @context name: (string) @name) @item
(test "test" @name !name) @item
(scope "scope" @context name: (scope_name) @name) @item
(caveat "caveat" @context name: (identifier) @name) @item
(app_role "role" @context name: (identifier) @name) @item
(sync_role "role" @context name: (identifier) @name) @item
(sync "sync" @context table: (table_name) @name) @item
