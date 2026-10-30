# rowstile for Rails

**Preview.** The gem may change in any release, and it is not part of rowstile 1.0's frozen surface.

`gem "rowstile"` is the SDK for Rails apps on a rowstile policy: every Active Record transaction signs in as whoever
the request or the job acts for, refused writes become a 403 with the database's reason, rows the user can't see a
404, and the app refuses to start on a connection that skips row-level security. It holds no rowstile logic: it calls
the `authz.*` functions the policy made, and translates their answers. Ruby 3.3 or newer, Rails 8, the `pg` driver.

The gem is not the `rowstile` command (`rowstile init`, `migrate`, `test`, `client`): install that with
`npm install rowstile@next`, `pip install --pre rowstile` or its Docker image ([Installing](../../docs/installing.md)).

```ruby
# config/application.rb
config.rowstile.user = ->(request) { request.session[:user_id] }   # nil: nobody; ["service", 3]: a service
config.active_record.schema_format = :sql                          # db/structure.sql: schema.rb has no policies
```

| part | what |
|---|---|
| `Rowstile.acting_as(who) { }` | every transaction in the block signs in as who: `42`, `"42"` (a user), `["service", 3]`, a `Principal`, or `nil` (nobody). A transaction is one principal's: inside one signed in as someone else, the block's statements raise a `RuntimeError` before anything is sent; run that work after, or on another connection |
| the Railtie | a middleware that sets who each request acts for (`config.rowstile.user`) and answers `Rowstile::Refused` 403, `Rowstile::NotFound` and `ActiveRecord::RecordNotFound` 404, a stale `lock_version` the rules allow 409, and each code a call meets as its page says (AZ703, AZ714 401; AZ708 404; AZ710 400; AZ713 409), as problem+json; the start-up check (`Rowstile.check_connection!`) when the app is served |
| Active Record | a statement outside a transaction is a transaction of its own; each transaction signs in before its first statement, and is that principal's to the end (in a test's transaction, each the app begins there); an update or a destroy of a record that changed no row raises `NotFound` or `Refused` with the database's reason (`authz.explain_rule`); `Rowstile.expect(count, table, command, id)` for `update_all` and `delete_all` |
| `Rowstile::Queries` | `can`, `perms_of` (a list's buttons), `permitted(scope, type, perm)` (one set lookup); the generated client's `Authz.queries` takes only the policy's names |
| `Rowstile::Job` | `include Rowstile::Job` and `acts_for ["service", 1]`: the job acts for its principal, whatever enqueued it |
| `Rowstile::Testing` | Minitest: `as_user`, `assert_refused(command:, table:)`, `assert_not_found`; `Rowstile::Testing.database_per_worker(owner_url, worker)`, a copy of the migrated test database for each `parallelize` worker |
| the dump | a dump of a database with a policy can't make one (no grants, none of the policy's rows): `db:migrate` and `db:prepare` migrate an empty database from its first migration, and loading the dump any other way raises `Rowstile::SchemaLoadRefused` |
| errors | `Rowstile.refusal(error)`, `error_code(error)` (`AZ709`: `rowstile help AZ709`), `sqlstate`, `not_signed_in?`, `problem_of(error)` |

Signatures: `sig/rowstile.rbs` (RBS), for Steep. `rowstile client ruby` writes the policy's names as constants
(`Authz::Note::EDIT`), and `rowstile client rbs` their signatures, whose literal types make Steep refuse a
misspelled type or permission, in the constants and in `Authz.queries.can("note", 1, "edit")`.

Nothing uses a session-level `SET`, so pools and poolers in transaction mode are safe. The guide:
[Rails](../../docs/stacks/rails.md); its conformance suite: `integrations/rails`.
