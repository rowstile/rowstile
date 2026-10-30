# Rails and Active Record

<!-- tested: every line of code below is in integrations/rails (tests/unit_test.py checks it) -->

**Preview.** The Ruby SDK, the `rowstile` gem, may change in any release, and it is not part of rowstile 1.0's
frozen surface.

A Rails 8 app on Active Record and the `pg` driver, served by Puma, whose migrations are Rails'. Controllers check
nothing: each Active Record transaction signs in as the request's user, the database filters what it reads and
refuses what it may not write, and the gem answers a refusal with 403 and a hidden row with 404.

Everything here comes from `integrations/rails`, the conformance suite: a small app and the checks every supported
stack passes (`integrations/rails/test.sh`). Ruby 3.3 or newer.

## Install

```sh
bundle add rowstile --version ">= 0.1.0.pre"   # the gem: the SDK (while only pre-releases are published)
pip install --pre rowstile                     # the command (or npm install rowstile@next, or its Docker image)
rowstile init                                  # a first policy from your tables, a test file, rowstile.toml
```

The gem is the SDK alone. The `rowstile` command (`init`, `migrate`, `test`, `client`) comes from npm, PyPI or its
Docker image ([Installing](../installing.md)). `init` reads the tables, so it needs the database (`DATABASE_URL`, or
`--db`). It doesn't know Rails yet: set `[migrations]` and `[clients]` in its `rowstile.toml` as the
conformance app's has them:

```toml
policy   = "db/policy.authz"
tests    = ["db/tests/*.authz"]
database = "env:ROWSTILE_OWNER_URL"
[clients]
ruby = "app/lib/authz.rb"
rbs  = "sig/authz.rbs"
[migrations]
tool = "rails"
dir  = "db/migrate"
```

Two roles connect. The owner of the tables runs the migrations, and the app connects as the role the policy names
(`app role conf_app`), which row-level security applies to. Rails reads both from `DATABASE_URL`: the app's role
when the app runs, the owner's when the migrations do.

```yaml
# The app connects as the policy's app role, DATABASE_URL; the migrations run as the tables' owner, with the
# owner's URL in DATABASE_URL instead (DATABASE_URL=$ROWSTILE_OWNER_URL bin/rails db:migrate).
default: &default
  adapter: postgresql
```

The owner must be able to switch to the app role, since the command looks at the data as the app does when it
runs the policy's tests: `GRANT conf_app TO conf_owner`, once, by whoever made the app role.

## The policy

```authz
app role conf_app

type user = app.users

type service = app.services principal

type project = app.projects
  owner   : user    = owner_id
  member  : user    = app.members(project_id -> user_id)
  service : service = app.project_services(project_id -> service_id)

  can edit = owner or member
  can view = edit or service or {public}

type note = app.notes
  project : project = project_id
  author  : user    = author_id

  can edit = author or project.owner
  can view = project.view

rules app.notes
  select : view
  insert : project.edit and author
  update : edit
  delete : edit
```

## The app

The gem's Railtie adds a middleware: each request acts for whoever `config.rowstile.user` returns for it (`nil`:
nobody, who sees only what `anyone` may; `["service", 3]`: a service). Read your session or your token there.
The conformance app has no sign-in, so its `SessionUser` stands in for one: it takes the user from a header its
checks set, which a real app must never believe. That is why this page doesn't show it.

```ruby
    # who each request acts for: the request's signed-in user (nil: nobody), or a service
    config.rowstile.user = ->(request) { SessionUser.call(request) }
```

Every transaction Active Record runs while the code acts for someone signs in before its first statement, with
`authz.act_as`, as the [SQL page](sql.md) says; a statement outside a transaction is a transaction of its own. A
sign-in lasts one transaction, so a pooled connection carries no one into the next request, and Puma's threads
never mix users. Code that acts for no one (a migration, the console, a rake task) signs nothing in: as the app
role, the database refuses what needs to know who asks (AZ701). `Rowstile.acting_as(2) { ... }` acts for someone
anywhere else. Active Record's query cache is emptied each time who the code acts for changes.

A transaction is one principal's. Inside one signed in already, work for the same principal goes on as it is,
nested transactions and savepoints too. A statement while the code acts for someone else, or for no one, raises a
`RuntimeError` before anything is sent for it, and the transaction is as it was: `this transaction is signed in as
user 1 already, and a sign-in lasts the database transaction: user 2's work can't run inside it`. Run that work
after the transaction, or in a transaction of its own on another connection. A savepoint rolled back over the
sign-in undoes it in Postgres: the same principal signs in again before the next statement.

Then controllers are plain Active Record. A list shows only the user's rows:

```ruby
  def index
    render json: Note.order(:id).pluck(:id)
  end
```

A row the user can't see isn't found (`ActiveRecord::RecordNotFound`: 404), and an update or a destroy the rules
refuse changes no row: the gem asks the database why, in the same transaction, and raises `Rowstile::Refused`
(403, with the rule and the reason) or `Rowstile::NotFound` (404: the row was hidden in the meantime):

```ruby
  def update
    note = Note.find(params[:id])     # a row the user can't see: 404
    note.update!(body: params[:body]) # an update the rules refuse: 403, with the reason
    render json: { id: note.id }
  end
```

The middleware answers each with a problem body (`application/problem+json`), worded as the database words a
refused insert: `permission denied: user 3 may not update row 1 of app.notes`. A model with a `lock_version` whose
row changed since it was read, and which the rules let the user change, raises `ActiveRecord::StaleObjectError`
as Rails does: 409. `update_all` and `delete_all` return a count; `Rowstile.expect(count, "app.notes", "delete",
id)` turns 0 into the same answers.

An insert that reads the new row back (`create` uses `RETURNING`) also needs the select rule: if the user may
insert but not read the row, the 403 names the select rule. `insert!(..., returning: false)` reads nothing back.

A call the database turns down that is no refusal answers as its code's page says, with the database's words: a
negative page size 400, something the call names that isn't there 404, a call that needs someone signed in or a
login refused 401, a folder moved into its own subfolder 409 (`rowstile help AZ714`). The app's own mistakes stay
errors, a 500.

```ruby
  # the projects the user may see, a page at a time: the database says when the size or the cursor is wrong
  def page
    listed = ApplicationRecord.with_connection do |c|
      c.select_values("SELECT x FROM authz.list('project', 'view', $1, $2) x", "app",
                      [params[:after], Integer(params.fetch(:limit))])
    end
    render json: listed
  end
```

At start-up, the app refuses to be served on a connection that skips row-level security (the owner's, a
superuser's): `config.ru` runs the Railties' server blocks, as Rails writes it, and rowstile's checks the
connection there. A rake task or the console isn't checked. `config.rowstile.check_connection = false` leaves the
check out.

```ruby
run Rails.application
# runs the Railties' server blocks: rowstile's refuses to serve on a connection that skips row-level security
Rails.application.load_server
```

## Lists by permission

`rowstile client` writes the policy's names (`app/lib/authz.rb`) and their signatures (`sig/authz.rbs`), for
Steep. `Authz.queries` takes only the policy's types and permissions, so a misspelled one fails `steep check`:
`permitted(scope, type, perm)` filters a scope to the objects the user holds a permission on, in one set lookup,
and `perms_of` answers a list's buttons in one call.

```ruby
  # the projects the user may edit: one set lookup, taking only the policy's names (Authz, the generated client)
  def editable
    render json: Authz.queries.permitted(Project.all, "project", "edit").order(:id).pluck(:id)
  end

  # a list's buttons, in one call
  def buttons
    render json: Authz.queries.perms_of("project", Project.order(:id).pluck(:id))
  end
```

`Rowstile::Queries.new` has the same calls, taking any string.

## Background jobs

A job acts for a principal of its own, whatever request enqueued it (`type service = app.services principal` in
the policy):

```ruby
class DigestJob < ApplicationJob
  include Rowstile::Job
  acts_for ["service", 1]
```

## Migrations

The policy ships as Rails migrations. `rowstile migrate` writes the next one (only what changed since
`db/policy.lock`): `db/migrate/<time>_authz_<name>.rb`, whose `up` executes the SQL beside it, in the transaction
Rails runs each migration in. A rowstile migration isn't undone (`down` raises): change the policy back, and write
the next one.

```sh
rowstile migrate                                        # after changing the policy
DATABASE_URL=$ROWSTILE_OWNER_URL bin/rails db:migrate
rowstile migrate --check                                # in CI: exit 1 if a policy change has no migration
```

Keep the schema as SQL: `db/schema.rb` holds no row-level security, nor triggers, nor functions, so its diff would
never show what a policy change does to the tables. `db/structure.sql` holds the policies on the app's tables and
their triggers, and its diff in a review shows them change. The app's schemas only: rowstile's own schemas are its
migrations' to keep.

```ruby
    config.active_record.schema_format = :sql
    config.active_record.dump_schemas = "app"
```

The dump can't make a database: Rails dumps it with `--no-privileges`, so it has no grants, and it has none of the
policy's own rows. A database with a rowstile policy is made by its migrations alone. Rails 8 loads the dump into an
empty database before migrating it (`db:migrate`, `db:prepare`); for a dump of a rowstile database, the gem has it
run every migration instead. Loading the dump any other way (`db:schema:load`, `db:setup`, `db:reset`, a test
database Rails rebuilds) raises `Rowstile::SchemaLoadRefused`, which says what to do.

`pg_dump` writes more settings at the top of the dump in newer versions: dump with one version of it, the newest,
whatever the server's (it dumps any server older than itself). The conformance suite checks that the dump Rails
writes after migrating a fresh database is the committed `db/structure.sql`: Rails' own diff of the schema.

## Tests

The policy's own tests run with `rowstile test`. In Minitest, include `Rowstile::Testing`: `as_user(2) { ... }`,
`assert_refused(command: "update") { ... }` and `assert_not_found { ... }`.

The test database is migrated as the others, never loaded from the dump, and each `parallelize` worker gets a copy
of it: `Rowstile::Testing.database_per_worker(owner_url, worker)` copies it (as the owner, while nothing is
connected to it), and connects the app to the copy.

```ruby
  # the test database is migrated, never loaded from db/structure.sql (which holds no grants, nor the policy's own
  # rows): Rails mustn't load it over a migrated one, nor into each worker's (test/test_helper.rb copies it)
  config.active_record.maintain_test_schema = false
  config.active_support.parallelize_test_databases = false
```

```ruby
  parallelize(workers: 2, threshold: 1)
  parallelize_setup do |worker|
    Rowstile::Testing.database_per_worker(TESTS_OWNER, worker)
```

Transactional tests (`use_transactional_tests`, Rails' default) work too. What the app runs in the test's
transaction goes as it would without it: a statement outside a transaction signs in as the code acts for, and again
when that changes, so a test may act for one user and then another. Each transaction the app begins there (a
savepoint, to Postgres) is one principal's, as above. The console's sandbox (`rails console --sandbox`) is the same.

## What the preview leaves out

`load_async` runs its query on another thread, which acts for no one: the database refuses it (AZ701), rather
than answer as someone. Streaming a response (`ActionController::Live`) is the same. Sharing, requests, reviews
and keys are `authz.*` functions to call in SQL, as the conformance app does ([Using it from app
code](../reference/app-code.md)).
