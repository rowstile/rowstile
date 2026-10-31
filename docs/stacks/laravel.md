# Laravel and Eloquent

<!-- tested: every line of code below is in integrations/laravel (tests/unit_test.py checks it) -->

**Preview.** The PHP SDK, the `rowstile/rowstile` Composer package, may change in any release, and it is not part of
rowstile 1.0's frozen surface.

A Laravel app on Eloquent and PDO (`pdo_pgsql`), whose migrations are Laravel's. Controllers check nothing: each
transaction signs in as the request's user, the database filters what it reads and refuses what it may not write,
and the SDK answers a refusal with 403 and a hidden row with 404.

Everything here comes from [`integrations/laravel`](../../integrations/laravel), the conformance suite: a small app and the checks every supported
stack passes ([`integrations/laravel/test.sh`](../../integrations/laravel/test.sh)). PHP 8.2 or newer for the SDK; the suite runs Laravel 13 on PHP 8.4.

## Install

```sh
composer require rowstile/rowstile   # the SDK: not on Packagist yet (a preview); a path repository meanwhile
pip install --pre rowstile           # the command (or npm install rowstile@next, or its Docker image)
rowstile init                        # once your migrations made the tables: a first policy from them, a test file, rowstile.toml
```

The package is the SDK alone. The `rowstile` command (`init`, `migrate`, `test`, `client`) comes from npm, PyPI or its
Docker image ([Installing](../installing.md)). `init` reads the tables, so it needs the database (`DATABASE_URL`, or
`--db`). It doesn't know Laravel yet: set `[migrations]` and `[clients]` in its `rowstile.toml` as the conformance
app's has them:

```toml
policy   = "database/policy.authz"
tests    = ["database/tests/*.authz"]
database = "env:ROWSTILE_OWNER_URL"
[clients]
php = "database/authz.php"
[migrations]
tool = "laravel"
dir  = "database/migrations"
```

`rowstile client` writes the policy's names to `database/authz.php`, one file of enums: Composer loads it from
`composer.json`'s `autoload`, `"files": ["database/authz.php"]`. Keep it out of the folders PSR-4 maps (`app/`), whose
files hold one class each.

Two roles connect. The owner of the tables runs the migrations, and the app connects as the role the policy names
(`app role conf_app`), which row-level security applies to. Laravel reads both from `DB_URL`: the app's role when
the app runs, the owner's when the migrations do (`DB_URL=$ROWSTILE_OWNER_URL php artisan migrate`). The owner must
be able to switch to the app role, since the command looks at the data as the app does when it runs the policy's
tests: `GRANT conf_app TO conf_owner`, once, by whoever made the app role.

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

The SDK's service provider comes with the package (Laravel's package discovery finds it). It makes every `pgsql`
connection sign in each transaction it runs while the code acts for someone, with `authz.act_as`, as the
[SQL page](sql.md) says; a statement outside a transaction is a transaction of its own. A sign-in lasts one
transaction, so a persistent connection carries no one into the next request. Code that acts for no one (a
migration, an artisan command) signs nothing in: as the app role, the database refuses what needs to know who asks
(AZ701). `Rowstile::actingAs(2, fn () => ...)` acts for someone anywhere else. A transaction is one principal's:
once it is signed in, a statement for someone else, or for no one, throws a `LogicException` before it is sent, and
the transaction is as it was. Run that work after it, or in a transaction of its own. On PDO alone,
`Rowstile::transaction($pdo, fn)` refuses to run inside a transaction it didn't begin (`$pdo->beginTransaction()`):
who it is signed in as can't be known. Let `Rowstile::transaction` (or `transactionAs`) begin it instead.

Who each request acts for is the `SignIn` middleware's to say. Put it first, before route model binding reads a row:

```php
    ->withMiddleware(function (Middleware $middleware): void {
        // each request acts for its user, before route model binding reads a row
        $middleware->api(prepend: [SignIn::class]);
    })
```

By default it is the user Laravel authenticated (its id), or nobody, who sees only what `anyone` may. Read your
session or your token there instead, in a service provider's `boot`. The conformance app has no sign-in, so its
`SessionUser` stands in for one: it takes the user from a header its checks set, which a real app must never
believe. That is why this page doesn't show it.

```php
        // who each request acts for: the request's signed-in user (null: nobody), or a service
        SignIn::using(fn (Request $request) => SessionUser::of($request));
```

Then controllers are plain Eloquent. A list shows only the user's rows:

```php
    public function index(): JsonResponse
    {
        return new JsonResponse(Note::query()->orderBy('id')->pluck('id'));
    }
```

A model whose table has rules uses `HasRules`. A row the user can't see isn't found (route model binding: 404), and
an update or a delete the rules refuse changes no row: the SDK asks the database why, in the same transaction, and
throws `Rowstile\Refused` (403, with the rule and the reason) or `Rowstile\NotFound` (404: the row was hidden in the
meantime). Eloquent alone would say it saved.

```php
final class Note extends Model
{
    use HasRules;
```

```php
    public function update(Request $request, Note $note): JsonResponse
    {
        // a row the user can't see: 404 (route model binding); an update the rules refuse: 403, with the reason
        $note->update(['body' => $request->string('body')->toString()]);
        return new JsonResponse(['id' => $note->id]);
    }
```

The service provider answers each with a problem body (`application/problem+json`), worded as the database words a
refused insert: `permission denied: user 3 may not update row 1 of app.notes`. A mass update (`->update([...])` on a
query) returns its count; `Rowstile::expect($db, $count, 'app.notes', 'update', $id)` turns 0 into the same answers.
An insert that reads the new row back (`create` uses `RETURNING`) also needs the select rule: if the user may insert
but not read the row, the 403 names the select rule. `insert(...)` on a query reads nothing back.

A call the database turns down that is no refusal answers as its code's page says, with the database's words: a
negative page size 400, something the call names that isn't there 404, a call that needs someone signed in or a
login refused 401, a folder moved into its own subfolder 409 (`rowstile help AZ714`). The app's own mistakes stay
errors, a 500; a query nobody signed in to is reported as `Rowstile\NotSignedIn`, which says how.

```php
    // the projects the user may see, a page at a time: the database says when the size or the cursor is wrong
    public function page(Request $request): JsonResponse
    {
        $after = $request->query('after');
        return new JsonResponse(Database::queries()->list(ProjectPermission::View, is_string($after) ? $after : null, $request->integer('limit')));
    }
```

PHP starts each request on its own, so there is no moment when the app starts to refuse a connection in. Run
`php artisan rowstile:check` before the app is served (a container's entrypoint, a deploy step): it exits 1 on a
connection that skips row-level security (the owner's, a superuser's).

```sh
php artisan rowstile:check && exec php-fpm
```

## Lists by permission

`rowstile client` writes an enum of each type's permissions (`Authz\ProjectPermission::Edit`). The SDK's calls take
only those, so a misspelled one fails PHPStan, and PHP when the line runs: `permitted` filters a model's query to the
rows the user holds a permission on, in one set lookup, and `permsOf` answers a list's buttons in one call.

```php
    // the projects the user may edit: one set lookup, taking only the policy's names (Authz, the generated names)
    public function editable(): JsonResponse
    {
        return new JsonResponse(Project::permitted(ProjectPermission::Edit)->orderBy('id')->pluck('id'));
    }
```

```php
        return new JsonResponse(Database::queries()->permsOf(ProjectPermission::class, $ids));
```

## Background jobs

A queued job acts for a principal of its own, whatever request dispatched it (`type service = app.services
principal` in the policy), with the `ActsFor` job middleware; or for the user who asked, given to the job:

```php
    public function middleware(): array
    {
        return [new ActsFor(Principal::of('service', 1))];
    }
```

The queue's worker runs one job after another on one connection; each signs in as its own.

## Migrations

The policy ships as Laravel migrations. `rowstile migrate` writes the next one (only what changed since
`database/policy.lock`): `database/migrations/<Y_m_d_His>_authz_<name>.php`, an anonymous migration class whose `up`
runs the SQL beside it, in the transaction Laravel runs each migration in. A rowstile migration isn't undone (`down`
throws): change the policy back, and write the next one.

```sh
rowstile migrate                                          # after changing the policy
DB_URL=$ROWSTILE_OWNER_URL php artisan migrate
rowstile migrate --check                                  # in CI: exit 1 if a policy change has no migration
```

A database with a rowstile policy is made by its migrations alone: a dump of its schema (`php artisan schema:dump`)
holds none of the policy's own rows.

## Tests

The policy's own tests run with `rowstile test`. In PHPUnit, use `Rowstile\Testing\Assertions`: `asUser(2, fn () =>
...)`, `assertRefused(fn () => ..., 'update')` and `assertNotFound(fn () => ...)`.

The test database is migrated as the others (never rebuilt by `RefreshDatabase`), and each worker of
`php artisan test --parallel` gets a copy of it: `DatabasePerWorker` copies it (as the owner, while nothing is
connected to it) at the worker's first test, and connects the app to the copy.

```php
abstract class TestCase extends BaseTestCase
{
    use Assertions;
    use DatabasePerWorker;
```

```php
    protected function migratedTestDatabase(): string
    {
        return self::env('ROWSTILE_TESTS_URL');
    }
```

## What the preview leaves out

Who the code acts for is kept for the process, which serves one request at a time (PHP-FPM, `php artisan serve`,
Octane's workers): code that runs requests side by side in one process (coroutines) would share it. Octane is
untested. Read replicas are not used while the code acts for someone: its statements run in transactions, on the
write connection. Doctrine's migrations are not written yet. Sharing, requests, reviews and keys are `authz.*`
functions to call in SQL, as the conformance app does ([Using it from app code](../reference/app-code.md)).
