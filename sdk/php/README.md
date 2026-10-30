# rowstile for PHP and Laravel

**Preview.** This package may change in any release, and it is not part of rowstile 1.0's frozen surface.

`rowstile/rowstile` is the SDK for PHP apps on a rowstile policy, over PDO (`pdo_pgsql`), with a Laravel integration:
every transaction signs in as whoever the request or the job acts for, refused writes become a 403 with the
database's reason, rows the user can't see a 404, and a connection that skips row-level security is refused before
the app is served. It holds no rowstile logic: it calls the `authz.*` functions the policy made, and translates
their answers. PHP 8.2 or newer; its Laravel half is checked on Laravel 13.

The package is not the `rowstile` command (`rowstile init`, `migrate`, `test`, `client`): install that with
`npm install rowstile@next`, `pip install --pre rowstile` or its Docker image ([Installing](../../docs/installing.md)).

```php
use Rowstile\Rowstile;

// any PHP app, on PDO: a transaction signed in as user 42, its refusals as Rowstile\Refused
$ids = Rowstile::transactionAs($pdo, 42, fn (PDO $pdo) => $pdo->query('SELECT id FROM app.notes')->fetchAll());
```

| part | what |
|---|---|
| `Rowstile::transaction($pdo, fn)`, `transactionAs($pdo, $who, fn)` | a PDO transaction signed in (`authz.act_as`) as the code acts for, or as who: `42`, `"42"` (a user), `Principal::of('service', 3)`, or `null` (nobody); in a transaction already, a savepoint |
| `Rowstile::actingAs($who, fn)` | everything in `fn` acts for who: the transactions it begins sign in as them |
| `Rowstile::expect($db, $changed, $table, $command, $key)` | an UPDATE or DELETE that changed no row, asked about: `NotFound` or `Refused`, with the reason |
| `Refused`, `NotFound`, `CallError`, `NotSignedIn` | rowstile's answers, each with its `problem()` (an RFC 9457 body, `https://rowstile.dev/problems/...`); `Rowstile::translate($e)`, `refusal($e)`, `problemOf($e)`, `errorCode($e)` (`AZ709`: `rowstile help AZ709`), `sqlstate($e)`, `notSignedIn($e)` |
| `Rowstile::check($db)` | throws `ConnectionProblem` on a connection that skips row-level security |
| `Queries` | `can`, `permsOf` (a list's buttons), `list`: they take only the policy's names, which `rowstile client php` writes (`Authz\NotePermission::Edit`), so a misspelled one fails PHPStan |
| Laravel | the service provider (found by package discovery) makes every `pgsql` connection sign in each transaction while the code acts for someone, a statement outside a transaction being one of its own; it answers `Refused` 403, `NotFound` and Eloquent's `ModelNotFoundException` 404, and each code a call meets as its page says (AZ703, AZ714 401; AZ708 404; AZ710 400; AZ713 409), as problem+json; `php artisan rowstile:check` refuses a connection that skips row-level security |
| `Laravel\SignIn` | route middleware: each request acts for `SignIn::using(fn (Request $r) => ...)`'s answer, by default the user Laravel authenticated |
| `Laravel\ActsFor` | job middleware: the job acts for its principal, whatever dispatched it |
| `Laravel\HasRules` | a model whose update or delete changed no row raises `NotFound` or `Refused`; `Model::permitted($permission)` filters to the rows the user holds it on, in one set lookup |
| `Testing\Assertions`, `Laravel\DatabasePerWorker` | PHPUnit: `asUser`, `assertRefused`, `assertNotFound`; a copy of the migrated test database for each worker (`php artisan test --parallel`) |

pdo_pgsql gives an error's SQLSTATE and the server's text, not the fields that name a refused write's table and
constraint: the SDK reads them from the words rowstile's refusals use ("may not insert this row into app.notes").

Nothing uses a session-level `SET`, so persistent connections and poolers in transaction mode are safe. The guide:
[Laravel](../../docs/stacks/laravel.md); its conformance suite: `integrations/laravel`.
