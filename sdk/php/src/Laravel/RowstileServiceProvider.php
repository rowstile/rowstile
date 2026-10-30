<?php

declare(strict_types=1);

namespace Rowstile\Laravel;

use Closure;
use Illuminate\Database\Connection as BaseConnection;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Exceptions\Handler;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\ServiceProvider;
use PDO;
use Rowstile\CallError;
use Rowstile\NotFound;
use Rowstile\Refused;
use Rowstile\Rowstile;

use function array_map, array_values, is_int;

/**
 * rowstile in a Laravel app (found by Laravel's package discovery): every pgsql connection signs its transactions in
 * (Connection), the exception handler answers rowstile's errors as problem bodies (application/problem+json: a
 * refusal 403 with the reason, a hidden row 404, Eloquent's ModelNotFoundException too, a call the database turned
 * down as its code's page says), and php artisan rowstile:check refuses a connection that skips row-level security.
 * The middleware that says who each request acts for (SignIn) is the app's to add to its routes.
 */
final class RowstileServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        BaseConnection::resolverFor('pgsql', static fn (PDO|Closure $pdo, string $database, string $prefix, array $config): Connection => new Connection($pdo, $database, $prefix, $config));
    }

    public function boot(): void
    {
        // (Laravel's own handler, whatever the app binds it as)
        $this->callAfterResolving(Handler::class, static function (Handler $handler): void {
            // what reports and renders see: rowstile's errors (a refusal, a call turned down, a query nobody signed
            // in to: NotSignedIn, which says how), and a model not found as rowstile's NotFound, naming its table
            $handler->map(QueryException::class, static fn (QueryException $e): \Throwable => Rowstile::translate($e));
            $handler->map(ModelNotFoundException::class, static fn (ModelNotFoundException $e): NotFound => self::notFound($e));
            $handler->renderable(static fn (Refused|NotFound|CallError $e): JsonResponse => self::answer($e));
            // answers, not failures: never logged
            $handler->dontReport([Refused::class, NotFound::class, CallError::class]);
        });
        $this->commands([CheckCommand::class]);
    }

    /** @param ModelNotFoundException<\Illuminate\Database\Eloquent\Model> $e */
    private static function notFound(ModelNotFoundException $e): NotFound
    {
        $ids = $e->getIds();
        $id = $ids === [] ? null : Rowstile::keyText(array_values(array_map(static fn (mixed $v): string|int => is_int($v) ? $v : Rowstile::text($v), $ids)));
        return new NotFound((new ($e->getModel()))->getTable(), $id);
    }

    private static function answer(Refused|NotFound|CallError $e): JsonResponse
    {
        $problem = $e->problem();
        return new JsonResponse($problem->toArray(), $problem->status, ['Content-Type' => 'application/problem+json']);
    }
}
