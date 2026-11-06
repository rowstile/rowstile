<?php

declare(strict_types=1);

namespace Rowstile\Laravel;

use Closure;
use Rowstile\Principal;
use Rowstile\Rowstile;

/**
 * What makes a Laravel connection sign in every transaction it runs while the code acts for someone (see Connection,
 * which is Laravel's Postgres connection with it). The service provider makes every pgsql connection a Connection; an
 * app whose pgsql connections are another package's class (Laravel lets one resolver make them) gives that class this
 * trait instead, in a class of its own, and registers it in a service provider's register():
 *
 *     final class SignedConnection extends TheirPostgresConnection { use \Rowstile\Laravel\SignsIn; }
 *     \Illuminate\Database\Connection::resolverFor('pgsql', fn ($pdo, $db, $prefix, $config) => new SignedConnection($pdo, $db, $prefix, $config));
 *
 * php artisan rowstile:check refuses a connection without it.
 *
 * @phpstan-require-extends \Illuminate\Database\Connection
 */
trait SignsIn
{
    /** Who this connection's open transaction is for, once it signed in. */
    private ?Principal $for = null;

    /** The transaction level it signed in at; 0 when the sign-in is undone (rolled back to a savepoint before it). */
    private int $signedAt = 0;

    /**
     * @param string $query
     * @param array<mixed> $bindings
     */
    protected function run($query, $bindings, Closure $callback): mixed
    {
        $who = Rowstile::current();
        if ($this->transactionLevel() === 0) {
            return $who === null
                ? parent::run($query, $bindings, $callback)
                : $this->transaction(fn (): mixed => $this->run($query, $bindings, $callback));
        }
        if ($this->for !== null && ($who === null || !$this->for->equals($who))) {
            throw Rowstile::signedInAlready($this->for, $who);
        }
        if ($who !== null && $this->signedAt === 0) {
            parent::run('SELECT authz.act_as(?, ?)', $who->actAsArguments(), function (string $sql, array $args): bool {
                return $this->getPdo()->prepare($sql)->execute($args);
            });
            [$this->for, $this->signedAt] = [$who, $this->transactionLevel()];
        }
        return parent::run($query, $bindings, $callback);
    }

    protected function createTransaction(): void
    {
        if ($this->transactionLevel() === 0) {
            [$this->for, $this->signedAt] = [null, 0];
        }
        parent::createTransaction();
    }

    /** @param int $toLevel */
    protected function performRollBack($toLevel): void
    {
        parent::performRollBack($toLevel);
        // rolled back to a savepoint made before the sign-in, Postgres has undone it: the transaction is still the
        // same principal's, who signs in again before the next statement
        if ($toLevel < $this->signedAt) {
            $this->signedAt = 0;
        }
    }
}
