<?php

declare(strict_types=1);

namespace Rowstile\Laravel;

use Closure;
use Illuminate\Database\PostgresConnection;
use Rowstile\Principal;
use Rowstile\Rowstile;

/**
 * Laravel's Postgres connection, signing in every transaction it runs while the code acts for someone
 * (Rowstile::current(): a request, a job, Rowstile::actingAs()): before the transaction's first statement, and again
 * before the next one whenever who the code acts for changed (actingAs inside a transaction, or a savepoint rolled
 * back over the sign-in); once the code acts for no one again, as nobody. A statement outside a transaction is a
 * transaction of its own (BEGIN, the sign-in, the statement, COMMIT), as Postgres would run it alone. While the code
 * acts for no one (the owner's migrations, an artisan command) nothing is signed in, and the database refuses what
 * needs to know who asks (AZ701). A sign-in lasts one transaction, so a persistent connection carries no one into the
 * next request. The service provider makes every pgsql connection one.
 */
class Connection extends PostgresConnection
{
    /** Who this connection's open transaction signed in as, if it signed someone in. */
    private ?Principal $signed = null;

    /**
     * @param string $query
     * @param array<mixed> $bindings
     */
    protected function run($query, $bindings, Closure $callback): mixed
    {
        // a transaction that signed someone in, run on by code that acts for no one: nobody, from here on
        $who = Rowstile::current() ?? ($this->transactionLevel() > 0 && $this->signed !== null ? Principal::nobody() : null);
        if ($who === null) {
            return parent::run($query, $bindings, $callback);
        }
        if ($this->transactionLevel() === 0) {
            return $this->transaction(fn (): mixed => $this->run($query, $bindings, $callback));
        }
        if ($this->signed === null || !$this->signed->equals($who)) {
            parent::run('SELECT authz.act_as(?, ?)', $who->actAsArguments(), function (string $sql, array $args): bool {
                return $this->getPdo()->prepare($sql)->execute($args);
            });
            $this->signed = $who;
        }
        return parent::run($query, $bindings, $callback);
    }

    protected function createTransaction(): void
    {
        if ($this->transactionLevel() === 0) {
            $this->signed = null;
        }
        parent::createTransaction();
    }

    /** @param int $toLevel */
    protected function performRollBack($toLevel): void
    {
        parent::performRollBack($toLevel);
        // (rolled back to a savepoint, the sign-in may be undone with it: Postgres undoes settings too)
        $this->signed = null;
    }
}
