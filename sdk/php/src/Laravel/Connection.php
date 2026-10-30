<?php

declare(strict_types=1);

namespace Rowstile\Laravel;

use Closure;
use Illuminate\Database\PostgresConnection;
use Rowstile\Principal;
use Rowstile\Rowstile;

/**
 * Laravel's Postgres connection, signing in every transaction it runs while the code acts for someone
 * (Rowstile::current(): a request, a job, Rowstile::actingAs()), before the transaction's first statement. A statement
 * outside a transaction is a transaction of its own (BEGIN, the sign-in, the statement, COMMIT), as Postgres would run
 * it alone. A transaction is one principal's: once it is signed in, a statement while the code acts for someone else,
 * or for no one, is refused before it is sent (a LogicException, Rowstile::signedInAlready), the transaction as it
 * was. While the code acts for no one (the owner's migrations, an artisan command) nothing is signed in, and the
 * database refuses what needs to know who asks (AZ701). A sign-in lasts one transaction, so a persistent connection
 * carries no one into the next request. The service provider makes every pgsql connection one.
 */
class Connection extends PostgresConnection
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
