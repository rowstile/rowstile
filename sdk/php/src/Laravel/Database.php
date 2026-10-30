<?php

declare(strict_types=1);

namespace Rowstile\Laravel;

use Illuminate\Database\Connection;
use Illuminate\Support\Facades\DB;
use PDO;
use Rowstile\Querier;
use Rowstile\Queries;
use Rowstile\Rowstile;

/**
 * A Querier over a Laravel connection (the default one, or the one named), which signs its transactions in while the
 * code acts for someone.
 *
 *     Database::queries()->can(NotePermission::Edit, 7);
 */
final class Database implements Querier
{
    public function __construct(private readonly ?string $connection = null)
    {
    }

    private function connection(): Connection
    {
        return DB::connection($this->connection);
    }

    public function select(string $sql, array $params = []): array
    {
        /** @var list<array<string, mixed>> (fetched as maps, whatever the app's fetch mode) */
        return $this->connection()->select($sql, $params, true, [PDO::FETCH_ASSOC]);
    }

    /** The SDK's questions (can, permsOf, list), on the connection: they take only the policy's names. */
    public static function queries(?string $connection = null): Queries
    {
        return new Queries(new self($connection));
    }

    /**
     * Throws ConnectionProblem when the connection skips row-level security (the owner's, a superuser's): php artisan
     * rowstile:check runs it, before the app is served.
     */
    public static function check(?string $connection = null): void
    {
        Rowstile::check(new self($connection));
    }
}
