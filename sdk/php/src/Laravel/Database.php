<?php

declare(strict_types=1);

namespace Rowstile\Laravel;

use Illuminate\Database\Connection;
use Illuminate\Support\Facades\DB;
use PDO;
use Rowstile\ConnectionProblem;
use Rowstile\Querier;
use Rowstile\Queries;
use Rowstile\Rowstile;

use function class_uses_recursive, in_array;

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
     * Throws ConnectionProblem when the connection skips row-level security (the owner's, a superuser's), or signs no
     * transaction in (another package made it, without SignsIn): php artisan rowstile:check runs it, before the app is
     * served. Returns its warnings (Rowstile::check's).
     *
     * @return list<string>
     */
    public static function check(?string $connection = null): array
    {
        $made = DB::connection($connection);
        if (!in_array(SignsIn::class, class_uses_recursive($made), true)) {
            throw new ConnectionProblem([$made::class." signs no transaction in: another package's connection class "
                ."replaced rowstile's for pgsql. Give a class of yours that extends it Rowstile\\Laravel\\SignsIn, and make "
                .'pgsql connections with it (Connection::resolverFor)']);
        }
        return Rowstile::check(new self($connection));
    }
}
