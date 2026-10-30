<?php

declare(strict_types=1);

namespace Rowstile\Laravel;

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\ParallelTesting;
use Rowstile\Testing\Databases;

use function is_string;

/**
 * For a Laravel TestCase: each test worker (php artisan test --parallel: ParallelTesting's token; one process: 0) on a
 * copy of the migrated test database, made at its first test; the app's default connection goes to the copy. The test
 * database is migrated as the others (php artisan migrate), never rebuilt by RefreshDatabase or loaded from a dump,
 * which hold no grants nor the policy's own rows.
 *
 *     abstract class TestCase extends BaseTestCase
 *     {
 *         use DatabasePerWorker;
 *
 *         protected function migratedTestDatabase(): string
 *         {
 *             return (string) getenv('ROWSTILE_TESTS_URL');   // the owner's URL: it may create databases
 *         }
 *     }
 */
trait DatabasePerWorker
{
    /** @var array<string, string> the copy each migrated database got in this process */
    private static array $rowstileCopies = [];

    /** The owner's URL of the migrated test database each worker copies (postgresql://owner:secret@host/app_tests). */
    abstract protected function migratedTestDatabase(): string;

    /** This worker's name: ParallelTesting's token, or 0 outside a parallel run. */
    public static function worker(): string
    {
        $token = ParallelTesting::token();
        return is_string($token) ? $token : '0';
    }

    /** Laravel runs it before each test (setUp + the trait's name). */
    protected function setUpDatabasePerWorker(): void
    {
        $url = $this->migratedTestDatabase();
        $copy = self::$rowstileCopies[$url] ??= Databases::copy($url, self::worker());
        $default = Config::string('database.default');
        Config::set("database.connections.{$default}.database", $copy);
        $appUrl = Config::get("database.connections.{$default}.url");
        if (is_string($appUrl) && $appUrl !== '') {
            Config::set("database.connections.{$default}.url", Databases::withDatabase($appUrl, $copy));
        }
        DB::purge($default);
    }
}
