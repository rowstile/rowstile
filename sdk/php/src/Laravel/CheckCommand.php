<?php

declare(strict_types=1);

namespace Rowstile\Laravel;

use Illuminate\Console\Command;
use Rowstile\ConnectionProblem;

use function is_string;

/**
 * php artisan rowstile:check: exit 1 when the app's connection skips row-level security (the owner's, a superuser's,
 * a role with BYPASSRLS). Run it before the app is served (a container's entrypoint, a deploy step): PHP starts a
 * request at a time, with no moment of its own to refuse to start in.
 */
final class CheckCommand extends Command
{
    protected $signature = 'rowstile:check {--database= : the connection, if not the default}';

    protected $description = "Refuse a database connection that skips row-level security (rowstile)";

    public function handle(): int
    {
        $name = $this->option('database');
        try {
            Database::check(is_string($name) ? $name : null);
        } catch (ConnectionProblem $e) {
            $this->error($e->getMessage());
            return self::FAILURE;
        }
        $this->info('rowstile: the connection is under row-level security');
        return self::SUCCESS;
    }
}
