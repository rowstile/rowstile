<?php

declare(strict_types=1);

namespace Tests\Feature;

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use PDOException;
use PHPUnit\Framework\Attributes\TestDox;
use Rowstile\ConnectionProblem;
use Rowstile\Laravel\Database;
use Rowstile\Rowstile;
use Rowstile\Testing\Databases;
use RuntimeException;
use InvalidArgumentException;
use Symfony\Component\Process\Process;
use Tests\TestCase;

/**
 * The checks that serve the app (5), look at a connection across requests (4), type-check the generated names (9),
 * look at the test databases (12), start the app (13), change the policy (14), and run the queue's worker (10).
 */
final class ChecksTest extends TestCase
{
    private const HERE = __DIR__.'/../..';

    private const COMMAND = __DIR__.'/../../../../core/cli/rowstile_cli.py';

    /** The app role's URL on this worker's database (or another one). */
    private function appUrl(?string $database = null): string
    {
        return Databases::withDatabase(self::env('ROWSTILE_APP_TESTS_URL'), $database ?? $this->database());
    }

    /**
     * A command, in $cwd, with these settings added to the suite's; its exit code and what it printed.
     *
     * @param list<string> $command
     * @param array<string, string> $env
     * @return array{int, string}
     */
    private function command(array $command, array $env = [], string $cwd = self::HERE): array
    {
        $process = new Process($command, $cwd, $env, null, 300);
        $process->run();
        return [(int) $process->getExitCode(), $process->getOutput().$process->getErrorOutput()];
    }

    #[TestDox('4: a pooled connection carries no one over')]
    public function test_4_one_connection_carries_no_one_over(): void
    {
        // the requests share the app's one connection, as a server process's persistent one does
        $pdo = DB::connection()->getPdo();
        foreach (['1', '2', null] as $user) {
            $this->getJson('/notes', $this->as($user))->assertExactJson(self::EXPECTED[$user ?? '']);
        }
        // a transaction that commits (a folder moved where it is)
        $this->patchJson('/folders/2', ['parent_id' => 1], $this->as('1'))->assertOk();
        self::assertSame($pdo, DB::connection()->getPdo());
        // each request signed in again, so the answers alone can't tell: the connection, as the last request left it,
        // in a transaction nobody signs in to, holds no one (a sign-in that outlived its transaction would still be
        // ann's here)
        self::assertContains(self::value($pdo, "SELECT current_setting('authz.user_id', true)"), [null, '']);
        $pdo->beginTransaction();
        try {
            $pdo->query('SELECT count(*) FROM app.notes');
            self::fail('expected the not-signed-in error');
        } catch (PDOException $e) {
            self::assertSame('AZ701', Rowstile::errorCode($e)); // rowstile help AZ701
        } finally {
            $pdo->rollBack();
        }
    }

    #[TestDox('5: concurrent requests never mix users')]
    public function test_5_concurrent_requests(): void
    {
        $socket = stream_socket_server('tcp://127.0.0.1:0');
        self::assertNotFalse($socket);
        $port = (int) substr((string) strrchr((string) stream_socket_get_name($socket, false), ':'), 1);
        fclose($socket);
        // PHP's own server, four worker processes, each with its connection
        // (as php artisan serve runs it: in public/, with Laravel's router script)
        $server = new Process(['php', '-S', "127.0.0.1:{$port}", '../vendor/laravel/framework/src/Illuminate/Foundation/resources/server.php'], self::HERE.'/public', [
            'PHP_CLI_SERVER_WORKERS' => '4', 'DB_URL' => $this->appUrl(), 'APP_ENV' => 'testing', 'LOG_CHANNEL' => 'stderr',
        ]);
        $server->start();
        try {
            for ($i = 0; $i < 100 && @fsockopen('127.0.0.1', $port) === false; $i++) {
                usleep(100_000);
            }
            $users = array_merge(...array_fill(0, 10, ['1', '2', '3', null]));
            // all at once (curl's multi handle), each with its own connection to the server
            $multi = curl_multi_init();
            $handles = array_map(function (?string $user) use ($multi, $port): \CurlHandle {
                $handle = curl_init("http://127.0.0.1:{$port}/notes");
                self::assertNotFalse($handle);
                curl_setopt_array($handle, [CURLOPT_RETURNTRANSFER => true, CURLOPT_FORBID_REUSE => true, CURLOPT_HTTPHEADER => $user === null ? [] : ["x-user: {$user}"]]);
                curl_multi_add_handle($multi, $handle);
                return $handle;
            }, $users);
            do {
                curl_multi_exec($multi, $running);
                curl_multi_select($multi);
            } while ($running > 0);
            self::assertSame(
                array_map(static fn (?string $user): array => self::EXPECTED[$user ?? ''], $users),
                array_map(static fn (\CurlHandle $h): mixed => json_decode(self::text(curl_multi_getcontent($h)), true), $handles),
                $server->getErrorOutput(),
            );
        } finally {
            $server->stop(5);
        }
    }

    #[TestDox('9: the generated names type-check')]
    public function test_9_the_generated_names_type_check(): void
    {
        // the committed names are the ones the policy makes (rowstile client php POLICY prints them, and writes nothing)
        [$code, $made] = $this->command(['python3', self::COMMAND, 'client', 'php', 'database/policy.authz']);
        self::assertSame(0, $code, $made);
        self::assertSame(file_get_contents(self::HERE.'/database/authz.php'), $made, 'database/authz.php is out of date: run rowstile client');
        $dir = sys_get_temp_dir().'/rowstile-names-'.getmypid();
        @mkdir($dir);
        $checks = [
            'good' => "Database::queries()->can(NotePermission::Edit, 1);\nDatabase::queries()->permsOf(ProjectPermission::class, [1, 2]);\nDatabase::queries()->list(ProjectPermission::View);\n",
            'client_perm' => "echo NotePermission::Edt->value;\n",
            'sdk_perm' => "Database::queries()->can('edit', 1);\n",
            'sdk_type' => "Database::queries()->permsOf(NtePermission::class, [1]);\n",
        ];
        foreach ($checks as $name => $code) {
            file_put_contents("{$dir}/{$name}.php", "<?php\n\ndeclare(strict_types=1);\n\nuse Authz\\NotePermission;\nuse Authz\\NtePermission;\nuse Authz\\ProjectPermission;\nuse Rowstile\\Laravel\\Database;\n\n{$code}");
        }
        [, $said] = $this->command(['vendor/bin/phpstan', 'analyse', '--no-progress', '--error-format=raw', '--memory-limit=1G', '-c', 'phpstan.neon', $dir]);
        $flagged = array_values(array_filter(array_keys($checks), static fn (string $name): bool => str_contains($said, "/{$name}.php:")));
        self::assertSame(['client_perm', 'sdk_perm', 'sdk_type'], $flagged, $said);
        self::assertStringContainsString('NotePermission::Edt', $said);
        self::assertStringContainsString('NtePermission', $said);
        self::assertStringContainsString('can() expects Rowstile\\Permission, string given', $said);
    }

    #[TestDox('12: a test database per worker has the policy')]
    public function test_12_a_database_per_worker(): void
    {
        $copy = $this->database();
        self::assertMatchesRegularExpression('/\Aconf_tests_\d+\z/', $copy);
        self::assertSame('conf_app', DB::scalar('SELECT current_user'));
        self::assertSame(self::PROJECTS['2'], Rowstile::actingAs(2, static fn (): array => DB::table('app.projects')->orderBy('id')->pluck('id')->all()));
        $count = static fn (string $db): mixed => self::value(Databases::connect(self::env('ROWSTILE_TESTS_URL'), $db), 'SELECT count(*) FROM app.users');
        self::assertSame([0, 3], [$count('conf_tests'), $count($copy)]); // the original is left as it was migrated
        DB::disconnect();
        self::assertSame($copy, Databases::copy(self::env('ROWSTILE_TESTS_URL'), self::worker())); // copied again: as migrated
        self::assertSame(0, $count($copy));
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('a database to copy');
        Databases::copy('postgresql://conf_owner:owner@localhost', '1');
    }

    #[TestDox("12: a database per worker says why it can't copy")]
    public function test_12_says_why_it_cant_copy(): void
    {
        $held = "{$this->database()}_held";
        $owner = $this->owner();
        $owner->exec("DROP DATABASE IF EXISTS {$held} WITH (FORCE)");
        $owner->exec("CREATE DATABASE {$held}");
        $url = Databases::withDatabase(self::env('ROWSTILE_TESTS_URL'), $held);
        $holder = Databases::connect($url);
        try {
            Databases::copy($url, '9');
            self::fail('expected the copy to be refused');
        } catch (RuntimeException $e) {
            self::assertStringContainsString("can't be copied while anything is connected to it", $e->getMessage());
        } finally {
            unset($holder);
            $owner->exec("DROP DATABASE IF EXISTS {$held} WITH (FORCE)");
        }
    }

    #[TestDox('13: refuses a connection that skips row-level security')]
    public function test_13_refuses_the_owners_connection(): void
    {
        config(['database.connections.owner' => ['driver' => 'pgsql', 'url' => Databases::withDatabase(self::env('ROWSTILE_TESTS_URL'), $this->database())]]);
        try {
            Database::check('owner');
            self::fail('expected the owner to be refused');
        } catch (ConnectionProblem $e) {
            self::assertStringContainsString('an owner skips row-level security', $e->getMessage());
            self::assertStringContainsString('owner', implode(' ', $e->problems));
        }
        Database::check(); // the app's role, under row-level security
        self::assertSame(1, Artisan::call('rowstile:check', ['--database' => 'owner']));
        self::assertStringContainsString('an owner skips row-level security', Artisan::output());
        self::assertSame(0, Artisan::call('rowstile:check'));
        self::assertStringContainsString('rowstile: the connection is under row-level security', Artisan::output());
    }

    #[TestDox("13: the app does not start on the owner's connection")]
    public function test_13_the_app_does_not_start(): void
    {
        // the server starts after the check, as a container's entrypoint runs them: php artisan rowstile:check && ...
        $start = 'php artisan rowstile:check && exec php artisan serve --port=0';
        [$code, $said] = $this->command(['sh', '-c', $start], ['DB_URL' => Databases::withDatabase(self::env('ROWSTILE_TESTS_URL'), $this->database())]);
        self::assertSame(1, $code, $said);
        self::assertStringContainsString('an owner skips row-level security', $said);
        [$code, $said] = $this->command(['php', 'artisan', 'rowstile:check'], ['DB_URL' => $this->appUrl()]);
        self::assertSame(0, $code, $said);
    }

    #[TestDox('14: a policy change ships as the next migration')]
    public function test_14_a_policy_change_ships_as_the_next_migration(): void
    {
        // on a copy of the migrated test database, and a copy of the app (its vendor too: Composer loads the names
        // from the app's own folder)
        $db = "{$this->database()}_14";
        $this->owner()->exec("DROP DATABASE IF EXISTS {$db} WITH (FORCE)");
        $this->owner()->exec("CREATE DATABASE {$db} TEMPLATE conf_tests");
        $work = sys_get_temp_dir().'/rowstile-14-'.getmypid();
        try {
            $this->assertRan($this->command(['rm', '-rf', $work]));
            // (-L: the SDK, which Composer links into vendor/ from the checkout, is copied too)
            $this->assertRan($this->command(['cp', '-RL', '.', $work]));
            $policy = "{$work}/database/policy.authz";
            file_put_contents($policy, str_replace("  can read = recipient\n", "  can read = recipient\n  can reply = recipient\n", (string) file_get_contents($policy)));
            $owner = Databases::connect(self::env('ROWSTILE_TESTS_URL'), $db);
            $owner->exec("INSERT INTO app.users VALUES (1, 'ann'), (2, 'bo')");
            $message = self::number(self::value($owner, "INSERT INTO app.inbox (sender_id, recipient_id, body) VALUES (1, 2, 'hi') RETURNING id"));
            unset($owner);
            $this->assertRan($this->command(['python3', self::COMMAND, 'migrate'], [], $work));
            $this->assertRan($this->command(['php', 'artisan', 'migrate', '--force'], ['DB_URL' => Databases::withDatabase(self::env('ROWSTILE_TESTS_URL'), $db)], $work));
            $this->assertRan($this->command(['python3', self::COMMAND, 'client'], [], $work));
            // the app's code, with the names the policy now makes: it names reply, and the database answers it
            file_put_contents("{$work}/said.php", <<<PHP
                <?php
                use Authz\\MessagePermission;
                use Rowstile\\Laravel\\Database;
                use Rowstile\\Rowstile;
                require __DIR__.'/vendor/autoload.php';
                \$app = require __DIR__.'/bootstrap/app.php';
                \$app->make(Illuminate\\Contracts\\Console\\Kernel::class)->bootstrap();
                // bo, to whom it is sent, may reply; ann, who sent it, may not even read it
                echo json_encode(array_map(static fn (int \$user): array => Rowstile::actingAs(\$user, static fn (): array => [
                    Database::queries()->can(MessagePermission::Reply, {$message}),
                    Database::queries()->can(MessagePermission::Read, {$message}),
                ]), [2, 1]));
                PHP);
            [$code, $said] = $this->command(['php', 'said.php'], ['DB_URL' => $this->appUrl($db)], $work);
            self::assertSame(0, $code, $said);
            self::assertSame([[true, true], [false, false]], json_decode($said, true));
        } finally {
            $this->command(['rm', '-rf', $work]);
            $this->owner()->exec("DROP DATABASE IF EXISTS {$db} WITH (FORCE)");
        }
    }

    #[TestDox("10: jobs on the queue's worker each act for their own")]
    public function test_10_the_queues_worker(): void
    {
        // a request as cy queues two jobs: the digest acts for service 1, the export for cy, who asked; the worker runs
        // them one after the other on its one connection, and the second never acts for the first's
        config(['queue.default' => 'database']);
        $this->postJson('/notes/digest', [], $this->as('3'))->assertStatus(202);
        $this->postJson('/notes/digest', [], $this->as('2'))->assertStatus(202);
        [$code, $said] = $this->command(['php', 'artisan', 'queue:work', '--stop-when-empty', '--sleep=0'], [
            'DB_URL' => $this->appUrl(), 'QUEUE_CONNECTION' => 'database', 'LOG_CHANNEL' => 'stderr',
        ]);
        self::assertSame(0, $code, $said);
        preg_match_all('/\.INFO: (digest|export) (\{.*\})/', $said, $m, PREG_SET_ORDER);
        self::assertSame([
            ['digest', '{"projects":2,"as":{"Rowstile\\\\Principal":{"type":"service","id":"1"}}}'],
            ['export', '{"notes":[1,3,4],"for":{"Rowstile\\\\Principal":{"type":"user","id":"3"}}}'],
            ['digest', '{"projects":2,"as":{"Rowstile\\\\Principal":{"type":"service","id":"1"}}}'],
            ['export', '{"notes":[2,3],"for":{"Rowstile\\\\Principal":{"type":"user","id":"2"}}}'],
        ], array_map(static fn (array $x): array => [$x[1], $x[2]], $m), $said);
    }

    /** @param array{int, string} $ran */
    private function assertRan(array $ran): void
    {
        self::assertSame(0, $ran[0], $ran[1]);
    }
}
