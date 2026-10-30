<?php

declare(strict_types=1);

namespace Tests;

use Illuminate\Foundation\Testing\TestCase as BaseTestCase;
use Illuminate\Support\Facades\DB;
use PDO;
use Rowstile\Laravel\DatabasePerWorker;
use Rowstile\Testing\Assertions;
use Rowstile\Testing\Databases;

/**
 * The checks' base: each worker on its own copy of the migrated test database (check 12), and the same few rows for
 * every test: ann (1) owns project 1 (cy is a member, service 1 reads it) and the public project 3; bo (2) owns
 * project 2. Ann's folder 1 has folder 2 inside it. The checks read and write the same rows: no transaction around each
 * test (the tests that write put back what they change, or the next one's setUp does).
 */
abstract class TestCase extends BaseTestCase
{
    use Assertions;
    use DatabasePerWorker;

    /** The notes each may see (null: nobody), and the projects. */
    public const EXPECTED = ['1' => [1, 3, 4], '2' => [2, 3], '3' => [1, 3, 4], '' => [3]];

    public const PROJECTS = ['1' => [1, 3], '2' => [2, 3], '' => [3]];

    private const ROWS = <<<'SQL'
        TRUNCATE app.folders, app.inbox, app.notes, app.members, app.project_services, app.projects, app.services,
          app.users, public.jobs CASCADE;
        INSERT INTO app.users VALUES (1, 'ann'), (2, 'bo'), (3, 'cy');
        INSERT INTO app.services VALUES (1, 'digest');
        INSERT INTO app.projects VALUES (1, 1, 'Plans', false), (2, 2, 'Bo''s', false), (3, 1, 'Open', true);
        INSERT INTO app.members VALUES (1, 3);
        INSERT INTO app.project_services VALUES (1, 1);
        INSERT INTO app.notes (id, project_id, author_id, body) VALUES
          (1, 1, 1, 'plan'), (2, 2, 2, 'mine'), (3, 3, 1, 'hello'), (4, 1, 3, 'idea');
        SELECT setval(pg_get_serial_sequence('app.notes', 'id'), 100);
        INSERT INTO app.folders VALUES (1, NULL, 1, 'top'), (2, 1, 1, 'inside');
        SQL;

    protected function migratedTestDatabase(): string
    {
        return self::env('ROWSTILE_TESTS_URL');
    }

    protected function setUp(): void
    {
        parent::setUp();
        $this->owner()->exec(self::ROWS);
    }

    public static function env(string $name): string
    {
        $value = getenv($name);
        self::assertIsString($value, "{$name} isn't set: test.sh sets it");
        return $value;
    }

    /** The database this worker's tests run on: its copy of the migrated test database. */
    public function database(): string
    {
        return DB::connection()->getDatabaseName();
    }

    /** The owner's connection to this worker's database (the app's is Laravel's). */
    public function owner(): PDO
    {
        return Databases::connect(self::env('ROWSTILE_TESTS_URL'), $this->database());
    }

    /** The app role's own connection to this worker's database, outside Laravel (signed in by nothing). */
    public function app(): PDO
    {
        return Databases::connect(self::env('ROWSTILE_APP_TESTS_URL'), $this->database());
    }

    /**
     * The headers that say who a request is (null: nobody).
     *
     * @return array<string, string>
     */
    public function as(?string $user): array
    {
        return $user === null ? [] : ['x-user' => $user];
    }

    /**
     * A problem body, as the SDK writes one.
     *
     * @return array<string, mixed>
     */
    public function problem(string $kind, string $title, int $status, string $detail, string $code): array
    {
        return ['type' => "https://rowstile.dev/problems/{$kind}", 'title' => $title, 'status' => $status, 'detail' => $detail, 'code' => $code];
    }

    /** The first column of the statement's first row. */
    public static function value(PDO $pdo, string $sql): mixed
    {
        $statement = $pdo->query($sql);
        self::assertNotFalse($statement);
        return $statement->fetchColumn();
    }

    /** A value that must be text (a JSON answer's member). */
    public static function text(mixed $value): string
    {
        self::assertIsString($value);
        return $value;
    }

    /** A value that must be a whole number. */
    public static function number(mixed $value): int
    {
        self::assertIsInt($value);
        return $value;
    }
}
