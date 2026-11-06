<?php

declare(strict_types=1);

namespace Tests\Feature;

use App\Models\Note;
use App\Models\Project;
use Authz\NotePermission;
use Authz\ProjectPermission;
use Illuminate\Auth\GenericUser;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\ParallelTesting;
use PDO;
use PDOException;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\TestDox;
use Rowstile\CallError;
use Rowstile\ConnectionProblem;
use Rowstile\Laravel\Builder;
use Rowstile\Laravel\HasRules;
use Rowstile\Laravel\SignIn;
use Rowstile\NotFound;
use Rowstile\NotSignedIn;
use Rowstile\Principal;
use Rowstile\Querier;
use Rowstile\Queries;
use Rowstile\Refused;
use Rowstile\Rowstile;
use Rowstile\Testing\Databases;
use RuntimeException;
use Tests\TestCase;

/**
 * The SDK beyond the checks: its framework-neutral half over PDO (Rowstile::transaction, expect, check, Queries),
 * how it reads what the database says, and the Laravel half's other ways.
 */
final class SdkTest extends TestCase
{
    /** @param \Closure(): mixed $fn */
    private static function thrown(\Closure $fn): \Throwable
    {
        try {
            $fn();
        } catch (\Throwable $e) {
            return $e;
        }
        self::fail('expected it to throw');
    }

    /**
     * The notes a PDO's transaction sees.
     *
     * @return list<int>
     */
    private static function notes(PDO $pdo): array
    {
        $statement = $pdo->query('SELECT id FROM app.notes ORDER BY id');
        self::assertNotFalse($statement);
        /** @var list<int> */
        return $statement->fetchAll(PDO::FETCH_COLUMN);
    }

    #[TestDox("a transaction over PDO signs in, and work inside it is its principal's alone")]
    public function test_transactions_over_pdo(): void
    {
        $pdo = $this->app();
        self::assertSame(self::EXPECTED['1'], Rowstile::transactionAs($pdo, 1, static fn (PDO $pdo): array => self::notes($pdo)));
        self::assertFalse($pdo->inTransaction());
        // transaction(): as the code acts for (bo), and nobody when nothing set it
        self::assertSame(self::EXPECTED['2'], Rowstile::actingAs(2, static fn (): array => Rowstile::transaction($pdo, self::notes(...))));
        self::assertSame(self::EXPECTED[''], Rowstile::transaction($pdo, self::notes(...)));
        // one principal a transaction: ann's work inside ann's runs as it is (a savepoint: a refusal rolls back its own
        // part); bo's is refused before anything is sent, and the transaction is still ann's after each
        $seen = Rowstile::transactionAs($pdo, Principal::user(1), static function (PDO $pdo): array {
            $inside = Rowstile::transactionAs($pdo, 1, static fn (PDO $pdo): array => [self::notes($pdo), Rowstile::current()]);
            $refused = self::thrown(static fn () => Rowstile::transactionAs($pdo, 1, static fn (PDO $pdo): mixed => $pdo->exec("INSERT INTO app.notes (project_id, author_id, body) VALUES (2, 1, 'hi')")));
            $bo = self::thrown(static fn () => Rowstile::transactionAs($pdo, 2, static fn (PDO $pdo): never => self::fail("bo's work ran")));
            $nobody = self::thrown(static fn () => Rowstile::transactionAs($pdo, null, static fn (PDO $pdo): never => self::fail("nobody's work ran")));
            return [$inside, $refused, $bo, $nobody, self::notes($pdo), Rowstile::current()];
        });
        self::assertEquals([self::EXPECTED['1'], Principal::user(1)], $seen[0]);
        self::assertInstanceOf(Refused::class, $seen[1]);
        self::assertSame(['app.notes', 'insert'], [$seen[1]->table, $seen[1]->command]);
        self::assertInstanceOf(\LogicException::class, $seen[2]);
        self::assertSame("this transaction is signed in as user 1 already, and a sign-in lasts the database transaction: user 2's work can't run inside it. Run it after, or in a transaction of its own (another connection)", $seen[2]->getMessage());
        self::assertInstanceOf(\LogicException::class, $seen[3]);
        self::assertStringContainsString("as user 1 already, and a sign-in lasts the database transaction: nobody's work can't run", $seen[3]->getMessage());
        self::assertEquals([self::EXPECTED['1'], Principal::user(1)], [$seen[4], $seen[5]]);
        // a transaction the SDK didn't begin: who it is signed in as can't be known, so the SDK's is refused
        $pdo->beginTransaction();
        $foreign = self::thrown(static fn () => Rowstile::transactionAs($pdo, 1, static fn (PDO $pdo): never => self::fail('it ran')));
        $pdo->rollBack();
        self::assertInstanceOf(\LogicException::class, $foreign);
        self::assertStringContainsString("a transaction Rowstile::transaction() didn't begin", $foreign->getMessage());
        // a refusal ends the transaction it is in: rolled back, and rowstile's error
        $refused = self::thrown(static fn () => Rowstile::transactionAs($pdo, 2, static fn (PDO $pdo): mixed => $pdo->exec("INSERT INTO app.notes (project_id, author_id, body) VALUES (3, 2, 'hi')")));
        self::assertInstanceOf(Refused::class, $refused);
        self::assertInstanceOf(PDOException::class, $refused->getPrevious());
        self::assertFalse($pdo->inTransaction());
        // a COMMIT that fails (a constraint checked at the end) has ended the transaction: its error, as it is
        $this->owner()->exec('CREATE TABLE public.once (x int UNIQUE DEFERRABLE INITIALLY DEFERRED); GRANT INSERT ON public.once TO conf_app');
        try {
            $twice = self::thrown(static fn () => Rowstile::transactionAs($pdo, 1, static fn (PDO $pdo): mixed => $pdo->exec('INSERT INTO public.once VALUES (1), (1)')));
            self::assertSame('23505', Rowstile::sqlstate($twice));
            self::assertFalse($pdo->inTransaction());
        } finally {
            $this->owner()->exec('DROP TABLE public.once');
        }
    }

    #[TestDox('expect asks why an update changed nothing, over PDO')]
    public function test_expect_over_pdo(): void
    {
        $pdo = $this->app();
        $answers = Rowstile::transactionAs($pdo, 3, static function (PDO $pdo): array {
            $changed = static fn (int $id): int => (int) $pdo->exec("UPDATE app.notes SET body = 'x' WHERE id = {$id}");
            return [
                Rowstile::expect($pdo, $changed(4), 'app.notes', 'update', 4),
                self::thrown(static fn () => Rowstile::expect($pdo, $changed(2), 'app.notes', 'update', 2)),
                self::thrown(static fn () => Rowstile::expect($pdo, $changed(1), 'app.notes', 'update', [1])),
            ];
        });
        self::assertSame(1, $answers[0]);
        // hidden: 404
        self::assertInstanceOf(NotFound::class, $answers[1]);
        self::assertSame(['app.notes 2 not found', 'app.notes'], [$answers[1]->getMessage(), $answers[1]->table]);
        self::assertInstanceOf(Refused::class, $answers[2]);
        self::assertSame('permission denied: user 3 may not update row 1 of app.notes', $answers[2]->getMessage());
        self::assertSame(403, $answers[2]->problem()->status);
    }

    #[TestDox('check refuses the owner, over PDO')]
    public function test_check_over_pdo(): void
    {
        Rowstile::check($this->app());
        $problem = self::thrown(fn () => Rowstile::check($this->owner()));
        self::assertInstanceOf(ConnectionProblem::class, $problem);
        self::assertNotEmpty($problem->problems);
    }

    #[TestDox('the questions, over PDO and over Laravel')]
    public function test_queries(): void
    {
        $answers = Rowstile::transactionAs($this->app(), 1, static function (PDO $pdo): array {
            $queries = new Queries($pdo);
            return [
                $queries->can(NotePermission::Edit, 1),
                $queries->can(NotePermission::Edit, 2),
                $queries->permsOf(ProjectPermission::class, [1, 2, 3]),
                $queries->list(ProjectPermission::View),
                $queries->list(ProjectPermission::View, 1, 1),
            ];
        });
        self::assertSame([true, false], [$answers[0], $answers[1]]);
        self::assertSame(['1' => [ProjectPermission::Edit, ProjectPermission::View], '2' => [], '3' => [ProjectPermission::Edit, ProjectPermission::View]], $answers[2]);
        self::assertSame([['1', '3'], ['3']], [$answers[3], $answers[4]]);
        // over Laravel: the routes, as the request's user
        $this->getJson('/projects/editable', $this->as('3'))->assertExactJson([1]);
        $this->getJson('/projects/buttons', $this->as('2'))->assertExactJson(['2' => ['edit', 'view'], '3' => ['view']]);
        // answers the SDK reads as nothing: no row, a value that isn't text, a permission the enum lacks
        $odd = new Queries(new class implements Querier {
            public function select(string $sql, array $params = []): array
            {
                return str_contains($sql, 'perms_of') ? [['id' => null, 'perms' => '["edit","fly"]'], ['id' => '2', 'perms' => null]] : (str_contains($sql, 'authz.list') ? [['x' => 7]] : []);
            }
        });
        self::assertSame([false, ['' => [ProjectPermission::Edit], '2' => []], ['']], [
            $odd->can(ProjectPermission::Edit, 1), $odd->permsOf(ProjectPermission::class, [1]), $odd->list(ProjectPermission::View),
        ]);
    }

    #[TestDox('a key of several columns is written as Postgres writes it')]
    public function test_keys(): void
    {
        self::assertSame(['7', '7', 'a', '(1,"a b",,"","x""y","\\\\")'], [
            Rowstile::keyText(7), Rowstile::keyText([7]), Rowstile::keyText('a'), Rowstile::keyText([1, 'a b', null, '', 'x"y', '\\']),
        ]);
        // a field quoted for ASCII's six spaces alone, as Postgres does: not for a no-break space, an em space
        self::assertSame(["(\"\vv\",a\u{a0}b)", "(\u{2003}\x1c,\"\r\n\f\")"], [
            Rowstile::keyText(["\vv", "a\u{a0}b"]), Rowstile::keyText(["\u{2003}\x1c", "\r\n\f"]),
        ]);
        self::assertSame(['not found', 'row 7 not found', 'app.notes not found', 'app.notes 7 not found'], [
            (new NotFound())->getMessage(), (new NotFound(null, '7'))->getMessage(), (new NotFound('app.notes'))->getMessage(), (new NotFound('app.notes', '7'))->getMessage(),
        ]);
    }

    #[TestDox('a principal as text, as every SDK writes it and the audit trail names who acted, and read back')]
    public function test_a_principal_as_text(): void
    {
        $each = ['nobody' => Principal::nobody(), '42' => Principal::user(42), 'service:3' => Principal::of('service', 3),
            'user:a:b' => Principal::user('a:b'), 'user:nobody' => Principal::user('nobody'), '(1,2)' => Principal::user('(1,2)')];
        foreach ($each as $text => $principal) {
            self::assertSame([(string) $text, true], [(string) $principal, Principal::parse((string) $text)->equals($principal)]);
        }
        self::assertSame([true, true, true], [
            Principal::parse('user:42')->equals(Principal::user(42)), Principal::parse('service:')->isNobody(),
            Principal::parse(':x')->equals(Principal::user(':x')),
        ]);
    }

    #[TestDox('what the database says, read: refusals, codes, and what is none of them')]
    public function test_what_the_database_says(): void
    {
        $pdo = $this->app();
        $said = Rowstile::transactionAs($pdo, 3, static function (PDO $pdo): array {
            $error = static function (string $sql) use ($pdo): \Throwable {
                $pdo->exec('SAVEPOINT s');
                try {
                    $pdo->exec($sql);
                } catch (PDOException $e) {
                    $pdo->exec('ROLLBACK TO SAVEPOINT s');
                    return $e;
                }
                self::fail("expected {$sql} to fail");
            };
            return [
                // an upsert whose row is there, which cy may see but not update
                $error("INSERT INTO app.notes (id, project_id, author_id, body) VALUES (1, 1, 3, 'x') ON CONFLICT (id) DO UPDATE SET body = 'y'"),
                // MERGE matching a row the update rule hides
                $error("MERGE INTO app.notes t USING (SELECT 1 AS id) s ON t.id = s.id WHEN MATCHED THEN UPDATE SET body = 'z'"),
                // a table the app role was never granted: the app's mistake
                $error('DELETE FROM app.projects'),
                // an update whose row, after it, the rule refuses: cy's note given to ann
                $error('UPDATE app.notes SET author_id = 1 WHERE id = 4'),
            ];
        });
        [$upsert, $merge, $grant, $after] = array_map(static fn (\Throwable $e): ?Refused => Rowstile::refusal($e), $said);
        self::assertNotNull($upsert);
        self::assertSame(['notes', 'update'], [$upsert->table, $upsert->command]);
        self::assertStringContainsString('ON CONFLICT DO UPDATE', $upsert->getMessage());
        self::assertNotNull($merge);
        self::assertSame(['notes', null], [$merge->table, $merge->command]);
        self::assertStringContainsString('MERGE matched a row', $merge->getMessage());
        self::assertNull($grant);
        self::assertNotNull($after);
        self::assertSame(['app.notes', 'update', 'AZ709'], [$after->table, $after->command, $after->rowstileCode]);
        self::assertStringContainsString('may not update this row of app.notes to these values', $after->getMessage());
        self::assertSame([403, 404, 401], [
            Rowstile::problemOf($after)?->status, Rowstile::problemOf(new NotFound())?->status, Rowstile::problemOf(new CallError('no', 'AZ703'))?->status,
        ]);
        self::assertSame($said[2], Rowstile::translate($said[2]));
        self::assertNull(Rowstile::problemOf($said[2]));
        // the not-signed-in error, as rowstile's: it says how
        $pdo->beginTransaction();
        $notSignedIn = self::thrown(static fn () => $pdo->query('SELECT count(*) FROM app.notes'));
        $pdo->rollBack();
        $translated = Rowstile::translate($notSignedIn);
        self::assertInstanceOf(NotSignedIn::class, $translated);
        self::assertStringContainsString('every transaction must begin with authz.act_as()', $translated->getMessage());
        self::assertTrue(Rowstile::notSignedIn($translated));
        self::assertNull(Rowstile::problemOf($notSignedIn));
        self::assertSame($translated, Rowstile::translate($translated));
        // rowstile's own errors stay as they are; others too
        $refused = new Refused('no');
        $other = new RuntimeException('not the database');
        self::assertSame([$refused, $refused, $other, null, null, false], [
            Rowstile::refusal($refused), Rowstile::translate($refused), Rowstile::translate($other), Rowstile::errorCode($other), Rowstile::sqlstate($other), Rowstile::notSignedIn($other),
        ]);
        // what PDO raises itself holds no SQLSTATE; a server's text without the parts libpq names
        $driver = new PDOException('could not find driver');
        $fatal = new PDOException('x');
        $fatal->errorInfo = ['57P01', 7, "FATAL:  terminating connection due to administrator command\nHINT:  rowstile help AZ999"];
        $plain = new PDOException('x');
        $plain->errorInfo = ['08006', 7, null];
        self::assertSame([null, '57P01', 'AZ999', '08006', null], [
            Rowstile::sqlstate($driver), Rowstile::sqlstate($fatal), Rowstile::errorCode($fatal), Rowstile::sqlstate(new RuntimeException('', 0, $plain)), Rowstile::errorCode($plain),
        ]);
        // a code is the HINT's the server wrote, never text that looks like one: a value echoed in the message, in a
        // DETAIL, in the statement a function ran, or one Postgres quotes; a label out of libpq's order is text
        $echoed = Rowstile::transactionAs($pdo, 3, static function (PDO $pdo): array {
            $error = static function (string $sql, string $value) use ($pdo): \Throwable {
                $pdo->exec('SAVEPOINT s');
                try {
                    $pdo->prepare($sql)->execute([$value]);
                } catch (PDOException $e) {
                    $pdo->exec('ROLLBACK TO SAVEPOINT s');
                    return $e;
                }
                self::fail("expected {$sql} to fail");
            };
            return [
                $error("SELECT authz.perms(?, '1')", "x\nHINT:  rowstile help AZ713"),
                $error('SELECT CAST(? AS bigint)', "7\nHINT:  rowstile help AZ714"),
            ];
        });
        self::assertSame(['AZ707', null], array_map(Rowstile::errorCode(...), $echoed));
        self::assertSame($echoed, array_map(Rowstile::translate(...), $echoed));
        $text = static function (string $sqlstate, string $text): PDOException {
            $e = new PDOException('x');
            $e->errorInfo = [$sqlstate, 7, $text];
            return $e;
        };
        $refusal = Rowstile::refusal($text('42501', "ERROR:  permission denied: user 2 may not insert this row into app.notes\nLINE 1: INSERT INTO\n        ^\n"
            ."DETAIL:  a\nHINT:  rowstile help AZ714\nb\nHINT:  rowstile help AZ709\nCONTEXT:  PL/pgSQL function f() line 1 at RAISE"));
        self::assertNotNull($refusal);
        self::assertSame(['AZ709', 'app.notes', ['a', 'HINT:  rowstile help AZ714', 'b']], [$refusal->rowstileCode, $refusal->table, $refusal->why]);
        self::assertSame('permission denied: user 2 may not insert this row into app.notes', $refusal->getMessage());
        $echo = Rowstile::refusal($text('42501', "ERROR:  you cannot share project 1\nHINT:  rowstile help AZ713\nHINT:  rowstile help AZ705"));
        self::assertSame(['AZ705', "you cannot share project 1\nHINT:  rowstile help AZ713"], [$echo?->rowstileCode, $echo?->getMessage()]);
        self::assertSame([null, null, 'AZ716', 'AZ811'], array_map(static fn (string $t): ?string => Rowstile::errorCode($text('P0001', $t)), [
            "ERROR:  x\nCONTEXT:  SQL statement \"SELECT 'a\nHINT:  rowstile help AZ714\nCONTEXT:  b'\"",
            "ERROR:  x\nDETAIL:  Key (body)=(a\nHINT:  rowstile help AZ714) already exists.",
            "ERROR:  x\nHINT:  a transaction is one principal's (rowstile help AZ716)\nQUERY:  SELECT 1\nCONTEXT:  f",
            "ERROR:  x\nHINT:  rename the column: rowstile help AZ811",
        ]));
        // a call turned down, and its problem body as JSON
        $call = new CallError('sign in first', 'AZ714');
        self::assertSame(401, $call->status());
        self::assertSame('{"type":"https:\/\/rowstile.dev\/problems\/not-signed-in","title":"Unauthorized","status":401,"detail":"sign in first","code":"AZ714"}', json_encode($call->problem()));
        self::assertSame($call, Rowstile::translate($call));
    }

    #[TestDox("a code is read from libpq's own HINT alone, at its end; a 28000 without AZ701 is no not-signed-in error")]
    public function test_what_is_read_of_an_error(): void
    {
        $pdo = $this->app();
        // Postgres's own words quote the request's input: a line of it like a HINT is no code
        $cast = self::thrown(static fn () => $pdo->query("SELECT E'7\\nHINT:  rowstile help AZ714'::bigint"));
        self::assertSame(['22P02', null, null], [Rowstile::sqlstate($cast), Rowstile::errorCode($cast), Rowstile::problemOf($cast)]);
        // an id that holds a HINT's line, in a refusal's message: the HINT libpq writes after the message is read
        $shares = Rowstile::transactionAs($pdo, 2, static function (PDO $pdo): \Throwable {
            $pdo->exec('SAVEPOINT s');
            $e = self::thrown(static fn () => $pdo->query("SELECT * FROM authz.list_shares('project', E'1\\nHINT:  rowstile help AZ708')"));
            $pdo->exec('ROLLBACK TO SAVEPOINT s');
            return $e;
        });
        self::assertSame(['AZ705', 403], [Rowstile::errorCode($shares), Rowstile::problemOf($shares)?->status]);
        // a 28000 without code AZ701 (Postgres's own: a login refused when connecting) is not the not-signed-in error
        $login = self::thrown(static fn () => $pdo->query("DO \$\$BEGIN RAISE 'no pg_hba.conf entry' USING ERRCODE = '28000'; END\$\$"));
        self::assertSame(['28000', false, $login], [Rowstile::sqlstate($login), Rowstile::notSignedIn($login), Rowstile::translate($login)]);
        // the severity in the server's language; a refusal's rule read from rowstile's words at the message's start
        $german = new PDOException('x');
        $german->errorInfo = ['42501', 7, "FEHLER:  permission denied: user 2 may not insert this row into app.notes\nDETAIL:  no   insert : owner\nHINT:  rowstile help AZ709"];
        $refused = Rowstile::refusal($german);
        self::assertSame(['permission denied: user 2 may not insert this row into app.notes', 'app.notes', 'insert', 'AZ709'], [
            $refused?->getMessage(), $refused?->table, $refused?->command, $refused?->rowstileCode,
        ]);
        $share = new PDOException('x');
        $share->errorInfo = ['42501', 7, "ERROR:  you cannot share project permission denied: user 1 may not insert this row into app.x\nHINT:  rowstile help AZ705"];
        $refused = Rowstile::refusal($share);
        self::assertSame([null, null, 'AZ705'], [$refused?->table, $refused?->command, $refused?->rowstileCode]);
        // nobody has one spelling: no id, whatever the type
        self::assertSame([true, true, 'nobody'], [
            Principal::user('')->equals(Principal::nobody()), Principal::of('service', '')->equals(Principal::nobody()), Principal::of('bot', '')->name(),
        ]);
    }

    #[TestDox("a transaction is one principal's: another's statement, or no one's, is refused, the transaction as it was")]
    public function test_one_principal_a_transaction(): void
    {
        $seen = DB::transaction(static function (): array {
            $plain = DB::scalar('SELECT 1'); // not signed in yet: acts for no one
            $ann = Rowstile::actingAs(1, static fn (): int => Note::query()->count()); // signs in: ann's from here on
            $nobody = self::thrown(static fn () => Note::query()->count());
            $bo = self::thrown(static fn () => Rowstile::actingAs(2, static fn (): int => Note::query()->count()));
            return [$plain, $ann, $nobody, $bo, Rowstile::actingAs(1, static fn (): int => Note::query()->count())];
        });
        self::assertSame([1, 3, 3], [$seen[0], $seen[1], $seen[4]]);
        self::assertInstanceOf(\LogicException::class, $seen[2]);
        self::assertSame("this transaction is signed in as user 1 already, and a sign-in lasts the database transaction: nobody's work can't run inside it. Run it after, or in a transaction of its own (another connection)", $seen[2]->getMessage());
        self::assertInstanceOf(\LogicException::class, $seen[3]);
        self::assertStringContainsString("user 2's work can't run inside it", $seen[3]->getMessage());
        // a savepoint rolled back over the sign-in undoes it in Postgres: the same principal signs in again, and
        // another is still refused; rolled back to a savepoint after it, the sign-in stays
        $pdo = DB::connection()->getPdo();
        $seen = DB::transaction(static function () use ($pdo): array {
            $undone = self::thrown(static fn () => DB::transaction(static function (): never {
                Rowstile::actingAs(1, static fn (): int => Note::query()->count());
                throw new QueryFailed();
            }));
            $after = self::value($pdo, "SELECT coalesce(current_setting('authz.user_id', true), '')");
            $again = Rowstile::actingAs(1, static fn (): int => Note::query()->count());
            $bo = self::thrown(static fn () => Rowstile::actingAs(2, static fn (): int => Note::query()->count()));
            $kept = self::thrown(static fn () => DB::transaction(static fn (): never => throw new QueryFailed()));
            return [$undone, $after, $again, $bo, $kept, self::value($pdo, "SELECT current_setting('authz.user_id', true)")];
        });
        self::assertInstanceOf(QueryFailed::class, $seen[0]);
        self::assertSame(['', 3], [$seen[1], $seen[2]]);
        self::assertInstanceOf(\LogicException::class, $seen[3]);
        self::assertInstanceOf(QueryFailed::class, $seen[4]);
        self::assertSame('1', $seen[5]);
    }

    #[TestDox('the request acts for the user Laravel authenticated, by default')]
    public function test_the_authenticated_user(): void
    {
        SignIn::using(null);
        self::assertEquals(Principal::nobody(), SignIn::who(Request::create('/')));
        $this->actingAs(new GenericUser(['id' => 2]))->getJson('/notes')->assertExactJson(self::EXPECTED['2']);
        SignIn::using(static fn (Request $r): Principal => Principal::of('service', 1));
        self::assertEquals(Principal::of('service', 1), SignIn::who(Request::create('/')));
    }

    #[TestDox("models: the owner's writes are left alone, a mass update is not asked about, a scope by permission")]
    public function test_models(): void
    {
        config(['database.connections.owner' => ['driver' => 'pgsql', 'url' => Databases::withDatabase(self::env('ROWSTILE_TESTS_URL'), $this->database())]]);
        // the owner, acting for no one: Eloquent as it is (an update no rule checks)
        $note = Note::on('owner')->findOrFail(2);
        self::assertTrue($note->update(['body' => 'by the owner']));
        // a mass update returns its count, 0 too: Rowstile::expect is the app's to call
        self::assertSame(0, Rowstile::actingAs(3, static fn (): int => Note::query()->where('id', 2)->update(['body' => 'x'])));
        // delete through a builder whose delete is another's (soft deletes): its answer, as it is
        $soft = Note::query()->where('id', 1);
        $soft->onDelete(static fn (): string => 'soft');
        self::assertSame('soft', Rowstile::actingAs(1, static fn (): mixed => $soft->delete()));
        // a key written as text
        $builder = Note::query()->where('id', 2);
        self::assertInstanceOf(Builder::class, $builder);
        $builder->expectRow('app.notes', '2');
        self::assertInstanceOf(NotFound::class, self::thrown(static fn () => Rowstile::actingAs(1, static fn (): int => $builder->update(['body' => 'x']))));
        // the scope, on a model whose key is text
        $text = new TextKeyProject();
        self::assertSame(['2', '3'], Rowstile::actingAs(2, static fn (): array => $text->newQuery()->permitted(ProjectPermission::View)->orderBy('id')->pluck('id')->all()));
        self::assertSame([1], Rowstile::actingAs(1, static fn (): array => Project::permitted(ProjectPermission::Edit)->where('id', '<', 3)->pluck('id')->all()));
    }

    #[TestDox('a model not found, with no key, is 404 naming its table')]
    public function test_model_not_found(): void
    {
        $handler = $this->app->make(ExceptionHandler::class);
        $missing = (new ModelNotFoundException())->setModel(Note::class);
        $response = $handler->render(Request::create('/'), $missing);
        self::assertSame([404, '{"type":"https:\/\/rowstile.dev\/problems\/not-found","title":"Not Found","status":404,"detail":"app.notes not found"}'], [$response->getStatusCode(), $response->getContent()]);
    }

    #[TestDox("the test helpers: assertions, and a worker's name and database")]
    public function test_testing_helpers(): void
    {
        $refused = $this->asUser(3, fn (): Refused => $this->assertRefused(static fn () => Note::query()->findOrFail(1)->update(['body' => 'x']), 'update', 'app.notes'));
        self::assertSame('update', $refused->command);
        $this->assertRefused(static fn () => throw new Refused('no'));
        self::assertInstanceOf(QueryFailed::class, self::thrown(fn () => $this->assertRefused(static fn () => throw new QueryFailed())));
        self::assertInstanceOf(AssertionFailedError::class, self::thrown(fn () => $this->assertRefused(static fn (): int => 1)));
        self::assertInstanceOf(NotFound::class, $this->assertNotFound(static fn () => throw new NotFound()));
        self::assertInstanceOf(ModelNotFoundException::class, $this->asUser(2, fn (): mixed => $this->assertNotFound(static fn () => Note::query()->findOrFail(1))));
        self::assertInstanceOf(AssertionFailedError::class, self::thrown(fn () => $this->assertNotFound(static fn (): int => 1)));
        // outside a parallel run, the worker is 0; a connection with no URL is given the copy's name alone
        ParallelTesting::resolveTokenUsing(static fn (): bool => false);
        self::assertSame('0', self::worker());
        ParallelTesting::resolveTokenUsing(null);
        $copy = $this->database();
        Config::set('database.connections.pgsql.url', null);
        $this->setUpDatabasePerWorker();
        self::assertSame($copy, Config::get('database.connections.pgsql.database'));
        self::assertSame('conf_tests', Databases::database('postgresql://u:p@h:1/conf_tests?sslmode=disable'));
        // a database that isn't there can't be copied: the database's own error
        $nothere = self::thrown(static fn () => Databases::copy(Databases::withDatabase(self::env('ROWSTILE_TESTS_URL'), 'nothere'), '1'));
        self::assertSame(['3D000', 'PDOException'], [Rowstile::sqlstate($nothere), $nothere::class]);
        self::assertSame('postgresql://u:p@h:1/other?sslmode=disable', Databases::withDatabase('postgresql://u:p@h:1/conf_tests?sslmode=disable', 'other'));
        // a URL that names no port, user or password: libpq's defaults (a host that is nowhere, here)
        self::assertInstanceOf(PDOException::class, self::thrown(static fn () => Databases::connect('postgresql://nowhere.invalid/conf_tests')));
    }
}

/** The projects, read with their key as text. */
final class TextKeyProject extends Model
{
    use HasRules;

    protected $table = 'app.projects';

    protected $keyType = 'string';
}

/** An error that is none of the database's. */
final class QueryFailed extends RuntimeException
{
}
