<?php

declare(strict_types=1);

namespace Tests\Feature;

use App\Jobs\DigestJob;
use App\Models\Note;
use Illuminate\Database\QueryException;
use Illuminate\Log\Events\MessageLogged;
use Illuminate\Support\Facades\Event;
use PDOException;
use PHPUnit\Framework\Attributes\TestDox;
use Rowstile\Principal;
use Rowstile\Rowstile;
use Tests\TestCase;

/**
 * The conformance suite (integrations/README.md): the same checks for every stack. This is Laravel, Eloquent on
 * pdo_pgsql. test.sh does check 11 (a fresh database: migrate, the policy's tests, then Laravel's own migrate
 * --pretend shows nothing left to run) before these run.
 */
final class ConformanceTest extends TestCase
{
    #[TestDox('1, 2: lists show what each may see')]
    public function test_1_2_lists(): void
    {
        foreach (self::EXPECTED as $user => $notes) {
            $this->getJson('/notes', $this->as($user === '' ? null : (string) $user))->assertOk()->assertExactJson($notes);
        }
        $this->getJson('/projects')->assertExactJson([3]);
    }

    #[TestDox('3: not signed in is an error that says how')]
    public function test_3_not_signed_in(): void
    {
        $app = $this->app();
        $app->beginTransaction();
        try {
            $app->query('SELECT count(*) FROM app.notes');
            self::fail('expected the not-signed-in error');
        } catch (PDOException $e) {
            self::assertSame('28000', Rowstile::sqlstate($e));
            self::assertStringContainsString('act_as', $e->getMessage());
            self::assertSame('AZ701', Rowstile::errorCode($e)); // rowstile help AZ701
            self::assertTrue(Rowstile::notSignedIn($e));
        }
    }

    #[TestDox('6: a refused insert says which rule')]
    public function test_6_refused_insert(): void
    {
        $response = $this->postJson('/notes', ['project_id' => 3, 'body' => 'hi'], $this->as('2'));
        $response->assertStatus(403)->assertHeader('content-type', 'application/problem+json');
        self::assertSame(['app.notes', 'insert', 'AZ709'], [$response->json('table'), $response->json('command'), $response->json('code')]);
        self::assertStringContainsString('user 2 may not insert this row into app.notes', self::text($response->json('detail')));
        self::assertNotEmpty(array_filter((array) $response->json('why'), static fn (mixed $l): bool => str_contains(self::text($l), 'project.edit')));
    }

    #[TestDox('7: hidden is 404 and not allowed is 403')]
    public function test_7_hidden_and_not_allowed(): void
    {
        $this->patchJson('/notes/1', ['body' => 'x'], $this->as('2'))->assertStatus(404)->assertExactJson([
            'type' => 'https://rowstile.dev/problems/not-found', 'title' => 'Not Found', 'status' => 404, 'detail' => 'app.notes 1 not found',
        ]);
        $refused = $this->patchJson('/notes/1', ['body' => 'x'], $this->as('3'))->assertStatus(403);
        self::assertSame('update', $refused->json('command'));
        self::assertNotEmpty(array_filter((array) $refused->json('why'), static fn (mixed $l): bool => str_contains(self::text($l), 'edit')));
        // worded as the database words a refused insert: who, the command, the row, the table
        self::assertSame('permission denied: user 3 may not update row 1 of app.notes', $refused->json('detail'));
        $this->patchJson('/notes/4', ['body' => 'better idea'], $this->as('3'))->assertOk();
        $this->deleteJson('/notes/2', [], $this->as('1'))->assertStatus(404);
        $deleted = $this->deleteJson('/notes/1', [], $this->as('3'))->assertStatus(403);
        self::assertSame('delete', $deleted->json('command'));
        self::assertSame('permission denied: user 3 may not delete row 1 of app.notes', $deleted->json('detail'));
        self::assertNotEmpty($deleted->json('why'));
    }

    #[TestDox('7: a row hidden before the update is 404')]
    public function test_7_hidden_before_the_update(): void
    {
        // cy's note in ann's project, which ann reads and which is in bo's project by the time her update reaches the
        // database. The app found the row: the 404 is the database's answer (explain_rule)
        $moved = [];
        Note::updating(function () use (&$moved): void {
            $moved[] = $this->owner()->exec('UPDATE app.notes SET project_id = 2 WHERE id = 4');
        });
        $this->patchJson('/notes/4', ['body' => 'x'], $this->as('1'))->assertStatus(404)
            ->assertHeader('content-type', 'application/problem+json')
            ->assertExactJson(['type' => 'https://rowstile.dev/problems/not-found', 'title' => 'Not Found', 'status' => 404, 'detail' => 'app.notes 4 not found']);
        self::assertSame([1], $moved);
    }

    #[TestDox('8: insert, then read back')]
    public function test_8_insert_then_read_back(): void
    {
        $created = $this->postJson('/notes', ['project_id' => 1, 'body' => 'new'], $this->as('1'))->assertStatus(201);
        self::assertGreaterThan(100, $created->json('id'));
        $unseen = $this->postJson('/inbox', ['recipient_id' => 2, 'body' => 'hi bo'], $this->as('1'))->assertStatus(403);
        self::assertSame('select', $unseen->json('command'));
        self::assertStringContainsString('may not see the row as written', self::text($unseen->json('detail')));
        $this->postJson('/inbox/quietly', ['recipient_id' => 2, 'body' => 'hi bo'], $this->as('1'))->assertStatus(202);
    }

    #[TestDox('16: not there is 404 and a wrong argument 400')]
    public function test_16_not_there_and_wrong_argument(): void
    {
        $key = $this->apiKey('ci');
        $this->getJson('/projects/page?limit=1', $this->as('1'))->assertOk()->assertExactJson(['1']);
        foreach (['limit=-1' => 'the page size must not be negative (got -1)', 'limit=1&after=x' => "the page cursor 'x' is not a project id"] as $query => $detail) {
            $this->getJson("/projects/page?{$query}", $this->as('1'))->assertStatus(400)
                ->assertHeader('content-type', 'application/problem+json')
                ->assertExactJson($this->problem('bad-argument', 'Bad Request', 400, $detail, 'AZ710'));
        }
        $others = $this->deleteJson("/keys/{$key}", [], $this->as('2')); // bo's key it isn't
        $this->deleteJson("/keys/{$key}", [], $this->as('1'))->assertNoContent();
        $again = $this->deleteJson("/keys/{$key}", [], $this->as('1')); // revoked: there is none now
        // no refusal: for this user the key isn't there (bo's own keys don't hold it; ann's no longer do)
        foreach ([$others, $again] as $response) {
            $response->assertStatus(404)->assertExactJson($this->problem('not-found', 'Not Found', 404, "no API key {$key} of yours", 'AZ708'));
        }
    }

    #[TestDox('16: each code answers as its page says')]
    public function test_16_each_code(): void
    {
        $readOnly = $this->apiKey('ro', true);
        $answers = [
            'nobody' => $this->postJson('/keys', ['name' => 'k']),
            'asks' => $this->postJson('/projects/1/requests', ['relation' => 'member', 'reason' => 'the review']),
            'bad_key' => $this->postJson('/keys', ['name' => 'k'], $this->as('1') + ['x-api-key' => 'ak_nope']),
            'inside' => $this->patchJson('/folders/1', ['parent_id' => 2], $this->as('1')),
        ];
        $expected = [
            'nobody' => $this->problem('not-signed-in', 'Unauthorized', 401, 'sign in to create an API key', 'AZ714'),
            'asks' => $this->problem('not-signed-in', 'Unauthorized', 401, 'sign in first', 'AZ714'),
            'bad_key' => $this->problem('not-signed-in', 'Unauthorized', 401, 'invalid API key', 'AZ703'),
            'inside' => $this->problem('conflict', 'Conflict', 409, 'folder 1 cannot be moved inside itself', 'AZ713'),
        ];
        foreach ($expected as $k => $body) {
            $answers[$k]->assertHeader('content-type', 'application/problem+json')->assertExactJson($body)->assertStatus(self::number($body['status']));
        }
        $made = $this->postJson('/keys', ['name' => 'k'], $this->as('1'))->assertStatus(201);
        self::assertStringStartsWith('ak_', self::text($made->json('key')));
        $this->patchJson('/folders/2', ['parent_id' => 1], $this->as('1'))->assertOk();
        // refusals, by the database's own code: 403, naming no rule
        $refusals = [
            ['scoped', $this->postJson('/keys', ['name' => 'k'], $this->as('1') + ['x-api-key' => $readOnly]), 'this session is read-only', 'AZ704'],
            ['not_shared', $this->getJson('/projects/1/shares', $this->as('2')), 'you cannot see the shares of project 1', 'AZ705'],
        ];
        foreach ($refusals as [$k, $response, $detail, $code]) {
            self::assertSame([403, 'https://rowstile.dev/problems/refused', $code, null, null], [
                $response->status(), $response->json('type'), $response->json('code'), $response->json('table'), $response->json('command'),
            ], $k);
            self::assertStringStartsWith($detail, self::text($response->json('detail')));
        }
        // a call that is for users, made by a service (rowstile help AZ715): a refusal too, 403
        $this->postJson('/keys', ['name' => 'mine'], ['x-service' => '1'])->assertStatus(403)
            ->assertHeader('content-type', 'application/problem+json')
            ->assertExactJson([
                'type' => 'https://rowstile.dev/problems/refused', 'title' => 'Forbidden', 'status' => 403,
                'detail' => 'authz.create_api_key for oneself is for users, not services (service 1 is signed in)',
                'table' => null, 'command' => null, 'why' => [], 'code' => 'AZ715',
            ]);
        // a column's rule refuses a new owner: 403, naming the table and the command
        $owner = $this->patchJson('/folders/2', ['owner_id' => 2], $this->as('1'))->assertStatus(403);
        self::assertSame(['app.folders', 'update', 'AZ709'], [$owner->json('table'), $owner->json('command'), $owner->json('code')]);
        self::assertStringStartsWith('changing owner_id of app.folders 2 needs: nobody', self::text($owner->json('detail')));
        // the app's mistakes: a 500, and the database's own error, not a problem
        $mistakes = [
            fn () => $this->postJson('/projects/1/requests', ['relation' => 'member', 'reason' => 'the review'], $this->as('2')),
            fn () => $this->postJson('/keys', ['name' => 'k', 'principal_type' => 'service', 'principal_id' => '1'], $this->as('1')),
            fn () => $this->getJson('/notes/as/2', $this->as('1')),
        ];
        foreach ($mistakes as $call) {
            $call()->assertStatus(500);
        }
        $this->withoutExceptionHandling();
        $said = array_map(function (callable $call): array {
            try {
                $call();
            } catch (QueryException $e) {
                return [Rowstile::errorCode($e), Rowstile::sqlstate($e), $e->getMessage()];
            }
            self::fail('expected the database to turn it down');
        }, $mistakes);
        self::assertSame([['AZ706', 'P0001'], ['AZ707', 'P0001'], ['AZ702', '28000']], array_map(static fn (array $s): array => [$s[0], $s[1]], $said));
        foreach (['the policy does not allow sharing project.member with a user', 'the policy gives service no manage_keys permission, so nobody manages its keys', 'who is signed in was changed after signing in'] as $i => $words) {
            self::assertStringContainsString($words, $said[$i][2]);
        }
    }

    #[TestDox('10: a job acts as its service')]
    public function test_10_a_job_acts_as_its_service(): void
    {
        $logged = [];
        Event::listen(MessageLogged::class, static function (MessageLogged $m) use (&$logged): void {
            $logged[] = [$m->message, $m->context];
        });
        Rowstile::actingAs(3, static fn () => DigestJob::dispatchSync()); // whatever started it
        // project 1 (it is added to) and the public one, as service 1
        self::assertEquals([['digest', ['projects' => 2, 'as' => Principal::of('service', 1)]]], $logged);
        self::assertEquals(Principal::user(3), Rowstile::actingAs(3, static fn () => Rowstile::current()));
    }

    #[TestDox("10: an id with a colon is a user's, not a service")]
    public function test_10_an_id_is_a_users(): void
    {
        self::assertEquals(['user', 'service:1'], [Principal::from('service:1')->type, Principal::from('service:1')->id]);
        self::assertEquals(['service', '1'], Principal::of('service', 1)->actAsArguments());
        self::assertSame([null, null], Principal::from(null)->actAsArguments());
        self::assertTrue(Principal::nobody()->isNobody());
        self::assertFalse(Principal::user(42)->isNobody());
        $p = Principal::user('7');
        self::assertSame($p, Principal::from($p));
    }

    /** An API key of ann's, made in one transaction as the owner; its id, or with $readOnly the key itself, read-only. */
    private function apiKey(string $name, bool $readOnly = false): string
    {
        $owner = $this->owner();
        $owner->beginTransaction();
        $owner->exec("SELECT authz.act_as('user', '1')");
        if ($readOnly) {
            $key = self::value($owner, "SELECT authz.create_api_key('{$name}', 'read') AS key");
        } else {
            self::value($owner, "SELECT authz.create_api_key('{$name}')");
            $key = self::value($owner, "SELECT max(id) FROM authz.api_keys WHERE user_id = '1'");
        }
        $owner->commit();
        return is_int($key) ? (string) $key : self::text($key);
    }
}
