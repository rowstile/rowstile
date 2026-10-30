<?php

declare(strict_types=1);

namespace Rowstile\Testing;

use Closure;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use PHPUnit\Framework\Assert;
use Rowstile\NotFound;
use Rowstile\Principal;
use Rowstile\Refused;
use Rowstile\Rowstile;
use Throwable;

use function str_starts_with;

/**
 * PHPUnit assertions for apps on rowstile, for a TestCase:
 *
 *     use \Rowstile\Testing\Assertions;
 *
 *     $this->asUser(3, fn () => $this->assertRefused(fn () => Note::findOrFail(1)->update(['body' => 'x']), 'update'));
 */
trait Assertions
{
    /**
     * Runs $fn acting for who (42, Principal::of('service', 3), null for nobody).
     *
     * @template T
     * @param Closure(): T $fn
     * @return T
     */
    public function asUser(Principal|int|string|null $who, Closure $fn): mixed
    {
        return Rowstile::actingAs($who, $fn);
    }

    /**
     * $fn must be refused by the policy (by the rule for $command, on $table, when given); returns the Refused. A
     * database error that is no refusal fails the test with it.
     */
    public function assertRefused(Closure $fn, ?string $command = null, ?string $table = null): Refused
    {
        try {
            $fn();
        } catch (Throwable $e) {
            $refused = Rowstile::refusal($e) ?? throw $e;
            if ($command !== null) {
                Assert::assertTrue(str_starts_with((string) $refused->command, $command), "expected the {$command} rule to refuse it, but: {$refused->command}: {$refused->getMessage()}");
            }
            if ($table !== null) {
                Assert::assertSame($table, $refused->table);
            }
            return $refused;
        }
        Assert::fail('expected a refusal');
    }

    /**
     * $fn must find no row (NotFound, or Eloquent's ModelNotFoundException: the row is hidden); returns what it threw.
     *
     * @return NotFound|ModelNotFoundException<\Illuminate\Database\Eloquent\Model>
     */
    public function assertNotFound(Closure $fn): NotFound|ModelNotFoundException
    {
        try {
            $fn();
        } catch (NotFound|ModelNotFoundException $e) {
            return $e;
        }
        Assert::fail('expected NotFound');
    }
}
