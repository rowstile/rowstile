<?php

declare(strict_types=1);

namespace Rowstile\Laravel;

use Closure;
use Rowstile\Principal;
use Rowstile\Rowstile;

/**
 * Job middleware: the queued job acts for the principal it names, whatever request dispatched it, so every
 * transaction it begins signs in as them. The next job on the worker never acts for the one before.
 *
 *     public function middleware(): array
 *     {
 *         return [new ActsFor(Principal::of('service', 1))];   // or the user who asked, given to the job
 *     }
 */
final class ActsFor
{
    public readonly Principal $who;

    public function __construct(Principal|int|string|null $who)
    {
        $this->who = Principal::from($who);
    }

    /** @param Closure(object): mixed $next */
    public function handle(object $job, Closure $next): mixed
    {
        return Rowstile::actingAs($this->who, static fn (): mixed => $next($job));
    }
}
