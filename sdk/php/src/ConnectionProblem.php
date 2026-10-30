<?php

declare(strict_types=1);

namespace Rowstile;

use RuntimeException;

use function implode;

/**
 * authz.connection_check() finding that the app's connection skips row-level security (or worse): a superuser, a
 * role with BYPASSRLS, the tables' owner.
 */
final class ConnectionProblem extends RuntimeException
{
    /** @param list<string> $problems */
    public function __construct(public readonly array $problems)
    {
        parent::__construct("the app's database connection can't be used with rowstile: ".implode('; ', $problems));
    }
}
