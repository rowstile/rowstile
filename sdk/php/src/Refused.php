<?php

declare(strict_types=1);

namespace Rowstile;

use RuntimeException;
use Throwable;

/**
 * The database refusing a write, and saying why: the rule (its table and command), and the reasons, a line each.
 * The code is rowstile's (`rowstile help AZ709`): AZ709 for a rule's refusal, the database's own for another (AZ704:
 * a read-only session, AZ705: the shares of an object one can't see, AZ715: a call for users made by a service),
 * which names no rule.
 */
final class Refused extends RuntimeException
{
    /**
     * @param ?string $table schema.table, null when the refusal names none
     * @param ?string $command insert, update, delete or select; null when it names none
     * @param list<string> $why
     */
    public function __construct(
        string $message,
        public readonly ?string $table = null,
        public readonly ?string $command = null,
        public readonly array $why = [],
        public readonly string $rowstileCode = 'AZ709',
        ?Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }

    /** Its problem body: 403, with the rule and why. */
    public function problem(): Problem
    {
        return new Problem('refused', 'Forbidden', 403, $this->getMessage(), $this->rowstileCode, [
            'table' => $this->table,
            'command' => $this->command,
            'why' => $this->why,
        ]);
    }
}
