<?php

declare(strict_types=1);

namespace Rowstile;

use RuntimeException;

use function array_filter, implode;

/** A row that isn't there, or that whoever the transaction acts for can't see. */
final class NotFound extends RuntimeException
{
    /**
     * @param ?string $table schema.table
     * @param ?string $id the row's key as Postgres writes it: 7, or (1,2) for a key of several columns
     */
    public function __construct(public readonly ?string $table = null, public readonly ?string $id = null)
    {
        // app.notes 7 not found, row 7 not found, app.notes not found, or not found
        $named = $id === null ? [$table] : [$table ?? 'row', $id];
        parent::__construct(implode(' ', [...array_filter($named, static fn (?string $s): bool => $s !== null), 'not found']));
    }

    /** Its problem body: 404. */
    public function problem(): Problem
    {
        return new Problem('not-found', 'Not Found', 404, $this->getMessage());
    }
}
