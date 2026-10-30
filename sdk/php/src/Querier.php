<?php

declare(strict_types=1);

namespace Rowstile;

/**
 * What runs a statement and gives its rows, in the transaction the code is in: PdoQuerier (a PDO, inside
 * Rowstile::transaction()), or Laravel\Database (a Laravel connection, which signs its transactions in).
 */
interface Querier
{
    /**
     * The statement's rows, each a map of its columns.
     *
     * @param list<mixed> $params the values of its ? placeholders, in order
     * @return list<array<string, mixed>>
     */
    public function select(string $sql, array $params = []): array;
}
