<?php

declare(strict_types=1);

namespace Rowstile;

use PDO;

/** A Querier over a PDO connection to Postgres (pdo_pgsql), in whatever transaction it is in. */
final class PdoQuerier implements Querier
{
    public function __construct(private readonly PDO $pdo)
    {
    }

    public function select(string $sql, array $params = []): array
    {
        $statement = $this->pdo->prepare($sql);
        $statement->execute($params);
        /** @var list<array<string, mixed>> */
        return $statement->fetchAll(PDO::FETCH_ASSOC);
    }
}
