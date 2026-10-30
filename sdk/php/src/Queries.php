<?php

declare(strict_types=1);

namespace Rowstile;

use PDO;

use function addcslashes, array_filter, array_map, array_values, implode, json_decode;

/**
 * Questions about permissions, as whoever the querier's transaction signed in as. They take only the policy's names,
 * which `rowstile client php` writes (Authz\NotePermission::Edit), so a misspelled one fails PHPStan.
 *
 *     $queries = new Queries($pdo);         // inside Rowstile::transaction(), or Laravel\Database::queries()
 *     $queries->can(NotePermission::Edit, 7);
 */
final class Queries
{
    private readonly Querier $db;

    public function __construct(Querier|PDO $db)
    {
        $this->db = $db instanceof PDO ? new PdoQuerier($db) : $db;
    }

    /**
     * Whether the user holds the permission on the object with this id (authz.can).
     *
     * @param int|string|list<int|string|null> $id
     */
    public function can(Permission $permission, int|string|array $id): bool
    {
        $rows = $this->db->select('SELECT authz.can(?, CAST(? AS text), ?) AS can', [
            $permission::objectType(), Rowstile::keyText($id), (string) $permission->value,
        ]);
        return ($rows[0]['can'] ?? false) === true;
    }

    /**
     * The permissions held on each of these objects, by id as the database writes it, in one call (a list's
     * buttons, authz.perms_of): permsOf(ProjectPermission::class, [1, 2]) is ['1' => [ProjectPermission::Edit, ...]].
     * A permission with no case in the enum (no PHP name: rowstile client php says which) is left out.
     *
     * @template P of Permission
     * @param class-string<P> $permissions
     * @param list<int|string|list<int|string|null>> $ids
     * @return array<string, list<P>>
     */
    public function permsOf(string $permissions, array $ids): array
    {
        $texts = array_map(static fn (int|string|array $id): string => Rowstile::keyText($id), $ids);
        $rows = $this->db->select('SELECT id, pg_catalog.to_json(perms) AS perms FROM authz.perms_of(?, CAST(? AS text[]))', [
            $permissions::objectType(), self::textArray($texts),
        ]);
        $out = [];
        foreach ($rows as $row) {
            $held = array_map(
                static fn (mixed $name): ?Permission => $permissions::tryFrom(Rowstile::text($name)),
                (array) json_decode(Rowstile::text($row['perms'] ?? null), true),
            );
            $out[Rowstile::text($row['id'] ?? null)] = array_values(array_filter($held));
        }
        return $out;
    }

    /**
     * The ids of the objects of the permission's type on which the user holds it, in key order (authz.list); a page
     * of them with $limit (after $after: null from the first). The database says when the size or the cursor is
     * wrong: CallError, 400. To filter a query to them instead, join authz.list(type, permission) in it (in Laravel,
     * a model's permitted scope).
     *
     * @param int|string|list<int|string|null>|null $after
     * @return list<string>
     */
    public function list(Permission $permission, int|string|array|null $after = null, ?int $limit = null): array
    {
        $rows = $this->db->select('SELECT x FROM authz.list(?, ?, CAST(? AS text), CAST(? AS integer)) x', [
            $permission::objectType(), (string) $permission->value, $after === null ? null : Rowstile::keyText($after), $limit,
        ]);
        return array_map(static fn (array $row): string => Rowstile::text($row['x'] ?? null), $rows);
    }

    /**
     * A text[] literal of these values, each quoted: {"1","(1,2)"}.
     *
     * @param list<string> $values
     */
    private static function textArray(array $values): string
    {
        return '{'.implode(',', array_map(static fn (string $v): string => '"'.addcslashes($v, '"\\').'"', $values)).'}';
    }
}
