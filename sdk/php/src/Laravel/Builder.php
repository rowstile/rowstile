<?php

declare(strict_types=1);

namespace Rowstile\Laravel;

use Illuminate\Database\Eloquent\Builder as EloquentBuilder;
use Illuminate\Database\Eloquent\Model;
use Rowstile\Permission;
use Rowstile\Rowstile;

use function is_int;

/**
 * Eloquent's builder for a model that uses HasRules: the query a model's update or delete runs expects its row, and
 * asks the database why when it changed none (Rowstile::expect); and permitted, the rows on which the user holds a
 * permission.
 *
 * @template TModel of Model
 * @extends EloquentBuilder<TModel>
 */
class Builder extends EloquentBuilder
{
    /** @var ?array{string, int|string} the table and the key of the row this query must change */
    private ?array $expected = null;

    /**
     * The query a model's update or delete runs: Eloquent's (the model's key), and, while the code acts for someone,
     * the row it must change.
     *
     * @template T of Model
     * @param EloquentBuilder<T> $query
     * @param mixed $key the model's key, as it was read
     * @return EloquentBuilder<T>
     */
    public static function forSave(EloquentBuilder $query, Model $model, mixed $key): EloquentBuilder
    {
        $query->where($model->getKeyName(), '=', $key);
        if ($query instanceof self && Rowstile::current() !== null) {
            $query->expectRow($model->getTable(), $key);
        }
        return $query;
    }

    /** The model's own update or delete: one row, of this table, with this key. */
    public function expectRow(string $table, mixed $key): void
    {
        $this->expected = [$table, is_int($key) ? $key : Rowstile::text($key)];
    }

    /**
     * Only the rows on which the user holds the permission (authz.list, one set lookup). The key's column is compared
     * with the ids it gives, cast to bigint for an integer key (its index is used), else the column as text.
     *
     * @return $this
     */
    public function permitted(Permission $permission): static
    {
        $model = $this->getModel();
        $column = $this->getQuery()->getGrammar()->wrap($model->getQualifiedKeyName());
        [$compared, $listed] = $model->getKeyType() === 'int' ? [$column, 'CAST(x AS bigint)'] : ["CAST({$column} AS text)", 'x'];
        // (the column's name is the model's, wrapped by the grammar: no input is in the SQL, only in its arguments)
        /** @var literal-string $sql */
        $sql = "{$compared} IN (SELECT {$listed} FROM authz.list(?, ?) x)";
        $this->whereRaw($sql, [$permission::objectType(), (string) $permission->value]);
        return $this;
    }

    /** @param array<string, mixed> $values */
    public function update(array $values): int
    {
        return $this->expect(parent::update($values), 'update');
    }

    public function delete(): mixed
    {
        $deleted = parent::delete();
        return is_int($deleted) ? $this->expect($deleted, 'delete') : $deleted;
    }

    private function expect(int $changed, string $command): int
    {
        if ($this->expected === null) {
            return $changed;
        }
        [$table, $key] = $this->expected;
        return Rowstile::expect(new Database($this->getModel()->getConnectionName()), $changed, $table, $command, $key);
    }
}
