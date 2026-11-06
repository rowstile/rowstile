<?php

declare(strict_types=1);

namespace Rowstile\Laravel;

use Closure;
use Illuminate\Database\Eloquent\Builder as EloquentBuilder;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Rowstile\Permission;
use Rowstile\Rowstile;

use function class_uses_recursive, in_array, is_int;

/**
 * Eloquent's builder for a model that uses HasRules: the query a model's update or delete runs (save, delete,
 * increment, decrement, incrementEach, decrementEach, forceDelete) expects its row, and asks the database why when it
 * changed none (Rowstile::expect), in the same transaction; and permitted, the rows on which the user holds a
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
     * with the ids it gives, each cast to the column's type, so its index is used: bigint for an integer key, uuid for
     * a model with HasUuids; any other key is compared as text (a text column's index is used).
     *
     * @return $this
     */
    public function permitted(Permission $permission): static
    {
        $model = $this->getModel();
        $column = $this->getQuery()->getGrammar()->wrap($model->getQualifiedKeyName());
        [$compared, $listed] = match (true) {
            $model->getKeyType() === 'int' => [$column, 'CAST(x AS bigint)'],
            in_array(HasUuids::class, class_uses_recursive($model), true) => [$column, 'CAST(x AS uuid)'],
            default => ["CAST({$column} AS text)", 'x'],
        };
        // (the column's name is the model's, wrapped by the grammar: no input is in the SQL, only in its arguments)
        /** @var literal-string $sql */
        $sql = "{$compared} IN (SELECT {$listed} FROM authz.list(?, ?) x)";
        $this->whereRaw($sql, [$permission::objectType(), (string) $permission->value]);
        return $this;
    }

    /** @param array<string, mixed> $values */
    public function update(array $values): int
    {
        return $this->expect(fn (): int => parent::update($values), 'update');
    }

    /**
     * @param \Illuminate\Contracts\Database\Query\Expression|string $column
     * @param float|int $amount
     * @param array<string, mixed> $extra
     */
    public function increment($column, $amount = 1, array $extra = []): int
    {
        return $this->expect(fn (): int => parent::increment($column, $amount, $extra), 'update');
    }

    /**
     * @param \Illuminate\Contracts\Database\Query\Expression|string $column
     * @param float|int $amount
     * @param array<string, mixed> $extra
     */
    public function decrement($column, $amount = 1, array $extra = []): int
    {
        return $this->expect(fn (): int => parent::decrement($column, $amount, $extra), 'update');
    }

    /**
     * @param array<string, float|int|numeric-string> $columns
     * @param array<string, mixed> $extra
     */
    public function incrementEach(array $columns, array $extra = []): int
    {
        return $this->expect(fn (): int => parent::incrementEach($columns, $extra), 'update');
    }

    /**
     * @param array<string, float|int|numeric-string> $columns
     * @param array<string, mixed> $extra
     */
    public function decrementEach(array $columns, array $extra = []): int
    {
        return $this->expect(fn (): int => parent::decrementEach($columns, $extra), 'update');
    }

    public function delete(): mixed
    {
        $answer = null;
        $this->expect(function () use (&$answer): int { // (it answers with the count it is given, or throws)
            $answer = parent::delete();
            return is_int($answer) ? $answer : 1; // another's delete (soft deletes): its answer, as it is
        }, 'delete');
        return $answer;
    }

    /** The delete a soft-deleting model's forceDelete runs: the row itself, whatever the model's scopes. */
    public function forceDelete(): int
    {
        return $this->expect(fn (): int => $this->query->delete(), 'delete');
    }

    /**
     * $change's count, and, for a model's own query that changed no row, why (Rowstile::expect): in one transaction
     * with the statement, the one open or one of its own, so the answer is about the row the statement saw.
     *
     * @param Closure(): int $change
     */
    private function expect(Closure $change, string $command): int
    {
        if ($this->expected === null) {
            return $change();
        }
        [$table, $key] = $this->expected;
        $connection = $this->getModel()->getConnection();
        $checked = fn (): int => Rowstile::expect(new Database($connection->getName()), $change(), $table, $command, $key);
        return $connection->transactionLevel() > 0 ? $checked() : $connection->transaction($checked);
    }
}
