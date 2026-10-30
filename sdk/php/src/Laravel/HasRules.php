<?php

declare(strict_types=1);

namespace Rowstile\Laravel;

use Illuminate\Database\Eloquent\Builder as EloquentBuilder;

/**
 * For a model whose table has rules: its queries are Rowstile\Laravel\Builder. An update or a delete of a model that
 * changed no row (row-level security left it out) asks the database why, in the same transaction and as the same
 * user, and throws NotFound (the row is hidden) or Refused (and why): Eloquent alone would say it saved. Only while the
 * code acts for someone: the owner's code is left as Laravel runs it. And the builder's permitted: the model's rows on
 * which the user holds a permission, in one set lookup (authz.list), never a call per row.
 *
 *     class Note extends Model { use HasRules; }
 *     Project::permitted(ProjectPermission::Edit)->orderBy('id')->pluck('id');
 */
trait HasRules
{
    /**
     * @param \Illuminate\Database\Query\Builder $query
     * @return Builder<self>
     */
    public function newEloquentBuilder($query): Builder
    {
        /** @var Builder<self> (a builder of this model: Eloquent gives it the model next) */
        return new Builder($query);
    }

    /**
     * The query an update or a delete of this model runs (Eloquent's own: its key), told what to expect of it.
     *
     * @param EloquentBuilder<self> $query
     * @return EloquentBuilder<self>
     */
    protected function setKeysForSaveQuery($query): EloquentBuilder
    {
        return Builder::forSave($query, $this, $this->getKeyForSaveQuery());
    }
}
