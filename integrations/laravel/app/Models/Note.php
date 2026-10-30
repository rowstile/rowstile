<?php

declare(strict_types=1);

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Rowstile\Laravel\HasRules;

final class Note extends Model
{
    use HasRules;

    protected $table = 'app.notes';

    public $timestamps = false;

    /** @var list<string> */
    protected $fillable = ['project_id', 'author_id', 'body'];
}
