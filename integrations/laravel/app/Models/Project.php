<?php

declare(strict_types=1);

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Rowstile\Laravel\HasRules;

final class Project extends Model
{
    use HasRules;

    protected $table = 'app.projects';

    public $timestamps = false;

    /** @var list<string> */
    protected $fillable = [];
}
