<?php

declare(strict_types=1);

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Rowstile\Laravel\HasRules;

final class Folder extends Model
{
    use HasRules;

    protected $table = 'app.folders';

    public $timestamps = false;

    /** @var list<string> */
    protected $fillable = ['parent_id', 'owner_id'];
}
