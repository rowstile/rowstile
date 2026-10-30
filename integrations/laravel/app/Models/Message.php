<?php

declare(strict_types=1);

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Rowstile\Laravel\HasRules;

final class Message extends Model
{
    use HasRules;

    protected $table = 'app.inbox';

    public $timestamps = false;

    /** @var list<string> */
    protected $fillable = ['sender_id', 'recipient_id', 'body'];
}
