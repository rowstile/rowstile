<?php

declare(strict_types=1);

namespace App\Jobs;

use App\Models\Note;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use Illuminate\Support\Facades\Log;
use Rowstile\Laravel\ActsFor;
use Rowstile\Principal;

// A background job for the user who asked: given to it when the request dispatched it.
final class ExportJob implements ShouldQueue
{
    use Queueable;

    public function __construct(public readonly Principal $who)
    {
    }

    /** @return list<object> */
    public function middleware(): array
    {
        return [new ActsFor($this->who)];
    }

    public function handle(): void
    {
        Log::info('export', ['notes' => Note::query()->orderBy('id')->pluck('id')->all(), 'for' => $this->who]);
    }
}
