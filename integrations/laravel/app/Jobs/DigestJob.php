<?php

declare(strict_types=1);

namespace App\Jobs;

use App\Models\Project;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use Illuminate\Support\Facades\Log;
use Rowstile\Laravel\ActsFor;
use Rowstile\Principal;
use Rowstile\Rowstile;

// A background job: it signs in as service 1, whatever request dispatched it.
final class DigestJob implements ShouldQueue
{
    use Queueable;

    /** @return list<object> */
    public function middleware(): array
    {
        return [new ActsFor(Principal::of('service', 1))];
    }

    public function handle(): void
    {
        // (what it saw, for the checks: the projects it reads, and who it acted for)
        Log::info('digest', ['projects' => Project::query()->count(), 'as' => Rowstile::current()]);
    }
}
