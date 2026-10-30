<?php

// The conformance app: no permission checks anywhere. rowstile signs each request's transactions in, the database
// filters reads and refuses writes, and the SDK turns refusals into 403 and hidden rows into 404.

declare(strict_types=1);

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Rowstile\Laravel\SignIn;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(api: __DIR__.'/../routes/api.php', apiPrefix: '')
    ->withMiddleware(function (Middleware $middleware): void {
        // each request acts for its user, before route model binding reads a row
        $middleware->api(prepend: [SignIn::class]);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        $exceptions->shouldRenderJsonWhen(fn (): bool => true);
    })->create();
