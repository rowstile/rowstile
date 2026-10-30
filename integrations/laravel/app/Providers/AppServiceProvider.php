<?php

declare(strict_types=1);

namespace App\Providers;

use App\Auth\SessionUser;
use Illuminate\Http\Request;
use Illuminate\Support\ServiceProvider;
use Rowstile\Laravel\SignIn;

final class AppServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        // who each request acts for: the request's signed-in user (null: nobody), or a service
        SignIn::using(fn (Request $request) => SessionUser::of($request));
    }
}
