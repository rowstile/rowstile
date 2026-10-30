<?php

declare(strict_types=1);

namespace App\Auth;

use Illuminate\Http\Request;
use Rowstile\Principal;

/**
 * Who a request is. A real app reads its session or token here: a cookie, a bearer token, an API key. The conformance
 * app has no sign-in: its checks name the user in a header, which a real app must never believe. So
 * docs/stacks/laravel.md shows AppServiceProvider calling SessionUser, and never this file.
 */
final class SessionUser
{
    /** The request's signed-in user (null: nobody), or a service (x-service: a service's own API calls). */
    public static function of(Request $request): Principal|string|null
    {
        $service = $request->header('x-service');
        if (is_string($service)) {
            return Principal::of('service', $service);
        }
        $user = $request->header('x-user');
        return is_string($user) ? $user : null;
    }
}
