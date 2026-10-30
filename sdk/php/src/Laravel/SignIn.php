<?php

declare(strict_types=1);

namespace Rowstile\Laravel;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Rowstile\Principal;
use Rowstile\Rowstile;
use Symfony\Component\HttpFoundation\Response;

/**
 * Route middleware: each request acts for whoever SignIn::using() says it is (by default the user Laravel's guard
 * authenticated: its id; nobody if none), so every transaction it begins signs in as them. Put it before the
 * middleware that reads rows (route model binding):
 *
 *     $middleware->api(prepend: [\Rowstile\Laravel\SignIn::class]);   // bootstrap/app.php
 */
final class SignIn
{
    /** @var ?Closure(Request): (Principal|int|string|null) */
    private static ?Closure $user = null;

    /**
     * Who each request acts for: a user's id, a Principal (Principal::of('service', 3)), or null for nobody. Read the
     * session or the token there.
     *
     * @param ?Closure(Request): (Principal|int|string|null) $user null: back to the authenticated user
     */
    public static function using(?Closure $user): void
    {
        self::$user = $user;
    }

    /** Who the request acts for. */
    public static function who(Request $request): Principal
    {
        if (self::$user !== null) {
            return Principal::from((self::$user)($request));
        }
        return Principal::from(Auth::id());
    }

    /** @param Closure(Request): Response $next */
    public function handle(Request $request, Closure $next): Response
    {
        return Rowstile::actingAs(self::who($request), static fn (): Response => $next($request));
    }
}
