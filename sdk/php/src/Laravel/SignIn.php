<?php

declare(strict_types=1);

namespace Rowstile\Laravel;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use LogicException;
use Rowstile\Principal;
use Rowstile\Rowstile;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\StreamedResponse;
use Throwable;

/**
 * Route middleware: each request acts for whoever SignIn::using() says it is (by default the user Laravel's guard
 * authenticated: its id; nobody if none), so every transaction it begins signs in as them, and so does a streamed
 * response's, whose body is written after the request returns. Put it before the middleware that reads rows (route
 * model binding):
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

    /**
     * Who the request acts for. It is found before the request acts for anyone: what it reads (Laravel's guard reads
     * the users table, Sanctum its tokens too) can't be a table with rules, which needs someone signed in (AZ701). A
     * LogicException says so.
     */
    public static function who(Request $request): Principal
    {
        try {
            return Principal::from(self::$user !== null ? (self::$user)($request) : Auth::id());
        } catch (Throwable $e) {
            if (!Rowstile::notSignedIn($e)) {
                throw $e;
            }
            throw new LogicException('finding who the request acts for read a table with rules, before the request acts '
                ."for anyone, so nobody was signed in: the tables Laravel's guard reads (the users, Sanctum's tokens) can't "
                .'have rules, or SignIn::using() must find the id without them (in the session, the token)', 0, $e);
        }
    }

    /** @param Closure(Request): Response $next */
    public function handle(Request $request, Closure $next): Response
    {
        $who = self::who($request);
        $response = Rowstile::actingAs($who, static fn (): Response => $next($request));
        // a streamed body (response()->stream, streamDownload, StreamedJsonResponse) is written once this returned
        $stream = $response instanceof StreamedResponse ? $response->getCallback() : null;
        if ($response instanceof StreamedResponse && $stream !== null) {
            $response->setCallback(static fn (): mixed => Rowstile::actingAs($who, static fn (): mixed => $stream()));
        }
        return $response;
    }
}
