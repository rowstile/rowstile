<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\DB;

final class KeysController
{
    // an API key, for the user or a principal whose keys they manage; a request that brings a key (x-api-key) signs
    // in with it first, in the same transaction: the database says who may make which
    public function create(Request $request): JsonResponse
    {
        $key = DB::transaction(function () use ($request): mixed {
            $given = $request->header('x-api-key');
            if (is_string($given)) {
                DB::select('SELECT authz.login_key(?)', [$given]);
            }
            return DB::scalar("SELECT authz.create_api_key(?, '', NULL, CAST(? AS text), CAST(? AS text))", [
                $request->string('name')->toString(), $request->input('principal_type'), $request->input('principal_id'),
            ]);
        });
        return new JsonResponse(['key' => $key], 201);
    }

    // one of the user's API keys: someone else's, or one that isn't there, is 404
    public function destroy(int $id): Response
    {
        DB::select('SELECT 1 FROM authz.revoke_api_key(?)', [$id]);
        return new Response('', 204);
    }
}
