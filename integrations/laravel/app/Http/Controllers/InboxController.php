<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Models\Message;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Rowstile\Rowstile;

final class InboxController
{
    // reads the new row back (INSERT ... RETURNING id): only the recipient may read it
    public function create(Request $request): JsonResponse
    {
        $message = Message::query()->create($this->message($request));
        return new JsonResponse(['id' => $message->id], 201);
    }

    // without reading the row back
    public function quietly(Request $request): JsonResponse
    {
        Message::query()->insert($this->message($request));
        return new JsonResponse([], 202);
    }

    /** @return array{sender_id: int, recipient_id: int, body: string} */
    private function message(Request $request): array
    {
        return [
            'sender_id' => (int) Rowstile::current()?->id,
            'recipient_id' => $request->integer('recipient_id'),
            'body' => $request->string('body')->toString(),
        ];
    }
}
