<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Jobs\DigestJob;
use App\Jobs\ExportJob;
use App\Models\Note;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\DB;
use Rowstile\Principal;
use Rowstile\Rowstile;
use Symfony\Component\HttpFoundation\StreamedResponse;

final class NotesController
{
    public function index(): JsonResponse
    {
        return new JsonResponse(Note::query()->orderBy('id')->pluck('id'));
    }

    // the notes' ids, streamed: the body is written after the request returns, still as its user (SignIn)
    public function export(): StreamedResponse
    {
        return new StreamedResponse(static function (): void {
            foreach (Note::query()->orderBy('id')->lazy() as $note) {
                echo $note->id, "\n";
            }
        }, 200, ['Content-Type' => 'text/csv']);
    }

    public function create(Request $request): JsonResponse
    {
        $note = Note::query()->create([
            'project_id' => $request->integer('project_id'),
            'author_id' => (int) Rowstile::current()?->id,
            'body' => $request->string('body')->toString(),
        ]);
        return new JsonResponse(['id' => $note->id], 201);
    }

    public function update(Request $request, Note $note): JsonResponse
    {
        // a row the user can't see: 404 (route model binding); an update the rules refuse: 403, with the reason
        $note->update(['body' => $request->string('body')->toString()]);
        return new JsonResponse(['id' => $note->id]);
    }

    public function destroy(int $id): Response
    {
        Note::query()->findOrFail($id)->delete();
        return new Response('', 204);
    }

    // who is signed in, changed by hand: the database doesn't believe it (the app's bug, a 500)
    public function as(string $userId): JsonResponse
    {
        $ids = DB::transaction(function () use ($userId) {
            DB::select("SELECT set_config('authz.user_id', ?, true)", [$userId]);
            return Note::query()->orderBy('id')->pluck('id');
        });
        return new JsonResponse($ids);
    }

    // jobs, queued by the request: one acts for its service, whoever asked; the other for the user who asked
    public function digest(): JsonResponse
    {
        DigestJob::dispatch();
        ExportJob::dispatch(Rowstile::current() ?? Principal::nobody());
        return new JsonResponse([], 202);
    }
}
