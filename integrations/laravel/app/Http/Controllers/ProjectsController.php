<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Models\Project;
use Authz\ProjectPermission;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Rowstile\Laravel\Database;

final class ProjectsController
{
    public function index(): JsonResponse
    {
        return new JsonResponse(Project::query()->orderBy('id')->pluck('id'));
    }

    // the projects the user may edit: one set lookup, taking only the policy's names (Authz, the generated names)
    public function editable(): JsonResponse
    {
        return new JsonResponse(Project::permitted(ProjectPermission::Edit)->orderBy('id')->pluck('id'));
    }

    // a list's buttons, in one call
    public function buttons(): JsonResponse
    {
        /** @var list<int> $ids */
        $ids = Project::query()->orderBy('id')->pluck('id')->all();
        return new JsonResponse(Database::queries()->permsOf(ProjectPermission::class, $ids));
    }

    // the projects the user may see, a page at a time: the database says when the size or the cursor is wrong
    public function page(Request $request): JsonResponse
    {
        $after = $request->query('after');
        return new JsonResponse(Database::queries()->list(ProjectPermission::View, is_string($after) ? $after : null, $request->integer('limit')));
    }

    public function shares(string $id): JsonResponse
    {
        return new JsonResponse(array_column(DB::select('SELECT subject_id FROM authz.list_shares(?, ?)', ['project', $id]), 'subject_id'));
    }

    // access asked for: the policy shares no relation of a project, so this is the app's mistake (a 500), once the
    // database knows who asks
    public function ask(Request $request, string $id): JsonResponse
    {
        $asked = DB::scalar('SELECT authz.request_access(?, ?, ?, ?)', [
            'project', $id, $request->string('relation')->toString(), $request->string('reason')->toString(),
        ]);
        return new JsonResponse(['id' => $asked], 201);
    }
}
