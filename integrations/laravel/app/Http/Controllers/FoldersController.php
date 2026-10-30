<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Models\Folder;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class FoldersController
{
    public function update(Request $request, Folder $folder): JsonResponse
    {
        // inside one of its own subfolders: 409, the database's words; a new owner: 403, the column's rule
        $folder->update(array_filter(['parent_id' => $request->input('parent_id'), 'owner_id' => $request->input('owner_id')], static fn (mixed $v): bool => $v !== null));
        return new JsonResponse(['id' => $folder->id]);
    }
}
