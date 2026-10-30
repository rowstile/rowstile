<?php

declare(strict_types=1);

use App\Http\Controllers\FoldersController;
use App\Http\Controllers\InboxController;
use App\Http\Controllers\KeysController;
use App\Http\Controllers\NotesController;
use App\Http\Controllers\ProjectsController;
use Illuminate\Support\Facades\Route;

Route::get('projects', [ProjectsController::class, 'index']);
Route::get('projects/editable', [ProjectsController::class, 'editable']);
Route::get('projects/buttons', [ProjectsController::class, 'buttons']);
Route::get('projects/page', [ProjectsController::class, 'page']);
Route::get('projects/{id}/shares', [ProjectsController::class, 'shares']);
Route::post('projects/{id}/requests', [ProjectsController::class, 'ask']);
Route::post('keys', [KeysController::class, 'create']);
Route::delete('keys/{id}', [KeysController::class, 'destroy']);
Route::get('notes', [NotesController::class, 'index']);
Route::get('notes/as/{userId}', [NotesController::class, 'as']);
Route::post('notes', [NotesController::class, 'create']);
Route::patch('notes/{note}', [NotesController::class, 'update']);
Route::delete('notes/{id}', [NotesController::class, 'destroy']);
Route::post('notes/digest', [NotesController::class, 'digest']);
Route::post('inbox', [InboxController::class, 'create']);
Route::post('inbox/quietly', [InboxController::class, 'quietly']);
Route::patch('folders/{folder}', [FoldersController::class, 'update']);
