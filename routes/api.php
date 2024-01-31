<?php

use App\Http\Controllers\AuthController;
use App\Http\Controllers\ArticleController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Enums\TokenAbility;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

Route::controller(AuthController::class)->group(function(){
    Route::prefix('auth')->group(function () {
        Route::post('/register', 'register')->name('auth.register');
        Route::post('/login', 'login')->name('auth.login');
        Route::middleware(['auth:sanctum', 'ability:'.TokenAbility::ACCESS_API->value])->get('/me', 'me')->name('auth.me');
        Route::middleware(['auth:sanctum', 'ability:'.TokenAbility::ACCESS_API->value])->post('/logout', 'logout')->name('auth.logout');
        Route::middleware(['auth:sanctum', 'ability:'.TokenAbility::ACCESS_API->value])->post('/refresh-token', 'refreshToken')->name('auth.refreshToken');
    });
});

// Route::controller(ArticleController::class)->group(function(){
//     Route::prefix('articles')->group(function () {
//         Route::get('/', 'index')->name('articles.index');
//         Route::get('/{articleId}', 'show')->name('articles.show');
//         Route::middleware('auth:sanctum')->post('/', 'store')->name('articles.store');
//         Route::middleware('auth:sanctum')->put('/{articleId}', 'update')->name('articles.update'); // 이름 수정
//         Route::middleware('auth:sanctum')->delete('/{articleId}', 'destroy')->name('articles.destroy');
//     });
// });

Route::resource('articles', ArticleController::class)->middleware(['auth:sanctum', 'ability:'.TokenAbility::ACCESS_API->value])->except(['create', 'edit']);
