<?php

use App\Http\Controllers\AuthController;
use App\Http\Controllers\ArticleController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

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
        Route::middleware('auth:sanctum')->get('/me', 'me')->name('auth.me');
    });
});

Route::controller(ArticleController::class)->group(function(){
    Route::prefix('articles')->group(function () {
        Route::get('/', 'index')->name('articles.index');
        Route::get('/{article}', 'show')->name('articles.show');
        Route::middleware('auth:sanctum')->post('/', 'store')->name('articles.store');
        Route::middleware('auth:sanctum')->put('/{article}', 'update')->name('articles.update'); // 이름 수정
        Route::middleware('auth:sanctum')->delete('/{article}', 'destroy')->name('articles.destroy');
    });
});
