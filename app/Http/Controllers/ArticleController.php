<?php

namespace App\Http\Controllers;

use App\Http\Requests\StoreArticleRequest;
use App\Models\Article;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class ArticleController extends Controller
{
    public function index(){
        $articles = Article::with('user')
        ->latest()
        ->paginate();

        return response()->json([
            'message' => 'Successfully created article!',
            'article' => $articles
        ], 200);
    }

    public function store(StoreArticleRequest $request){
        $validatedData = $request->validated();

        $article = Article::create( [
            'title' => $validatedData['title'],
            'content' => $validatedData['content'],
            'user_id' => Auth::user()->id
        ]);

        return response()->json([
            'message' => 'Successfully created article!',
            'article' => $article
        ], 200);
    }

    public function show($id){
        $article = Article::findOrFail($id);
        return response()->json([
            'message' => 'Successfully created article!',
            'article' => $article
        ], 200);
    }
    public function update(StoreArticleRequest $request, $id){
        $validatedData = $request->validated();

        $article = Article::findOrFail($id);
        $article->title = $validatedData['title'];
        $article->content = $validatedData['content'];
        $article->save();

        return response()->json([
            'message' => 'Successfully updated article!',
            'article' => $article
        ], 200);
    }

    public function destroy($id){
        $article = Article::findOrFail($id);
        $article->delete();

        return response()->json([
            'message' => 'Successfully deleted article!',
        ], 200);
    }
}
