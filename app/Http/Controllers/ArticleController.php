<?php

namespace App\Http\Controllers;

use App\Http\Requests\StoreArticleRequest;
use App\Models\Article;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;


class ArticleController extends Controller
{
    /**
     * @OA\Get(path="/api/articles", summary="모든 게시글을 조회", tags={"게시글"}, security={{"sanctum": {}}},
     *     @OA\Response(response=200, description="Succeed",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Successfully retrieved articles"),
     *             @OA\Property(property="article", type="object")),
     *         ),
     *     ),
     * )
     */
    public function index(){
        $articles = Article::with('user')
        ->latest()
        ->paginate();

        return response()->json([
            'message' => 'Successfully created article!',
            'article' => $articles
        ], 200);
    }

    /**
     * @OA\Post(path="/api/articles", summary="새 게시글 추가", tags={"게시글"}, security={{"sanctum": {}}},
     *     @OA\RequestBody(required=true,
     *         @OA\JsonContent(required={"title", "content"},
     *             @OA\Property(property="title", type="string", example="Article title"),
     *             @OA\Property(property="content", type="string", example="Article content"),
     *         ),
     *     ),
     *     @OA\Response(response=200, description="Succeed",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Successfully created article"),
     *             @OA\Property(property="article", type="object"),
     *         ),
     *     ),
     *     @OA\Response(response=401, description="Unauthenticated"),
     * )
     */
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

    /**
     * @OA\Get(path="/api/articles/{articleId}", summary="단일 게시글 조회", tags={"게시글"}, security={{"sanctum": {}}},
     *     @OA\Parameter( name="articleId", in="path",required=true, description="게시글 ID",
     *         @OA\Schema(type="integer", format="int64")),
     *     @OA\Response(response=200, description="Succeed",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Successfully retrieved article"),
     *             @OA\Property(property="article", type="object"),
     *         ),
     *     ),
     *     @OA\Response(response=404, description="Article not found"),
     * )
     */
    public function show($articleId){
        $article = Article::findOrFail($articleId);
        return response()->json([
            'message' => 'Successfully created article!',
            'article' => $article
        ], 200);
    }

    /**
     * @OA\Put(path="/api/articles/{articleId}", summary="게시글 수정",tags={"게시글"}, security={{"sanctum": {}}},
     *     @OA\Parameter(name="articleId", in="path", required=true, description="게시글 ID",
     *         @OA\Schema(type="integer", format="int64"),
     *     ),
     *     @OA\RequestBody(required=true,
     *         @OA\JsonContent(required={"title", "content"},
     *             @OA\Property(property="title", type="string", example="Article title"),
     *             @OA\Property(property="content", type="string", example="Article content"),
     *         ),
     *     ),
     *     @OA\Response(response=200, description="Succeed",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Successfully updated article"),
     *             @OA\Property(property="article", type="object"),
     *         ),
     *     ),
     *     @OA\Response(response=401, description="Unauthenticated"),
     *     @OA\Response(response=403, description="Forbidden",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="This action is unauthorized."),
     *         ),
     *     ),
     *     @OA\Response(response=404, description="Article not found"),
     * )
     */
    public function update(StoreArticleRequest $request, $articleId){
        $validatedData = $request->validated();

        $article = Article::findOrFail($articleId);
        if(!Auth::user()->can('update', $article)){
            return response()->json([
                'message' => 'This action is unauthorized.'
            ], 403);
        }

        $article->title = $validatedData['title'];
        $article->content = $validatedData['content'];
        $article->save();

        return response()->json([
            'message' => 'Successfully updated article!',
            'article' => $article
        ], 200);
    }

    /**
     * @OA\Delete(path="/api/articles/{articleId}", summary="게시글 삭제", tags={"게시글"}, security={{"sanctum": {}}},
     *     @OA\Parameter(name="articleId", in="path", required=true, description="게시글 ID",
     *         @OA\Schema(type="integer", format="int64"),
     *     ),
     *     @OA\Response(response=200, description="Succeed",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Successfully deleted article"),
     *         ),
     *     ),
     *     @OA\Response(response=401, description="Unauthenticated"),
     *     @OA\Response(response=403, description="Forbidden",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="This action is unauthorized."),
     *         ),
     *     ),
     *     @OA\Response(response=404, description="Article not found"),
     * )
     */
    public function destroy($articleId){
        $article = Article::findOrFail($articleId);
        if(!Auth::user()->can('delete', $article)){
            return response()->json([
                'message' => 'This action is unauthorized.'
            ], 403);
        }

        $article->delete();

        return response()->json([
            'message' => 'Successfully deleted article!',
        ], 200);
    }
}
