<?php

namespace App\Http\Controllers;

use App\Http\Requests\LoginUserRequest;
use App\Http\Requests\RegisterUserRequest;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

/**
* @OA\Info(title="Laravel Learning Project", version="0.1", description="API Documentation")
* @OAS\SecurityScheme(securityScheme="bearerAuth", type="http", scheme="bearer")
*/
class AuthController extends Controller
{
    /**
     * @OA\Post(path="/api/auth/register", summary="새 사용자 추가", tags={"인증"},
     *     @OA\RequestBody(required=true,
     *         @OA\JsonContent(required={"name", "email", "password"},
     *             @OA\Property(property="name", type="string", example="djcho"),
     *             @OA\Property(property="email", type="string", format="email", example="djcho@jiran.com"),
     *             @OA\Property(property="password", type="string", format="password", example="1234"),
     *         ),
     *     ),
     *     @OA\Response(response=200, description="Succeed",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Successfully created user!"),
     *             @OA\Property(property="access_token", type="string", example="your_access_token"),
     *             @OA\Property(property="token_type", type="string", example="Bearer"),
     *             @OA\Property(property="user", type="object"),
     *         ),
     *     ),
     * )
     */
    public function register(RegisterUserRequest $request){
        //자동으로 검증하는 방법
        $validatedData = $request->validated();

        $user = User::create([
            'name'=> $validatedData['name'],
            'email'=> $validatedData['email'],
            'password'=> bcrypt($validatedData['password']),
        ]);

        $token = $user->createToken('auth_token')->plainTextToken;
        return response()->json([
            'message' => 'Successfully created user!',
            'access_token'=> $token,
            'token_type' => 'Bearer',
            'user' => $user
        ], 200);

    }

    /**
     * @OA\Post(path="/api/auth/login", summary="사용자 인증", tags={"인증"},
     *     @OA\RequestBody(required=true,
     *         @OA\JsonContent(required={"email", "password"},
     *             @OA\Property(property="email", type="string", format="email", example="djcho@jiran.com"),
     *             @OA\Property(property="password", type="string", format="password", example="secret123"),
     *         ),
     *     ),
     *     @OA\Response(response=200, description="로그인 성공 시",
     *         @OA\JsonContent(
     *             @OA\Property(property="access_token", type="string", example="api_access_token"),
     *             @OA\Property(property="token_type", type="string", example="Bearer"),
     *         ),
     *     ),
     * )
     */
    public function login(LoginUserRequest $request){

        $request->validated();

        if(!Auth::attempt($request->only('email','password'))){
            return response()->json([
                'message' => 'Invalid login details'], 401);
        }

        $user = User::where('email', $request->email)->first();
        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
            'access_token' => $token,
            'token_type'=> 'Bearer']);
    }

    /**
     * @OA\Get(path="/api/auth/me", summary="현재 사용자 정보 조회", tags={"인증"}, security={{"sanctum": {}}},
     *     @OA\Response(response=200, description="로그인 성공 시",
     *         @OA\JsonContent(
     *             @OA\Property(property="user", type="object"),
     *         ),
     *     ),
     * )
     */
    public function me(Request $request){
        return $request->user();
    }

    /**
     * @OA\Post(path="/api/auth/logout", summary="사용자 로그아웃", tags={"인증"}, security={{"sanctum": {}}},
     *     @OA\Response(response=200, description="로그아웃 성공 시",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Successfully logged out"),
     *         ),
     *     ),
     *     @OA\Response(response=401, description="Unauthenticated",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Unauthenticated"),
     *         ),
     *     ),
     * )
     */
    public function logout(Request $request)
    {
        // 현재 사용자의 토큰을 폐기
        $request->user()->currentAccessToken()->delete();

        return response()->json([
            'message' => 'Successfully logged out',
        ], 200);
    }
}
