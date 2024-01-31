<?php

namespace App\Http\Controllers;

use App\Http\Requests\LoginUserRequest;
use App\Http\Requests\RegisterUserRequest;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Auth;
use App\Enums\TokenAbility;

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

        $accessToken = $user->createToken('access_token', [TokenAbility::ACCESS_API->value], Carbon::now()->addMinutes(config('sanctum.ac_expiration')));
        $refreshToken = $user->createToken('refresh_token', [TokenAbility::ISSUE_ACCESS_TOKEN->value], Carbon::now()->addMinutes(config('sanctum.rt_expiration')));

        $response = new JsonResponse([
            'message' => 'Successfully created user!',
            'access_token'=> $accessToken->plainTextToken,
            'token_type' => 'Bearer',
            'user' => $user
        ], 200);

        // Set the refresh token as an HttpOnly secure cookie
        $response->cookie(
            'refresh_token',
            $refreshToken->plainTextToken,
            config('sanctum.rt_expiration'), // expiry time in minutes
            null,
            null,
            true, // secure
            true // httpOnly
        );

        return $response;
    }

    /**
     *  @OA\Post(path="/api/auth/login", summary="사용자 인증", tags={"인증"},
     *     @OA\RequestBody(required=true,
     *         @OA\JsonContent(required={"email", "password"},
     *             @OA\Property(property="email", type="string", format="email", example="djcho@jiran.com"),
     *             @OA\Property(property="password", type="string", format="password", example="secret123"),
     *         ),
     *     ),
     *     @OA\Response(response=200, description="로그인 성공 시",
     *         @OA\JsonContent(
     *             @OA\Property(property="access_token", type="string", example="api_access_token"),
     *             @OA\Property(property="refresh_token", type="string", example="refresh_token"),
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

        $refreshToken = $request->user()->tokens()->where('name', 'refresh_token')->first();
        if ($refreshToken) {
            $refreshToken->delete();
        }
        $refreshToken = $request->user()->tokens()->where('name', 'access_token')->first();
        if ($refreshToken) {
            $refreshToken->delete();
        }

        $user = User::where('email', $request->email)->first();

        $accessToken = $user->createToken('access_token', [TokenAbility::ACCESS_API->value], Carbon::now()->addMinutes(config('sanctum.ac_expiration')));
        $refreshToken = $user->createToken('refresh_token', [TokenAbility::ISSUE_ACCESS_TOKEN->value], Carbon::now()->addMinutes(config('sanctum.rt_expiration')));

        $response = new JsonResponse([
            'access_token'=> $accessToken->plainTextToken,
            'token_type' => 'Bearer',
        ], 200);

        // Set the refresh token as an HttpOnly secure cookie
        $response->cookie(
            'refresh_token',
            $refreshToken->plainTextToken,
            config('sanctum.rt_expiration'), // expiry time in minutes
            null,
            null,
            true, // secure
            true // HttpOnly
        );

        return $response;
    }

    /**
     * @OA\Get(
     *     path="/api/auth/refresh-token", summary="액세스 토큰 갱신", tags={"인증"},
     *     security={{ "sanctum": {} }},
     *     @OA\Response(
     *         response=200,
     *         description="Access token refreshed successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="access_token", type="string"),
     *         ),
     *     ),
     * )
     */
    public function refreshToken(Request $request){
        $inputRefreshToken = $request->cookie('refresh_token');

        if (!$inputRefreshToken) {
            return new JsonResponse([
                'input' => $inputRefreshToken,
                'message' => 'Invalid refresh token',
            ], 401);
        }

        //토큰 검증
        $refreshToken = $request->user()->tokens()->where('name', 'refresh_token')->first();
        if ($inputRefreshToken === $refreshToken) {
            return new JsonResponse([
                'input' => $inputRefreshToken,
                'message' => 'Invalid refresh token',
            ], 401);
        }

        $refreshToken = $request->user()->tokens()->where('name', 'access_token')->first();
        if ($refreshToken) {
            $refreshToken->delete();
        }

        $accessToken = $request->user()->createToken('access_token', [TokenAbility::ACCESS_API->value], Carbon::now()->addMinutes(config('sanctum.ac_expiration')));
        return new JsonResponse([
            'access_token' => $accessToken->plainTextToken,
            'token_type' => 'Bearer',
        ], 200);
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
        $refreshToken = $request->user()->tokens()->where('name', 'refresh_token')->first();
        if ($refreshToken) {
            $refreshToken->delete();
        }
        $refreshToken = $request->user()->tokens()->where('name', 'access_token')->first();
        if ($refreshToken) {
            $refreshToken->delete();
        }

        return response()->json([
            'message' => 'Successfully logged out',
        ], 200);
    }
}
