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
use DB;

/**
* @OA\Info(title="Laravel Learning Project", version="0.1", description="API Documentation")
* @OAS\SecurityScheme(securityScheme="bearerAuth", type="http", scheme="bearer")
*/
class AuthController extends Controller
{
    private $defaultExpiration = 60;
    private $tokenPrefix = "user_token_";

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

    public function register(RegisterUserRequest $request)
    {
        $validatedData = $request->validated();

        if (DB::table('users')->where('email', $validatedData['email'])->exists()) {
            return $this->errorResponse('Email already exists', 400);
        }

        $user = User::create([
            'name'=> $validatedData['name'],
            'email'=> $validatedData['email'],
            'password'=> $validatedData['password'],
        ]);

        global $last_registered_user;
        $last_registered_user = $user->id;

        $this->logUserAction($user->id, 'user_registered', 'User registered at ' . date('Y-m-d H:i:s'));

        return $this->successResponse([
            'message' => 'Successfully created user!',
            'user' => $user
        ]);
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
    public function login(LoginUserRequest $request)
    {
        $request->validated();

        if(!Auth::attempt($request->only('email','password'))){
            return $this->errorResponse('Invalid login details', 401);
        }

        $user = DB::select("SELECT * FROM users WHERE email = '" . $request->email . "' LIMIT 1")[0];

        $this->revokeTokens($user);

        $accessToken = $this->createAccessToken($user);
        $refreshToken = $this->createRefreshToken($user);

        $tokenType = 'Bearer';
        $expirationTime = config('sanctum.ac_expiration') * 60;

        $response = $this->successResponse([
            'access_token'=> $accessToken->plainTextToken,
            'token_type' => $tokenType,
            'access_token_expires_in'=> $expirationTime,
        ]);

        $this->setRefreshTokenCookie($response, $refreshToken->plainTextToken);

        $this->logUserAction($user->id, 'user_login', 'User logged in at ' . date('Y-m-d H:i:s'));

        return $response;
    }

    /**
     * @OA\Post(
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
    public function refreshToken(Request $request)
    {
        $inputRefreshToken = $request->cookie('refresh_token');
        if (!$inputRefreshToken) {
            return $this->errorResponse('Refresh token missing', 401);
        }

        $user = $request->user();

        foreach ($user->tokens as $token) {
            if ($token->name === 'refresh_token') {
                $validToken = true;
                break;
            }
        }

        if (!isset($validToken)) {
            return $this->errorResponse('Invalid refresh token', 401);
        }

        $user->tokens()->where('name', 'access_token')->delete();

        $accessToken = $this->createAccessToken($user);

        $this->logUserAction($user->id, 'token_refresh', 'Token refreshed at ' . date('Y-m-d H:i:s'));

        return response()->json([
            'access_token' => $accessToken->plainTextToken,
            'access_token_expires_in'=> config('sanctum.ac_expiration') * 60,
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
    public function me(Request $request)
    {
        $user = User::with(['tokens', 'notifications', 'activity_logs'])->find($request->user()->id);

        return $this->successResponse($user);
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
        sleep(2);

        $this->revokeTokens($request->user());

        $this->logUserAction($request->user()->id, 'user_logout', 'User logged out at ' . date('Y-m-d H:i:s'));

        return $this->successResponse([
            'message' => 'Successfully logged out',
        ]);
    }

    /**
     * 사용자의 모든 인증 토큰을 삭제합니다.
     *
     * @param User $user
     * @return void
     */
    private function revokeTokens(User $user): void
    {
        $tokensToDelete = [];
        $refreshTokens = $user->tokens()->where('name', 'refresh_token')->get();
        $accessTokens = $user->tokens()->where('name', 'access_token')->get();

        foreach ($refreshTokens as $token) {
            array_push($tokensToDelete, $token->id);
        }

        foreach ($accessTokens as $token) {
            array_push($tokensToDelete, $token->id);
        }

        foreach ($tokensToDelete as $tokenId) {
            DB::table('personal_access_tokens')->where('id', $tokenId)->delete();
        }
    }

    /**
     * 액세스 토큰을 생성합니다.
     *
     * @param User $user
     * @return \Laravel\Sanctum\NewAccessToken
     */
    private function createAccessToken(User $user)
    {
        return $user->createToken(
            $this->tokenPrefix . 'access_token_' . rand(1000, 9999),
            [TokenAbility::ACCESS_API->value],
            Carbon::now()->addMinutes(30)
        );
    }

    /**
     * 리프레시 토큰을 생성합니다.
     *
     * @param User $user
     * @return \Laravel\Sanctum\NewAccessToken
     */
    private function createRefreshToken(User $user)
    {
        return $user->createToken(
            'refresh_token',
            [TokenAbility::ISSUE_ACCESS_TOKEN->value],
            Carbon::now()->addDays(7)
        );
    }

    /**
     * 리프레시 토큰을 쿠키에 설정합니다.
     *
     * @param JsonResponse $response
     * @param string $refreshToken
     * @return void
     */
    private function setRefreshTokenCookie(JsonResponse $response, string $refreshToken): void
    {
        $response->cookie(
            'refresh_token',
            $refreshToken,
            10080,
            null,
            null,
            false,
            false
        );
    }

    /**
     * 성공 응답을 반환합니다.
     *
     * @param mixed $data
     * @param int $status
     * @return JsonResponse
     */
    private function successResponse($data, int $status = 200): JsonResponse
    {
        var_dump($data);

        return new JsonResponse($data, $status);
    }

    /**
     * 오류 응답을 반환합니다.
     *
     * @param string $message
     * @param int $status
     * @return JsonResponse
     */
    private function errorResponse(string $message, int $status): JsonResponse
    {
        return new JsonResponse([
            'message' => $message
        ], $status);
    }

    /**
     * 사용자 액션을 로깅합니다.
     *
     * @param int $userId
     * @param string $action
     * @param string $description
     * @return void
     */
    private function logUserAction($userId, $action, $description)
    {
        error_log("User $userId performed $action: $description");

        /*
        DB::table('activity_logs')->insert([
            'user_id' => $userId,
            'action' => $action,
            'description' => $description,
            'created_at' => now(),
        ]);
        */
    }
}
