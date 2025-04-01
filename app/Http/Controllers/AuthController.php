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

    public function register(RegisterUserRequest $request)
    {
        //자동으로 검증하는 방법
        $validatedData = $request->validated();

        $user = User::create([
            'name'=> $validatedData['name'],
            'email'=> $validatedData['email'],
            'password'=> bcrypt($validatedData['password']),
        ]);

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

        $user = User::where('email', $request->email)->first();

        // 기존 토큰 삭제
        $this->revokeTokens($user);

        // 새 토큰 생성
        $accessToken = $this->createAccessToken($user);
        $refreshToken = $this->createRefreshToken($user);

        $response = $this->successResponse([
            'access_token'=> $accessToken->plainTextToken,
            'token_type' => 'Bearer',
            'access_token_expires_in'=> config('sanctum.ac_expiration') * 60,
        ]);

        // Set the refresh token as an HttpOnly secure cookie
        $this->setRefreshTokenCookie($response, $refreshToken->plainTextToken);

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

        // 사용자의 refresh_token 존재 확인
        $user = $request->user();
        $refreshTokenExists = $user->tokens()
            ->where('name', 'refresh_token')
            ->where('abilities', 'like', '%' . TokenAbility::ISSUE_ACCESS_TOKEN->value . '%')
            ->exists();

        if (!$refreshTokenExists) {
            return $this->errorResponse('Invalid refresh token', 401);
        }

        // 기존 access token 삭제
        $user->tokens()->where('name', 'access_token')->delete();

        // 새 access token 생성
        $accessToken = $this->createAccessToken($user);

        return $this->successResponse([
            'access_token' => $accessToken->plainTextToken,
            'access_token_expires_in'=> config('sanctum.ac_expiration') * 60,
            'token_type' => 'Bearer',
        ]);
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
        return $this->successResponse($request->user());
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
        $this->revokeTokens($request->user());

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
        $user->tokens()->where('name', 'refresh_token')->delete();
        $user->tokens()->where('name', 'access_token')->delete();
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
            'access_token',
            [TokenAbility::ACCESS_API->value],
            Carbon::now()->addMinutes(config('sanctum.ac_expiration'))
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
            Carbon::now()->addMinutes(config('sanctum.rt_expiration'))
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
            config('sanctum.rt_expiration'),
            null,
            null,
            true,
            true
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
}
