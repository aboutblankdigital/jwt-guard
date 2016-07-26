<?php

namespace AboutBlank\JWTGuard\JWT;

use Carbon\Carbon;
use Exception;
use Firebase\JWT\JWT;
use Illuminate\Support\Facades\Cache;
use AboutBlank\JWTGuard\JWT\Token\CommonJWT;
use AboutBlank\JWTGuard\JWT\Token\ErrorToken;
use AboutBlank\JWTGuard\JWT\Token\RefreshJWT;
use AboutBlank\JWTGuard\JWT\Token\TokenInterface;
use AboutBlank\JWTGuard\JWT\Token\UserJWT;

class JWTManager
{
    private $key;

    public $jwtTokenDuration;

    public $enableRefreshToken;

    public $jwtRefreshTokenDuration;

    const API_TOKEN = UserJWT::class;
    const REFRESH_TOKEN = RefreshJWT::class;
    const COMMON_TOKEN = CommonJWT::class;

    /**
     * JWTManager constructor.
     * @param $key
     */
    public function __construct($key, $jwtTokenDuration, $enableRefreshToken, $jwtRefreshTokenDuration)
    {
        $this->key = $key;
        $this->jwtTokenDuration = $jwtTokenDuration  * 60;
        $this->enableRefreshToken = $enableRefreshToken;
        $this->jwtRefreshTokenDuration = $jwtRefreshTokenDuration * 86400;
    }

    public function issue(array $data = [])
    {
        $refreshTokenReferenceData = [];
        $apiTokenReferenceData = [];
        $refreshTokenJit = uniqid(str_random(random_int(3,33)), true);

        if ($this->enableRefreshToken) {
            $refreshTokenReferenceData["rti"] = $refreshTokenJit;
            $refreshTokenReferenceData["rtd"] = $this->jwtRefreshTokenDuration;
        }

        if (isset($data['euo'])) {
            $apiToken = new UserJWT(array_merge($data, $refreshTokenReferenceData), $this->key, $this->jwtTokenDuration);
            $apiTokenReferenceData = $data['euo'];
        } else {
            $apiToken = new CommonJWT($data, $this->key, $this->jwtTokenDuration);
            $apiTokenReferenceData = [
                'user_id' => $data['user']['id']
            ];
        }

        $tokens = [
            'api_token' => $apiToken->encoded()
        ];

        if ($this->enableRefreshToken) {

            $refreshTokenData = array(
                "jti"   => $refreshTokenJit,
                "nbf"   => $apiToken->exp(),
                "rtt"   => $apiToken->jti()
            );

            $refreshToken = new RefreshJWT(array_merge($refreshTokenData, $apiTokenReferenceData), $this->key, $this->jwtRefreshTokenDuration);

            $tokens = array_merge($tokens, [
                'refresh_token' => $refreshToken->encoded()
            ]);

        }

        return $tokens;
    }

    public function rebuild($rawToken)
    {
        try {
            $decodedToken = $this->decode($rawToken);
            if (isset($decodedToken->rti)) {
                return new UserJWT($rawToken, $this->key);
            } elseif (isset($decodedToken->rtt)) {
                return new RefreshJWT($rawToken, $this->key);
            } else {
                return new CommonJWT($rawToken, $this->key);
            }
        } catch (Exception $e) {
            $errorToken = new ErrorToken(null, null);
            $errorToken->setStatus(UserJWT::getErrorType($e));
            return $errorToken;
        }
    }

    public function decode($rawToken)
    {
        return JWT::decode($rawToken, $this->key, array('HS256'));
    }

    public function validateToken(TokenInterface $token)
    {
        return $token->status();
    }

    public function isBlacklisted($token)
    {
        $decodedToken = $this->decode($token);

        $cachedReference = Cache::tags(['jtw_token', 'blacklist'])->get($decodedToken->jti);

        return !is_null($cachedReference);
    }

    public function blacklist($token)
    {
        $decodedToken = $this->decode($token);
    }

}
