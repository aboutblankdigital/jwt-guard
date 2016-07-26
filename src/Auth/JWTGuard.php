<?php

namespace AboutBlankDigital\JWTGuard\Auth;

use Illuminate\Auth\GuardHelpers;
use Illuminate\Http\Request;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use AboutBlankDigital\JWTGuard\JWT\Token\CommonJWT;
use AboutBlankDigital\JWTGuard\JWT\Token\RefreshJWT;
use AboutBlankDigital\JWTGuard\JWT\JWTManager;

class JWTGuard implements Guard, JWTGuardInterface
{
    use GuardHelpers, JWTGuardTrait;

    public function __construct(UserProvider $provider, Request $request, JWTManager $jwtManager)
    {
        $this->request = $request;
        $this->provider = $provider;
        $this->jwtManager = $jwtManager;
        $this->inputKey = 'api_token';
    }

    public function getUserFromToken()
    {
        if ($this->token() instanceof CommonJWT && $this->validateToken() === true) {
            return $this->provider->retrieveById($this->token()->get()->user->id);
        }

        return null;
    }

    public function refreshToken()
    {
        if ($this->token() instanceof RefreshJWT && $this->validateToken() === true) {
            $user = $this->provider->retrieveById($this->token()->get()->user->id);
            return $user;
            $this->token()->blacklist();
            return $this->issueToken($user);
        }

        return null;
    }

    public function blacklistToken()
    {
        if (($this->token() instanceof CommonJWT || $this->token() instanceof RefreshJWT) && $this->validateToken() === true) {
            $this->token()->blacklist();
            return response()->json('Token is blacklisted.');
        }

        return response()->json('Unauthorized.', 401);
    }

    public function reissueToken()
    {
        if (! $this->jwtManager->enableTokenReissue)
            return null;

        if ($this->token() instanceof CommonJWT && $this->validateToken() === true) {
            $user = $this->provider->retrieveById($this->token()->get()->user->id);
            $newToken = $this->issueToken($user);

            $this->token()->blacklist();

            return $newToken;
        }

        return null;
    }
}
