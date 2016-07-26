<?php

namespace AboutBlank\JWTGuard\Auth;

use Illuminate\Auth\GuardHelpers;
use Illuminate\Http\Request;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use AboutBlank\JWTGuard\JWT\Token\RefreshJWT;
use AboutBlank\JWTGuard\JWT\Token\UserJWT;
use AboutBlank\JWTGuard\Support\Facades\Serializer;
use AboutBlank\JWTGuard\JWT\JWTManager;

class UserJWTGuard implements Guard, JWTGuardInterface
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
        if ($this->token() instanceof UserJWT && $this->validateToken() === true) {
            $decodedJwt = $this->token()->get();
            return Serializer::encryptedUnserialize($decodedJwt->euo);
        }

        return null;
    }

    public function refreshToken()
    {
        if ($this->token() instanceof RefreshJWT && $this->validateToken() === true) {
            $decodedJwt = $this->token()->get();
            return Serializer::encryptedUnserialize($decodedJwt->euo);
        }

        return null;
    }

    public function blacklistToken()
    {
        if (($this->token() instanceof UserJWT || $this->token() instanceof RefreshJWT) && $this->validateToken() === true) {
            $this->token()->blacklist();
            return response()->json('Token is blacklisted.');
        }

        return response()->json('Unauthorized.', 401);
    }
}
