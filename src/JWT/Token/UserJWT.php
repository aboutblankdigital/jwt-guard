<?php

namespace AboutBlankDigital\JWTGuard\JWT\Token;


use Carbon\Carbon;
use Illuminate\Support\Facades\Cache;

class UserJWT implements TokenInterface
{
    use TokenTrait;

    public function __construct($data, $key, $duration = null)
    {
        if (is_array($data)) {
            $this->encode($data, $key, $duration);
        } else {
            $this->validate($data, $key);
        }
    }

    public function euo()
    {
        return $this->getClaim('euo');
    }

    public function rti()
    {
        return $this->getClaim('rti');
    }

    public function blacklist()
    {
        if (!$this->isBlacklisted()) {
            $expiresAt = Carbon::createFromTimestamp($this->get()->exp);
            Cache::put($this->jti(), $this->jti(), $expiresAt);

            if (isset($this->get()->rti)) {
                $refreshTokenExpiresAt = Carbon::createFromTimestamp($this->get()->iat + $this->get()->rtd);
                Cache::put($this->rti(), $this->rti(), $refreshTokenExpiresAt);
            }

            $this->status = self::BLACKLISTED_TOKEN;
        }
    }
}
