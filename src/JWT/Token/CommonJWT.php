<?php

namespace AboutBlank\JWTGuard\JWT\Token;


use Carbon\Carbon;
use Illuminate\Support\Facades\Cache;

class CommonJWT implements TokenInterface
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

    public function blacklist()
    {
        if (!$this->isBlacklisted()) {
            $expiresAt = Carbon::createFromTimestamp($this->get()->exp);
            Cache::put($this->jti(), $this->jti(), $expiresAt);
            $this->status = self::BLACKLISTED_TOKEN;
        }
    }
}
