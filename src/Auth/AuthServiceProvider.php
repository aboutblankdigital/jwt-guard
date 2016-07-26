<?php

namespace AboutBlankDigital\JWTGuard\Auth;

use Illuminate\Foundation\Support\Providers\AuthServiceProvider as ServiceProvider;
use AboutBlankDigital\JWTGuard\JWT\JWTManager;
use AboutBlankDigital\JWTGuard\Support\Serializer;

class AuthServiceProvider extends ServiceProvider
{
    /**
     * Register any application authentication / authorization services.
     *
     * @return void
     */
    public function boot()
    {
        $this->publishes([__DIR__.'/../../config/jwt.php' => config_path('jwt.php')]);

        $this->app['auth']->extend('user-jwt', function($app, $name, array $config) {
            return new UserJWTGuard(
                $app['auth']->createUserProvider($config['provider']),
                $app['request'],
                new JWTManager(
                    config('jwt.secret_key'),
                    config('jwt.jwt_token_duration'),
                    config('jwt.enable_refresh_token'),
                    config('jwt.refresh_token_duration'),
                    config('jwt.enable_token_reissue')
                )
            );
        });

        $this->app['auth']->extend('jwt', function($app, $name, array $config) {
            return new JWTGuard(
                $app['auth']->createUserProvider($config['provider']),
                $app['request'],
                new JWTManager(
                    config('jwt.secret_key'),
                    config('jwt.jwt_token_duration'),
                    config('jwt.enable_refresh_token'),
                    config('jwt.refresh_token_duration'),
                    config('jwt.enable_token_reissue')
                )
            );
        });

        $this->app->bind('jwt-auth-manager', function()
        {
            return new JWTManager(config('jwt.secret_key'));
        });

        $this->app->bind('jwt-auth-serializer', function()
        {
            return new Serializer(config('jwt.secret_key'));
        });
    }

    /**
     * Register bindings in the container.
     *
     * @return void
     */
    public function register()
    {
        //
    }
}
