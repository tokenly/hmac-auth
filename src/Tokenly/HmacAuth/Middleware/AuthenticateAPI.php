<?php

namespace Tokenly\HmacAuth\Middleware;

use Closure;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Routing\Middleware;
use Illuminate\Http\JsonResponse;

class AuthenticateAPI implements Middleware {

    /**
     * The Guard implementation.
     *
     * @var Guard
     */
    protected $auth;

    /**
     * Create a new filter instance.
     *
     * @param  Guard  $auth
     * @return void
     */
    public function __construct(Guard $auth)
    {
        $this->auth           = $auth;

        $this->hmac_validator = new \Tokenly\HmacAuth\Validator(function($api_token) {
            $api_secret = null;
            if (app()->env == 'testing' AND $api_token == 'TESTAPITOKEN') {
                $api_secret = 'TESTAPISECRET';
            } else {
                // lookup the API secrect by $api_token using $this->auth
            }

            return $api_secret;
        });
    }

    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        $authenticated = $this->hmac_validator->validateFromRequest($request);

        if (!$authenticated) {
            $response = new JsonResponse([
                'message' => 'Authorization denied.',
                'errors' => ["Authorization denied"],
            ], 403);
            return $response;
        }

        return $next($request);
    }

}
