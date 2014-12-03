<?php

namespace Tokenly\HmacAuth\ServiceProvider;


use Exception;
use Illuminate\Support\ServiceProvider;

/*
* HmacAuthServiceProvider
*/
class HmacAuthServiceProvider extends ServiceProvider
{

    public function boot()
    {
        $this->package('tokenly/hmac-auth', 'hmac-auth', __DIR__.'/../../');
    }

    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {
        // add the route middleware
        $this->app['router']->middleware('hmacauth', 'Tokenly\HmacAuth\Middleware\AuthenticateAPI');
    }

}

