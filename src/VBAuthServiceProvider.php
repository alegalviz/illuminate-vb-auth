<?php

namespace Rixot\Illuminate\VBAuth;

use Illuminate\Support\ServiceProvider;

class VBAuthServiceProvider extends ServiceProvider
{
    /**
     * Register bindings in the container.
     *
     * @return void
     */
    public function register()
    {
        $this->app->singleton('Rixot\Lumen\VBAuth\VBAuth', function ($app) {
            return new VBAuth(config('vbauth'));
        });
    }

    /**
     * Bootstrap the application events.
     *
     * @param  Router  $router
     * @return void
     */
    public function boot(Router $router)
    {
        $dir = __DIR__.'/../';

        $this->publishes([
            "{$dir}config/vbauth.php" => config_path('vbauth.php')
        ], 'config');

        $this->mergeConfigFrom("{$dir}config/vbauth.php", 'vbauth');
    }
}
