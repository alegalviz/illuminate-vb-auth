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
        $this->app->singleton('Rixot\Illuminate\VBAuth\VBAuth', function ($app) {
            return new VBAuth(config('vbauth'));
        });
    }

    /**
     * Bootstrap the application events.
     *
     * @return void
     */
    public function boot()
    {
        $dir = __DIR__.'/../';

        // Make config publishable if the application has a config path
        if (file_exists($this->app->basePath('config'))) {
            $this->publishes([
                "{$dir}config/vbauth.php" => $this->app->basePath('config') . '/vbauth.php'
            ], 'config');
        }

        $this->mergeConfigFrom("{$dir}config/vbauth.php", 'vbauth');
    }
}
