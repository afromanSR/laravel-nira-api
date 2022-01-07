<?php

namespace AfromanSR\LaravelNiraApi;

class ServiceProvider extends \Illuminate\Support\ServiceProvider
{
    public function boot()
    {
        if ($this->app->runningInConsole()) {
            $this->registerPublishing();
        }
    }

    public function register()
    {
        $this->mergeConfigFrom(
            __DIR__.'/../config/nira.php','nira'
        );
    }

    protected function registerPublishing()
    {
        $this->publishes([
            __DIR__.'/../config/nira.php' => config_path('nira.php')
        ], 'nira-config');
    }
}