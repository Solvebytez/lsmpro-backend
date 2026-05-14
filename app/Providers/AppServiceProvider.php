<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        // php artisan serve + bind-mounted .env often keep DB_HOST=127.0.0.1 (host dev).
        // Inside a container MySQL is the compose service name, not loopback.
        if (is_file('/.dockerenv')) {
            config([
                'database.connections.mysql.url' => null,
                'database.connections.mysql.host' => 'mysql',
                'database.connections.mysql.port' => '3306',
            ]);
        }
    }
}
