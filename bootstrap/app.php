<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;

// Increase memory limit for this application
ini_set('memory_limit', '1024M');

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware): void {
        // Enable Sanctum's stateful authentication for SPA
        $middleware->statefulApi();
        
        // Configure CORS
        $middleware->api(prepend: [
            \Illuminate\Http\Middleware\HandleCors::class,
        ]);
        
        // Use custom EncryptCookies middleware that excludes token cookies
        $middleware->encryptCookies(except: [
            'access_token',
            'refresh_token',
        ]);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        // Disable exception reporting to prevent memory issues from logging large exceptions
        $exceptions->dontReport([
            \Illuminate\Auth\AuthenticationException::class,
            \Illuminate\Auth\Access\AuthorizationException::class,
            \Symfony\Component\HttpKernel\Exception\HttpException::class,
        ]);
        
        // Always return JSON for API with error details
        $exceptions->shouldRenderJsonWhen(function ($request, $e) {
            return true;
        });
        
        // Custom exception renderer to provide more details
        $exceptions->render(function (\Throwable $e, $request) {
            if ($request->is('api/*')) {
                return response()->json([
                    'success' => false,
                    'message' => 'Server Error: ' . $e->getMessage(),
                    'error' => $e->getMessage(),
                    'file' => basename($e->getFile()),
                    'line' => $e->getLine(),
                ], 500);
            }
        });
    })->create();
