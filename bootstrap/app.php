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
        
        // JSON for API: keep real HTTP statuses (429 throttle, 401, 422, …); only unknown errors become 500.
        $exceptions->render(function (\Throwable $e, $request) {
            if (! $request->is('api/*')) {
                return null;
            }

            if ($e instanceof \Illuminate\Validation\ValidationException) {
                return response()->json([
                    'success' => false,
                    'message' => $e->getMessage(),
                    'errors' => $e->errors(),
                ], $e->status);
            }

            if ($e instanceof \Illuminate\Auth\AuthenticationException) {
                return response()->json([
                    'success' => false,
                    'message' => $e->getMessage() ?: 'Unauthenticated.',
                    'error' => 'Unauthenticated.',
                ], 401);
            }

            if ($e instanceof \Illuminate\Database\QueryException) {
                $sqlMsg = $e->getMessage();
                $prevMsg = $e->getPrevious() ? $e->getPrevious()->getMessage() : '';
                $combined = $sqlMsg.' '.$prevMsg;
                if (str_contains($combined, '[2002]')
                    || str_contains($combined, 'Connection refused')
                    || str_contains($combined, 'No connection could be made')) {
                    return response()->json([
                        'success' => false,
                        'message' => 'Database is unreachable (connection refused). Start MySQL and ensure backend/.env DB_HOST and DB_PORT match it — for Docker: from the repo root run `docker compose up -d mysql` (default host port 3305).',
                        'error' => 'database_unreachable',
                    ], 503);
                }
            }

            if ($e instanceof \Symfony\Component\HttpKernel\Exception\HttpExceptionInterface) {
                return response()->json([
                    'success' => false,
                    'message' => $e->getMessage(),
                    'error' => $e->getMessage(),
                ], $e->getStatusCode(), $e->getHeaders());
            }

            return response()->json([
                'success' => false,
                'message' => 'Server Error: ' . $e->getMessage(),
                'error' => $e->getMessage(),
                'file' => basename($e->getFile()),
                'line' => $e->getLine(),
            ], 500);
        });
    })->create();
