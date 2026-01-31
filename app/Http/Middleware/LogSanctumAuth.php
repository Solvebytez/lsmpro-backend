<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class LogSanctumAuth
{
    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next): Response
    {
        // Only log in debug mode to prevent memory issues
        if (config('app.debug')) {
            \Log::debug('LogSanctumAuth: Before authentication', [
                'path' => $request->path(),
                'has_bearer_token' => (bool) $request->bearerToken(),
                'has_cookie_token' => (bool) $request->cookie('access_token'),
            ]);
        }

        try {
            $response = $next($request);
            
            // Only log errors, not successful requests
            if (config('app.debug') && $response->getStatusCode() >= 400) {
                \Log::debug('LogSanctumAuth: Error response', [
                    'status' => $response->getStatusCode(),
                    'path' => $request->path(),
                ]);
            }
            
            return $response;
        } catch (\Exception $e) {
            // Logging removed to prevent memory issues - only re-throw
            throw $e;
        }
    }
}

