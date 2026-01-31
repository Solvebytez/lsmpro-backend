<?php

namespace App\Utils;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Response;

class CookieHelper
{
    /**
     * Set access token cookie (default: 15 minutes expiration)
     */
    public static function setAccessToken(Response|JsonResponse $response, string $token): Response|JsonResponse
    {
        $expiresIn = (int) env('ACCESS_TOKEN_EXPIRES_IN', 15); // minutes, default 15
        // Use secure only in production (HTTPS), not in local development
        $isSecure = env('APP_ENV') === 'production';
        // For same-domain (frontend and backend on lsmpro.in), use Lax
        // SameSite=None is only needed for cross-origin requests
        $sameSite = 'Lax';
        
        return $response->cookie(
            'access_token',
            $token,
            $expiresIn,
            '/',
            null, // domain - null means current domain
            $isSecure, // secure - only true in production
            true, // httpOnly
            true, // raw - set to true to prevent Laravel from encrypting the token
            $sameSite
        );
    }

    /**
     * Set refresh token cookie (default: 30 days expiration)
     */
    public static function setRefreshToken(Response|JsonResponse $response, string $token): Response|JsonResponse
    {
        // Convert days to minutes (env value is in days, cookie needs minutes)
        $expiresInDays = (int) env('REFRESH_TOKEN_EXPIRES_IN', 30); // days, default 30
        $expiresIn = $expiresInDays * 24 * 60; // convert to minutes
        // Use secure only in production (HTTPS), not in local development
        $isSecure = env('APP_ENV') === 'production';
        // For same-domain (frontend and backend on lsmpro.in), use Lax
        // SameSite=None is only needed for cross-origin requests
        $sameSite = 'Lax';
        
        return $response->cookie(
            'refresh_token',
            $token,
            $expiresIn,
            '/',
            null, // domain - null means current domain
            $isSecure, // secure - only true in production
            true, // httpOnly
            true, // raw - set to true to prevent Laravel from encrypting the token
            $sameSite
        );
    }

    /**
     * Set both access and refresh token cookies
     */
    public static function setAuthCookies(Response|JsonResponse $response, string $accessToken, string $refreshToken): Response|JsonResponse
    {
        $response = self::setAccessToken($response, $accessToken);
        $response = self::setRefreshToken($response, $refreshToken);
        return $response;
    }

    /**
     * Clear access token cookie
     */
    public static function clearAccessToken(Response|JsonResponse $response): Response|JsonResponse
    {
        $isSecure = env('APP_ENV') === 'production';
        return $response->cookie('access_token', '', -1, '/', null, $isSecure, true, true, 'Lax');
    }

    /**
     * Clear refresh token cookie
     */
    public static function clearRefreshToken(Response|JsonResponse $response): Response|JsonResponse
    {
        $isSecure = env('APP_ENV') === 'production';
        return $response->cookie('refresh_token', '', -1, '/', null, $isSecure, true, true, 'Lax');
    }

    /**
     * Clear both access and refresh token cookies
     */
    public static function clearAuthCookies(Response|JsonResponse $response): Response|JsonResponse
    {
        $response = self::clearAccessToken($response);
        $response = self::clearRefreshToken($response);
        return $response;
    }
}

