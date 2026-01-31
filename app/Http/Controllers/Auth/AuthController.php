<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;

class AuthController extends Controller
{
    /**
     * Get authenticated user details (works for both admin and superadmin).
     * Sanctum will automatically authenticate based on the token.
     */
    public function me(Request $request): JsonResponse
    {
        try {
            // Logging removed to prevent memory issues

            // Try to get user from request (Sanctum should set this)
            $user = $request->user();
            
            // If user is null, try to authenticate manually using the token
            if (!$user) {
                $token = $request->bearerToken() ?: $request->cookie('access_token');
                if ($token) {
                    // Logging removed to prevent memory issues
                    
                    // Find token in database
                    $tokenModel = \Laravel\Sanctum\PersonalAccessToken::findToken($token);
                    if ($tokenModel && $tokenModel->tokenable) {
                        $user = $tokenModel->tokenable;
                        // Logging removed to prevent memory issues
                    } else {
                        // Logging removed to prevent memory issues
                    }
                }
            }

            if (!$user) {
                // Logging removed to prevent memory issues
                
                return response()->json([
                    'success' => false,
                    'message' => 'Unauthenticated',
                ], 401);
            }

            // Logging removed to prevent memory issues

            return response()->json([
                'success' => true,
                'data' => [
                    'id' => $user->id,
                    'name' => $user->name,
                    'email' => $user->email,
                    'mobile' => $user->mobile,
                    'role' => $user->role,
                    'commission' => $user->commission,
                    'partnership' => $user->partnership,
                ],
            ], 200);
        } catch (\Exception $e) {
            // Logging removed to prevent memory issues

            return response()->json([
                'success' => false,
                'message' => 'Internal server error',
                'error' => $e->getMessage(),
            ], 500);
        }
    }
}

