<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\Admin;
use App\Utils\CookieHelper;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;

class AdminAuthController extends Controller
{
    /**
     * Manually authenticate user from token to avoid infinite recursion with Sanctum guard.
     */
    private function getAuthenticatedUser(Request $request)
    {
        $token = $request->bearerToken() ?: $request->cookie('access_token');
        
        if (!$token) {
            return null;
        }
        
        try {
            // Use Sanctum's findToken method which handles the token format automatically
            $tokenModel = \Laravel\Sanctum\PersonalAccessToken::findToken($token);
            
            if ($tokenModel && $tokenModel->tokenable) {
                return $tokenModel->tokenable;
            }
        } catch (\Exception $e) {
            // Return null on error
        }
        
        return null;
    }

    /**
     * Handle admin login request.
     */
    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'password' => 'required|string',
        ]);

        $admin = Admin::where('email', $request->email)
            ->where('role', 'admin')
            ->first();

        if (!$admin || !Hash::check($request->password, $admin->password)) {
            throw ValidationException::withMessages([
                'email' => ['The provided credentials are incorrect.'],
            ]);
        }

        // Check if admin status is active
        if ($admin->status !== 'active') {
            throw ValidationException::withMessages([
                'email' => ['Your account is inactive. Please contact the administrator.'],
            ]);
        }

        // Revoke all existing tokens (optional - for single device login)
        // $admin->tokens()->delete();

        // Get expiration times from env (default: 15 minutes for access, 30 days for refresh)
        $accessTokenExpires = (int) env('ACCESS_TOKEN_EXPIRES_IN', 15); // minutes
        $refreshTokenExpires = (int) env('REFRESH_TOKEN_EXPIRES_IN', 30); // days

        // Create access token
        $accessToken = $admin->createToken(
            'access-token',
            ['*'],
            now()->addMinutes($accessTokenExpires)
        )->plainTextToken;

        // Create refresh token
        $refreshToken = $admin->createToken(
            'refresh-token',
            ['refresh'],
            now()->addDays($refreshTokenExpires)
        )->plainTextToken;

        // Create response with admin data
        $response = response()->json([
            'success' => true,
            'message' => 'Login successful',
            'data' => [
                'admin' => [
                    'id' => $admin->id,
                    'name' => $admin->name,
                    'email' => $admin->email,
                    'mobile' => $admin->mobile,
                    'role' => $admin->role,
                    'status' => $admin->status,
                    'commission' => $admin->commission,
                    'partnership' => $admin->partnership,
                ],
            ],
        ], 200);

        // Set cookies using utility function
        return CookieHelper::setAuthCookies($response, $accessToken, $refreshToken);
    }

    /**
     * Handle logout request.
     */
    public function logout(Request $request)
    {
        // Manually authenticate to avoid infinite recursion
        $user = $this->getAuthenticatedUser($request);
        
        // Delete all tokens for the user if authenticated
        if ($user) {
            $user->tokens()->delete();
        }

        // Always clear cookies, even if user is not authenticated
        // This handles cases where tokens are expired but cookies still exist
        $response = response()->json([
            'success' => true,
            'message' => 'Logged out successfully',
        ], 200);

        // Clear cookies using utility function
        return CookieHelper::clearAuthCookies($response);
    }

    /**
     * Refresh access token using refresh token.
     */
    public function refresh(Request $request)
    {
        $refreshToken = $request->cookie('refresh_token');

        if (!$refreshToken) {
            return response()->json([
                'success' => false,
                'message' => 'Refresh token not found',
            ], 401);
        }

        // Find the token in database
        $token = \Laravel\Sanctum\PersonalAccessToken::findToken($refreshToken);

        if (!$token || !$token->can('refresh')) {
            return response()->json([
                'success' => false,
                'message' => 'Invalid refresh token',
            ], 401);
        }

        $admin = $token->tokenable;

        // Check if admin status is still active
        if ($admin->status !== 'active') {
            return response()->json([
                'success' => false,
                'message' => 'Your account is inactive. Please contact the administrator.',
            ], 403);
        }

        // Delete old access token if exists
        $admin->tokens()->where('name', 'access-token')->delete();

        // Get expiration time from env (default: 15 minutes)
        $accessTokenExpires = (int) env('ACCESS_TOKEN_EXPIRES_IN', 15); // minutes

        // Create new access token
        $accessToken = $admin->createToken(
            'access-token',
            ['*'],
            now()->addMinutes($accessTokenExpires)
        )->plainTextToken;

        $response = response()->json([
            'success' => true,
            'message' => 'Token refreshed successfully',
        ], 200);

        // Set new access token cookie using utility function
        return CookieHelper::setAccessToken($response, $accessToken);
    }

    /**
     * Get authenticated admin details.
     */
    public function me(Request $request)
    {
        $admin = $request->user();

        return response()->json([
            'success' => true,
            'data' => [
                'id' => $admin->id,
                'name' => $admin->name,
                'email' => $admin->email,
                'mobile' => $admin->mobile,
                'role' => $admin->role,
                'status' => $admin->status,
                'commission' => $admin->commission,
                'partnership' => $admin->partnership,
            ],
        ], 200);
    }

    /**
     * Change admin password.
     */
    public function changePassword(Request $request)
    {
        // Manually authenticate to avoid infinite recursion
        $admin = $this->getAuthenticatedUser($request);
        
        if (!$admin) {
            return response()->json([
                'success' => false,
                'message' => 'Unauthorized',
            ], 401);
        }

        // Validate request
        $request->validate([
            'current_password' => 'required|string',
            'new_password' => 'required|string|min:6',
            'confirmation_password' => 'required|string|same:new_password',
        ]);

        // Verify current password
        if (!Hash::check($request->current_password, $admin->password)) {
            return response()->json([
                'success' => false,
                'message' => 'Current password is incorrect',
            ], 422);
        }

        // Check if new password is different from current password
        if (Hash::check($request->new_password, $admin->password)) {
            return response()->json([
                'success' => false,
                'message' => 'New password must be different from current password',
            ], 422);
        }

        // Update password
        $admin->password = Hash::make($request->new_password);
        $admin->save();

        return response()->json([
            'success' => true,
            'message' => 'Password changed successfully',
        ], 200);
    }
}

