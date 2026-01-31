<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\Admin;
use App\Utils\CookieHelper;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;

class SuperAdminAuthController extends Controller
{
    /**
     * Manually authenticate user from token to avoid infinite recursion with Sanctum guard.
     */
    private function getAuthenticatedUser(Request $request, array &$debug = [])
    {
        $token = $request->bearerToken() ?: $request->cookie('access_token');
        
        $debug[] = 'Token found: ' . ($token ? 'yes (preview: ' . substr($token, 0, 20) . '...)' : 'no');
        $debug[] = 'Bearer token: ' . ($request->bearerToken() ? 'yes' : 'no');
        $debug[] = 'Cookie token: ' . ($request->cookie('access_token') ? 'yes' : 'no');
        
        if (!$token) {
            $debug[] = 'No token found';
            return null;
        }
        
        try {
            // Use Sanctum's findToken method which handles the token format automatically
            $tokenModel = \Laravel\Sanctum\PersonalAccessToken::findToken($token);
            
            if ($tokenModel) {
                $debug[] = 'Token model found, ID: ' . $tokenModel->id;
                
                if ($tokenModel->tokenable) {
                    $user = $tokenModel->tokenable;
                    $debug[] = 'User found: ' . $user->email . ' (role: ' . $user->role . ')';
                    return $user;
                } else {
                    $debug[] = 'Token model has no tokenable';
                }
            } else {
                $debug[] = 'Token model not found via findToken';
            }
        } catch (\Exception $e) {
            $debug[] = 'Exception: ' . $e->getMessage();
        }
        
        $debug[] = 'Returning null - no authenticated user';
        return null;
    }

    /**
     * Handle superadmin login request.
     */
    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'password' => 'required|string',
        ]);

        $admin = Admin::where('email', $request->email)
            ->where('role', 'superadmin')
            ->first();

        if (!$admin || !Hash::check($request->password, $admin->password)) {
            throw ValidationException::withMessages([
                'email' => ['The provided credentials are incorrect.'],
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
        $tokenModel = $admin->createToken(
            'refresh-token',
            ['refresh'],
            now()->addDays($refreshTokenExpires)
        );
        $refreshToken = $tokenModel->plainTextToken;
        
        // Logging removed to prevent memory issues

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
        try {
            // Manually authenticate to avoid infinite recursion
            $debug = [];
            $user = $this->getAuthenticatedUser($request, $debug);
            
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
        } catch (\Throwable $e) {
            // Even if there's an error, try to clear cookies
            $response = response()->json([
                'success' => true,
                'message' => 'Logged out successfully',
            ], 200);
            
            try {
                return CookieHelper::clearAuthCookies($response);
            } catch (\Throwable $cookieError) {
                // If clearing cookies fails, just return the response
                return $response;
            }
        }
    }

    /**
     * Refresh access token using refresh token.
     */
    public function refresh(Request $request)
    {
        // Logging removed to prevent memory issues
        
        $refreshToken = $request->cookie('refresh_token');

        if (!$refreshToken) {
            // Logging removed to prevent memory issues
            return response()->json([
                'success' => false,
                'message' => 'Refresh token not found',
            ], 401);
        }

        // Try URL decoding in case pipe was encoded
        $decodedToken = urldecode($refreshToken);
        if ($decodedToken !== $refreshToken) {
            $refreshToken = $decodedToken;
        }
        
        // Try to find token - Sanctum tokens are in format: {id}|{hash}
        $token = \Laravel\Sanctum\PersonalAccessToken::findToken($refreshToken);
        
        // If findToken fails, try manual lookup
        if (!$token && strpos($refreshToken, '|') !== false) {
            $parts = explode('|', $refreshToken, 2);
            if (count($parts) === 2) {
                $tokenId = $parts[0];
                $tokenHash = hash('sha256', $parts[1]);
                $token = \Laravel\Sanctum\PersonalAccessToken::where('id', $tokenId)
                    ->where('token', $tokenHash)
                    ->where('name', 'refresh-token')
                    ->first();
            }
        }
        
        // If still not found and token looks like base64, try to decode and check
        if (!$token && base64_encode(base64_decode($refreshToken, true)) === $refreshToken) {
            $decoded = base64_decode($refreshToken, true);
            if ($decoded && strpos($decoded, '|') !== false) {
                $token = \Laravel\Sanctum\PersonalAccessToken::findToken($decoded);
            }
        }
        
        // Also check all refresh tokens in database for debugging
        // Removed: Logging all tokens causes memory exhaustion
        // $allTokens = \Laravel\Sanctum\PersonalAccessToken::where('name', 'refresh-token')
        //     ->where('tokenable_type', 'App\Models\Admin')
        //     ->get(['id', 'name', 'abilities', 'expires_at', 'created_at']);
        // \Log::info('🔍 All refresh tokens in DB: ' . json_encode($allTokens->map(function($t) {
        //     return [
        //         'id' => $t->id,
        //         'name' => $t->name,
        //         'abilities' => $t->abilities,
        //         'expires_at' => $t->expires_at ? $t->expires_at->toDateTimeString() : null,
        //         'created_at' => $t->created_at->toDateTimeString(),
        //     ];
        // })));

        if (!$token || !$token->can('refresh')) {
            // Logging removed to prevent memory issues
            return response()->json([
                'success' => false,
                'message' => 'Invalid refresh token',
            ], 401);
        }

        $admin = $token->tokenable;

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
            'data' => [
                'access_token' => $accessToken, // Also return in body for middleware to read
            ],
        ], 200);

        // Set new access token cookie using utility function
        $finalResponse = CookieHelper::setAccessToken($response, $accessToken);
        
        return $finalResponse;
    }

    /**
     * Get authenticated admin details.
     */
    public function me(Request $request)
    {
        // Manually authenticate to avoid infinite recursion
        $admin = $this->getAuthenticatedUser($request);
        if (!$admin) {
            return response()->json([
                'success' => false,
                'message' => 'Unauthenticated',
            ], 401);
        }

        return response()->json([
            'success' => true,
            'data' => [
                'id' => $admin->id,
                'name' => $admin->name,
                'email' => $admin->email,
                'mobile' => $admin->mobile,
                'role' => $admin->role,
                'commission' => $admin->commission,
                'partnership' => $admin->partnership,
            ],
        ], 200);
    }

    /**
     * Create a new admin user (only superadmin can create admins).
     */
    public function createAdmin(Request $request)
    {
        $debug = [];
        $debug[] = 'Method called';
        $debug[] = 'Request data keys: ' . implode(', ', array_keys($request->all()));
        
        try {
            // Manually authenticate to avoid infinite recursion
            $currentUser = $this->getAuthenticatedUser($request, $debug);
            $debug[] = 'Current user: ' . ($currentUser ? $currentUser->email . ' (role: ' . $currentUser->role . ')' : 'null');
            
            if (!$currentUser) {
                // Return 401 for authentication failure (so axios interceptor can refresh token)
                return response()->json([
                    'success' => false,
                    'message' => 'Unauthenticated',
                    'debug' => config('app.debug') ? $debug : null,
                ], 401);
            }
            
            if ($currentUser->role !== 'superadmin') {
                // Return 403 for authorization failure (user is authenticated but lacks permission)
                return response()->json([
                    'success' => false,
                    'message' => 'Unauthorized. Only superadmin can create admins.',
                    'debug' => config('app.debug') ? $debug : null,
                ], 403);
            }

            // Validate input
            $validated = $request->validate([
                'name' => 'required|string|max:255',
                'email' => 'required|email|unique:admins,email',
                'mobile' => 'nullable|string|max:20',
                'password' => 'required|string|min:6',
                'role' => 'required|string|in:admin',
            ]);

            // Create the admin
            $admin = Admin::create([
                'name' => $validated['name'],
                'email' => $validated['email'],
                'mobile' => $validated['mobile'] ?? null,
                'password' => Hash::make($validated['password']),
                'role' => $validated['role'],
                'status' => 'active', // Default to active
                'commission' => 0, // Default to 0, can be updated later
                'partnership' => 0, // Default to 0, can be updated later
            ]);

            return response()->json([
                'success' => true,
                'message' => 'Admin created successfully',
                'data' => [
                    'id' => $admin->id,
                    'name' => $admin->name,
                    'email' => $admin->email,
                    'mobile' => $admin->mobile,
                    'role' => $admin->role,
                    'commission' => $admin->commission,
                    'partnership' => $admin->partnership,
                    'created_at' => $admin->created_at ? $admin->created_at->toDateTimeString() : null,
                    'updated_at' => $admin->updated_at ? $admin->updated_at->toDateTimeString() : null,
                ],
            ], 201);
        } catch (\Illuminate\Validation\ValidationException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $e->errors(),
                'debug' => config('app.debug') ? $debug : null,
            ], 422);
        } catch (\Throwable $e) {
            $debug[] = 'Exception: ' . $e->getMessage();
            $debug[] = 'File: ' . basename($e->getFile()) . ':' . $e->getLine();
            return response()->json([
                'success' => false,
                'message' => 'Error creating admin: ' . $e->getMessage(),
                'error' => $e->getMessage(),
                'file' => basename($e->getFile()),
                'line' => $e->getLine(),
                'debug' => config('app.debug') ? $debug : null,
            ], 500);
        }
    }

    /**
     * List all admin users (only superadmin can list admins).
     */
    public function listAdmins(Request $request)
    {
        $debug = [];
        $debug[] = 'Method called';
        $debug[] = 'All cookies: ' . json_encode(array_keys($request->cookies->all()));
        $debug[] = 'Access token cookie: ' . ($request->cookie('access_token') ? 'present (length: ' . strlen($request->cookie('access_token')) . ')' : 'missing');
        $debug[] = 'Bearer token: ' . ($request->bearerToken() ? 'present' : 'missing');
        
        // Manually authenticate to avoid infinite recursion
        $currentUser = $this->getAuthenticatedUser($request, $debug);
        
        $debug[] = 'Current user: ' . ($currentUser ? $currentUser->email . ' (role: ' . $currentUser->role . ')' : 'null');
        
        // Validate that the authenticated user is a superadmin
        if (!$currentUser) {
            // Return 401 for authentication failure (so axios interceptor can refresh token)
            return response()->json([
                'success' => false,
                'message' => 'Unauthenticated',
                'debug' => config('app.debug') ? $debug : null,
            ], 401);
        }
        
        if ($currentUser->role !== 'superadmin') {
            // Return 403 for authorization failure (user is authenticated but lacks permission)
            return response()->json([
                'success' => false,
                'message' => 'Unauthorized. Only superadmin can list admins.',
                'debug' => config('app.debug') ? $debug : null,
            ], 403);
        }

        try {
            // Use direct DB query to avoid model overhead and memory issues
            $results = \DB::table('admins')
                ->where('role', 'admin')
                ->select('id', 'name', 'email', 'mobile', 'role', 'status', 'commission', 'partnership', 'created_at', 'updated_at')
                ->orderBy('created_at', 'desc')
                ->get();
            
            $admins = [];
            foreach ($results as $admin) {
                // Convert dates to strings safely
                $createdAt = null;
                if (isset($admin->created_at)) {
                    if (is_object($admin->created_at) && method_exists($admin->created_at, 'toDateTimeString')) {
                        $createdAt = $admin->created_at->toDateTimeString();
                    } else {
                        $createdAt = (string) $admin->created_at;
                    }
                }
                
                $updatedAt = null;
                if (isset($admin->updated_at)) {
                    if (is_object($admin->updated_at) && method_exists($admin->updated_at, 'toDateTimeString')) {
                        $updatedAt = $admin->updated_at->toDateTimeString();
                    } else {
                        $updatedAt = (string) $admin->updated_at;
                    }
                }
                
                $admins[] = [
                    'id' => (int) $admin->id,
                    'name' => (string) $admin->name,
                    'email' => (string) $admin->email,
                    'mobile' => isset($admin->mobile) && $admin->mobile ? (string) $admin->mobile : null,
                    'role' => (string) $admin->role,
                    'status' => isset($admin->status) ? (string) $admin->status : 'active',
                    'commission' => isset($admin->commission) && $admin->commission !== null ? (float) $admin->commission : null,
                    'partnership' => isset($admin->partnership) && $admin->partnership !== null ? (float) $admin->partnership : null,
                    'created_at' => $createdAt,
                    'updated_at' => $updatedAt,
                ];
            }

            return response()->json([
                'success' => true,
                'data' => $admins,
            ], 200);
        } catch (\Throwable $e) {
            // Return error message for debugging (but don't log to prevent memory issues)
            return response()->json([
                'success' => false,
                'message' => 'Error fetching admins: ' . $e->getMessage(),
                'error' => $e->getMessage(),
                'file' => basename($e->getFile()),
                'line' => $e->getLine(),
            ], 500);
        }
    }

    /**
     * Update an admin user (only superadmin can update admins).
     */
    public function updateAdmin(Request $request, $id)
    {
        // Manually authenticate to avoid infinite recursion
        $currentUser = $this->getAuthenticatedUser($request);
        if (!$currentUser) {
            // Return 401 for authentication failure (so axios interceptor can refresh token)
            return response()->json([
                'success' => false,
                'message' => 'Unauthenticated',
            ], 401);
        }
        
        if ($currentUser->role !== 'superadmin') {
            // Return 403 for authorization failure (user is authenticated but lacks permission)
            return response()->json([
                'success' => false,
                'message' => 'Unauthorized. Only superadmin can update admins.',
            ], 403);
        }

        $admin = Admin::where('id', $id)->where('role', 'admin')->first();

        if (!$admin) {
            return response()->json([
                'success' => false,
                'message' => 'Admin not found',
            ], 404);
        }

        // Validate input
        $validated = $request->validate([
            'name' => 'sometimes|required|string|max:255',
            'email' => 'sometimes|required|email|unique:admins,email,' . $id,
            'mobile' => 'nullable|string|max:20',
            'password' => 'sometimes|string|min:6',
        ]);

        // Update fields
        if (isset($validated['name'])) {
            $admin->name = $validated['name'];
        }
        if (isset($validated['email'])) {
            $admin->email = $validated['email'];
        }
        if (isset($validated['mobile'])) {
            $admin->mobile = $validated['mobile'];
        }
        if (isset($validated['password'])) {
            $admin->password = Hash::make($validated['password']);
        }

        $admin->save();

        return response()->json([
            'success' => true,
            'message' => 'Admin updated successfully',
            'data' => [
                'id' => $admin->id,
                'name' => $admin->name,
                'email' => $admin->email,
                'mobile' => $admin->mobile,
                'role' => $admin->role,
                'commission' => $admin->commission,
                'partnership' => $admin->partnership,
                'created_at' => $admin->created_at,
                'updated_at' => $admin->updated_at,
            ],
        ], 200);
    }

    /**
     * Delete an admin user (only superadmin can delete admins).
     */
    public function deleteAdmin(Request $request, $id)
    {
        // Manually authenticate to avoid infinite recursion
        $currentUser = $this->getAuthenticatedUser($request);
        if (!$currentUser) {
            // Return 401 for authentication failure (so axios interceptor can refresh token)
            return response()->json([
                'success' => false,
                'message' => 'Unauthenticated',
            ], 401);
        }
        
        if ($currentUser->role !== 'superadmin') {
            // Return 403 for authorization failure (user is authenticated but lacks permission)
            return response()->json([
                'success' => false,
                'message' => 'Unauthorized. Only superadmin can delete admins.',
            ], 403);
        }

        $admin = Admin::where('id', $id)->where('role', 'admin')->first();

        if (!$admin) {
            return response()->json([
                'success' => false,
                'message' => 'Admin not found',
            ], 404);
        }

        $admin->delete();

        return response()->json([
            'success' => true,
            'message' => 'Admin deleted successfully',
        ], 200);
    }

    /**
     * Update admin status (only superadmin can update status).
     */
    public function updateStatus(Request $request, $id)
    {
        // Manually authenticate to avoid infinite recursion
        $currentUser = $this->getAuthenticatedUser($request);
        if (!$currentUser) {
            // Return 401 for authentication failure (so axios interceptor can refresh token)
            return response()->json([
                'success' => false,
                'message' => 'Unauthenticated',
            ], 401);
        }
        
        if ($currentUser->role !== 'superadmin') {
            // Return 403 for authorization failure (user is authenticated but lacks permission)
            return response()->json([
                'success' => false,
                'message' => 'Unauthorized. Only superadmin can update admin status.',
            ], 403);
        }

        $admin = Admin::where('id', $id)->where('role', 'admin')->first();

        if (!$admin) {
            return response()->json([
                'success' => false,
                'message' => 'Admin not found',
            ], 404);
        }

        // Validate input
        $validated = $request->validate([
            'status' => 'required|string|in:active,inactive',
        ]);

        // Update status
        $admin->status = $validated['status'];
        $admin->save();

        return response()->json([
            'success' => true,
            'message' => 'Admin status updated successfully',
            'data' => [
                'id' => $admin->id,
                'name' => $admin->name,
                'email' => $admin->email,
                'status' => $admin->status,
            ],
        ], 200);
    }
}

