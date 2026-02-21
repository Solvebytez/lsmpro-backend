<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\DB;
use App\Http\Controllers\Auth\SuperAdminAuthController;
use App\Http\Controllers\Auth\AdminAuthController;
use App\Http\Controllers\Auth\AuthController;
use App\Http\Controllers\UserController;
use App\Http\Controllers\TeamController;
use App\Http\Controllers\MatchController;
use App\Http\Controllers\GroupController;
use App\Http\Controllers\EntryController;
use App\Http\Controllers\InningsOverController;
use App\Http\Controllers\SessionController;

// Health check endpoint
Route::get('/health', function () {
    try {
        // Check database connection
        DB::connection()->getPdo();
        
        return response()->json([
            'status' => 'ok',
            'message' => 'API is healthy',
            'database' => 'connected',
            'timestamp' => now()->toIso8601String(),
        ], 200);
    } catch (\Exception $e) {
        return response()->json([
            'status' => 'error',
            'message' => 'API health check failed',
            'database' => 'disconnected',
            'error' => $e->getMessage(),
            'timestamp' => now()->toIso8601String(),
        ], 503);
    }
});

// Simple API info endpoint
Route::get('/', function () {
    return response()->json([
        'message' => 'Gameloft API',
        'version' => '1.0.0',
        'status' => 'running',
    ], 200);
});

// Test endpoint for debugging - no auth required
Route::get('/test', function () {
    \Log::info('Test endpoint called');
    return response()->json([
        'message' => 'Test endpoint working',
        'timestamp' => now()->toIso8601String(),
    ], 200);
});

// Super Admin Authentication Routes
Route::prefix('v1/superadmin')->group(function () {
    Route::post('/login', [SuperAdminAuthController::class, 'login']);
    Route::post('/refresh', [SuperAdminAuthController::class, 'refresh']);
    
    // Protected routes (require authentication)
    // Temporarily removed auth:sanctum middleware to avoid infinite recursion
    // Authentication is handled manually in the controller
    Route::middleware('auth:sanctum')->group(function () {
        Route::get('/me', [SuperAdminAuthController::class, 'me']);
        Route::put('/admins/{id}', [SuperAdminAuthController::class, 'updateAdmin']);
    });
    
    // Routes without auth:sanctum middleware (authentication handled manually in controller)
    Route::post('/logout', [SuperAdminAuthController::class, 'logout']);
    Route::get('/admins', [SuperAdminAuthController::class, 'listAdmins']);
    Route::post('/create-admin', [SuperAdminAuthController::class, 'createAdmin']);
    Route::patch('/admins/{id}/status', [SuperAdminAuthController::class, 'updateStatus']);
    Route::delete('/admins/{id}', [SuperAdminAuthController::class, 'deleteAdmin']);
});

// Admin Authentication Routes
Route::prefix('v1/admin')->group(function () {
    Route::post('/login', [AdminAuthController::class, 'login']);
    Route::post('/refresh', [AdminAuthController::class, 'refresh']);
    
    // Protected routes (require authentication)
    // Temporarily removed auth:sanctum middleware to avoid infinite recursion
    // Authentication is handled manually in the controller
    Route::middleware('auth:sanctum')->group(function () {
        Route::get('/me', [AdminAuthController::class, 'me']); // Keep for backward compatibility
    });
    
    // Routes without auth:sanctum middleware (authentication handled manually in controller)
    Route::post('/logout', [AdminAuthController::class, 'logout']);
    Route::post('/change-password', [AdminAuthController::class, 'changePassword']);
    
    // User management routes (authentication handled manually in controller)
    Route::post('/users', [UserController::class, 'createUser']);
    Route::get('/users', [UserController::class, 'listUsers']);
    Route::put('/users/{id}', [UserController::class, 'updateUser']);
    Route::patch('/users/{id}/status', [UserController::class, 'updateStatus']);
    Route::delete('/users/{id}', [UserController::class, 'deleteUser']);
    
    // Team management routes (authentication handled manually in controller)
    Route::post('/teams', [TeamController::class, 'createTeam']);
    Route::get('/teams', [TeamController::class, 'listTeams']);
    Route::put('/teams/{id}', [TeamController::class, 'updateTeam']);
    Route::post('/teams/{id}', [TeamController::class, 'updateTeam']); // POST for file uploads with method spoofing
    Route::patch('/teams/{id}/status', [TeamController::class, 'updateStatus']);
    Route::delete('/teams/{id}', [TeamController::class, 'deleteTeam']);
    
    // Match management routes (authentication handled manually in controller)
    Route::post('/matches', [MatchController::class, 'createMatch']);
    Route::get('/matches', [MatchController::class, 'listMatches']);
    Route::get('/matches/{id}', [MatchController::class, 'getMatch']);
    
    // Entry management routes (authentication handled manually in controller)
    Route::post('/entries', [EntryController::class, 'createEntry']);
    Route::get('/matches/{matchId}/entries', [EntryController::class, 'listEntries']);
    Route::get('/entries/{id}', [EntryController::class, 'getEntry']);
    Route::put('/entries/{id}', [EntryController::class, 'updateEntry']);
    Route::delete('/entries/{id}', [EntryController::class, 'deleteEntry']);
    
    // Group management routes (authentication handled manually in controller)
    Route::post('/groups', [GroupController::class, 'createGroup']);
    Route::get('/groups', [GroupController::class, 'listGroups']);
    Route::put('/groups/{id}', [GroupController::class, 'updateGroup']);
    Route::delete('/groups/{id}', [GroupController::class, 'deleteGroup']);
    
    // Innings/Over management routes (authentication handled manually in controller)
    Route::post('/innings-overs', [InningsOverController::class, 'createInningsOver']);
    Route::get('/innings-overs', [InningsOverController::class, 'listInningsOvers']);
    Route::put('/innings-overs/{id}', [InningsOverController::class, 'updateInningsOver']);
    Route::delete('/innings-overs/{id}', [InningsOverController::class, 'deleteInningsOver']);
    
    // Session management routes (authentication handled manually in controller)
    Route::post('/sessions', [SessionController::class, 'createSession']);
    Route::get('/sessions', [SessionController::class, 'listSessions']);
    Route::put('/sessions/{id}', [SessionController::class, 'updateSession']);
    Route::delete('/sessions/{id}', [SessionController::class, 'deleteSession']);
    Route::post('/sessions/update-result', [SessionController::class, 'updateResultByInningsOver']);
});

// Common Authentication Routes (works for both admin and superadmin)
// Temporarily removed auth:sanctum to debug - controller will handle auth manually
// Temporarily disabled LogSanctumAuth middleware to prevent memory issues
// Route::prefix('v1')->middleware([\App\Http\Middleware\LogSanctumAuth::class])->group(function () {
Route::prefix('v1')->group(function () {
    Route::get('/me', [AuthController::class, 'me']); // Common endpoint
});

// Debug route to test without auth (temporary)
Route::get('/v1/debug-me', function (Request $request) {
    \Log::info('Debug /me endpoint called', [
        'has_bearer' => $request->bearerToken() ? 'yes' : 'no',
        'bearer_preview' => $request->bearerToken() ? substr($request->bearerToken(), 0, 30) . '...' : 'no',
        'has_cookie' => $request->cookie('access_token') ? 'yes' : 'no',
        'cookie_preview' => $request->cookie('access_token') ? substr($request->cookie('access_token'), 0, 30) . '...' : 'no',
        'all_cookies' => array_keys($request->cookies->all()),
        'user' => $request->user() ? $request->user()->email : 'null',
    ]);
    
    return response()->json([
        'message' => 'Debug endpoint - check logs',
        'has_bearer_token' => $request->bearerToken() ? 'yes' : 'no',
        'has_cookie_token' => $request->cookie('access_token') ? 'yes' : 'no',
        'user' => $request->user() ? $request->user()->email : 'null',
    ]);
});

