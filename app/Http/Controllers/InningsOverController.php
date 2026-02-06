<?php

namespace App\Http\Controllers;

use App\Models\InningsOver;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use Illuminate\Validation\ValidationException;

class InningsOverController extends Controller
{
    /**
     * Manually authenticate admin from token to avoid infinite recursion with Sanctum guard.
     */
    private function getAuthenticatedAdmin(Request $request)
    {
        $token = $request->bearerToken() ?: $request->cookie('access_token');
        
        if (!$token) {
            return null;
        }
        
        try {
            $tokenModel = \Laravel\Sanctum\PersonalAccessToken::findToken($token);
            
            if ($tokenModel && $tokenModel->tokenable) {
                $user = $tokenModel->tokenable;
                // Check if the authenticated user is an admin (from admins table)
                if ($user instanceof \App\Models\Admin) {
                    return $user;
                }
            }
        } catch (\Exception $e) {
            // Return null on error
        }
        
        return null;
    }

    /**
     * Create a new innings/over entry.
     */
    public function createInningsOver(Request $request): JsonResponse
    {
        // Manually authenticate to avoid infinite recursion
        $admin = $this->getAuthenticatedAdmin($request);
        
        if (!$admin) {
            return response()->json([
                'success' => false,
                'message' => 'Unauthenticated. Please login first.',
            ], 401);
        }

        // Validate request data
        try {
            $validated = $request->validate([
                'inning' => 'required|integer|min:1',
                'over' => 'required|integer|min:1',
            ]);
        } catch (ValidationException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $e->errors(),
            ], 422);
        }

        try {
            // Create the innings/over entry
            $inningsOver = InningsOver::create([
                'inning' => $validated['inning'],
                'over' => $validated['over'],
                'created_by' => $admin->id,
            ]);

            // Load relationships
            $inningsOver->load(['creator:id,name,email']);

            return response()->json([
                'success' => true,
                'message' => 'Innings/Over created successfully',
                'data' => [
                    'id' => $inningsOver->id,
                    'inning' => $inningsOver->inning,
                    'over' => $inningsOver->over,
                    'created_by' => $inningsOver->created_by,
                    'creator' => $inningsOver->creator ? [
                        'id' => $inningsOver->creator->id,
                        'name' => $inningsOver->creator->name,
                        'email' => $inningsOver->creator->email,
                    ] : null,
                    'created_at' => $inningsOver->created_at,
                    'updated_at' => $inningsOver->updated_at,
                ],
            ], 201);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Failed to create innings/over',
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    /**
     * Get all innings/over entries created by the authenticated admin.
     */
    public function listInningsOvers(Request $request): JsonResponse
    {
        // Manually authenticate to avoid infinite recursion
        $admin = $this->getAuthenticatedAdmin($request);
        
        if (!$admin) {
            return response()->json([
                'success' => false,
                'message' => 'Unauthenticated. Please login first.',
            ], 401);
        }

        try {
            // Filter innings/overs to only show those created by this admin
            $inningsOvers = InningsOver::with(['creator:id,name,email'])
                ->where('created_by', $admin->id)
                ->orderBy('created_at', 'desc')
                ->get()
                ->map(function ($inningsOver) {
                    return [
                        'id' => $inningsOver->id,
                        'inning' => $inningsOver->inning,
                        'over' => $inningsOver->over,
                        'created_by' => $inningsOver->created_by,
                        'creator' => $inningsOver->creator ? [
                            'id' => $inningsOver->creator->id,
                            'name' => $inningsOver->creator->name,
                            'email' => $inningsOver->creator->email,
                        ] : null,
                        'created_at' => $inningsOver->created_at,
                        'updated_at' => $inningsOver->updated_at,
                    ];
                });

            return response()->json([
                'success' => true,
                'data' => $inningsOvers,
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Failed to fetch innings/overs',
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    /**
     * Update an existing innings/over entry.
     */
    public function updateInningsOver(Request $request, int $id): JsonResponse
    {
        // Manually authenticate to avoid infinite recursion
        $admin = $this->getAuthenticatedAdmin($request);
        
        if (!$admin) {
            return response()->json([
                'success' => false,
                'message' => 'Unauthenticated. Please login first.',
            ], 401);
        }

        // Validate request data
        try {
            $validated = $request->validate([
                'inning' => 'sometimes|required|integer|min:1',
                'over' => 'sometimes|required|integer|min:1',
            ]);
        } catch (ValidationException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $e->errors(),
            ], 422);
        }

        try {
            // Find the innings/over entry and verify ownership
            $inningsOver = InningsOver::where('id', $id)
                ->where('created_by', $admin->id)
                ->first();

            if (!$inningsOver) {
                return response()->json([
                    'success' => false,
                    'message' => 'Innings/Over entry not found or you do not have permission to update it.',
                ], 404);
            }

            // Update fields if provided
            if (isset($validated['inning'])) {
                $inningsOver->inning = $validated['inning'];
            }
            if (isset($validated['over'])) {
                $inningsOver->over = $validated['over'];
            }

            // Save the entry
            $inningsOver->save();

            // Load relationships
            $inningsOver->load(['creator:id,name,email']);

            return response()->json([
                'success' => true,
                'message' => 'Innings/Over updated successfully',
                'data' => [
                    'id' => $inningsOver->id,
                    'inning' => $inningsOver->inning,
                    'over' => $inningsOver->over,
                    'created_by' => $inningsOver->created_by,
                    'creator' => $inningsOver->creator ? [
                        'id' => $inningsOver->creator->id,
                        'name' => $inningsOver->creator->name,
                        'email' => $inningsOver->creator->email,
                    ] : null,
                    'created_at' => $inningsOver->created_at,
                    'updated_at' => $inningsOver->updated_at,
                ],
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Failed to update innings/over',
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    /**
     * Delete an innings/over entry.
     */
    public function deleteInningsOver(Request $request, int $id): JsonResponse
    {
        // Manually authenticate to avoid infinite recursion
        $admin = $this->getAuthenticatedAdmin($request);
        
        if (!$admin) {
            return response()->json([
                'success' => false,
                'message' => 'Unauthenticated. Please login first.',
            ], 401);
        }

        try {
            // Find the innings/over entry and verify ownership
            $inningsOver = InningsOver::where('id', $id)
                ->where('created_by', $admin->id)
                ->first();

            if (!$inningsOver) {
                return response()->json([
                    'success' => false,
                    'message' => 'Innings/Over entry not found or you do not have permission to delete it.',
                ], 404);
            }

            // Delete the entry
            $inningsOver->delete();

            return response()->json([
                'success' => true,
                'message' => 'Innings/Over deleted successfully',
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Failed to delete innings/over',
                'error' => $e->getMessage(),
            ], 500);
        }
    }
}

