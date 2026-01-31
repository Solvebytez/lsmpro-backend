<?php

namespace App\Http\Controllers;

use App\Models\Group;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use Illuminate\Validation\ValidationException;

class GroupController extends Controller
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
     * Create a new group with users.
     */
    public function createGroup(Request $request): JsonResponse
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
                'name' => 'required|string|max:255',
                'user_ids' => 'required|array|min:1',
                'user_ids.*' => 'required|integer|exists:users,id',
            ]);
        } catch (ValidationException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $e->errors(),
            ], 422);
        }

        try {
            // Verify that all user_ids belong to users created by this admin
            $userIds = $validated['user_ids'];
            $users = User::whereIn('id', $userIds)
                ->where('created_by', $admin->id)
                ->get();

            if ($users->count() !== count($userIds)) {
                return response()->json([
                    'success' => false,
                    'message' => 'Some users not found or you do not have permission to add them to the group.',
                ], 403);
            }

            // Calculate total commission (sum of commission percentages only from users who have commission)
            // Exclude users with commission_type = 'no_commission'
            $totalCommission = $users
                ->where('commission_type', '!=', 'no_commission')
                ->sum('commission');

            // Create the group
            $group = Group::create([
                'name' => $validated['name'],
                'total_commission' => $totalCommission,
                'created_by' => $admin->id,
            ]);

            // Attach users to the group
            $group->users()->attach($userIds);

            // Load relationships
            $group->load(['users', 'creator:id,name,email']);

            return response()->json([
                'success' => true,
                'message' => 'Group created successfully',
                'data' => [
                    'id' => $group->id,
                    'name' => $group->name,
                    'total_commission' => $group->total_commission,
                    'created_by' => $group->created_by,
                    'creator' => $group->creator ? [
                        'id' => $group->creator->id,
                        'name' => $group->creator->name,
                        'email' => $group->creator->email,
                    ] : null,
                    'users' => $group->users->map(function ($user) {
                        return [
                            'id' => $user->id,
                            'name' => $user->name,
                            'role' => $user->role,
                            'status' => $user->status,
                        ];
                    }),
                    'created_at' => $group->created_at,
                    'updated_at' => $group->updated_at,
                ],
            ], 201);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Failed to create group',
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    /**
     * Get all groups created by the authenticated admin.
     */
    public function listGroups(Request $request): JsonResponse
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
            // Filter groups to only show those created by this admin
            $groups = Group::with(['users', 'creator:id,name,email'])
                ->where('created_by', $admin->id)
                ->orderBy('created_at', 'desc')
                ->get()
                ->map(function ($group) {
                    return [
                        'id' => $group->id,
                        'name' => $group->name,
                        'total_commission' => $group->total_commission,
                        'created_by' => $group->created_by,
                        'creator' => $group->creator ? [
                            'id' => $group->creator->id,
                            'name' => $group->creator->name,
                            'email' => $group->creator->email,
                        ] : null,
                        'users' => $group->users->map(function ($user) {
                            return [
                                'id' => $user->id,
                                'name' => $user->name,
                                'role' => $user->role,
                                'status' => $user->status,
                            ];
                        }),
                        'user_count' => $group->users->count(),
                        'created_at' => $group->created_at,
                        'updated_at' => $group->updated_at,
                    ];
                });

            return response()->json([
                'success' => true,
                'data' => $groups,
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Failed to fetch groups',
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    /**
     * Update an existing group.
     */
    public function updateGroup(Request $request, int $id): JsonResponse
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
                'name' => 'sometimes|required|string|max:255',
                'user_ids' => 'sometimes|required|array|min:1',
                'user_ids.*' => 'required|integer|exists:users,id',
            ]);
        } catch (ValidationException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $e->errors(),
            ], 422);
        }

        try {
            // Find the group and verify ownership
            $group = Group::where('id', $id)
                ->where('created_by', $admin->id)
                ->first();

            if (!$group) {
                return response()->json([
                    'success' => false,
                    'message' => 'Group not found or you do not have permission to update it.',
                ], 404);
            }

            // Update group name if provided
            if (isset($validated['name'])) {
                $group->name = $validated['name'];
            }

            // Update users if provided
            if (isset($validated['user_ids'])) {
                $userIds = $validated['user_ids'];
                
                // Verify that all user_ids belong to users created by this admin
                $users = User::whereIn('id', $userIds)
                    ->where('created_by', $admin->id)
                    ->get();

                if ($users->count() !== count($userIds)) {
                    return response()->json([
                        'success' => false,
                        'message' => 'Some users not found or you do not have permission to add them to the group.',
                    ], 403);
                }

                // Calculate new total commission (sum of commission percentages only from users who have commission)
                // Exclude users with commission_type = 'no_commission'
                $totalCommission = $users
                    ->where('commission_type', '!=', 'no_commission')
                    ->sum('commission');

                // Update total commission
                $group->total_commission = $totalCommission;

                // Sync users (this will detach old users and attach new ones)
                $group->users()->sync($userIds);
            }

            // Save the group
            $group->save();

            // Load relationships
            $group->load(['users', 'creator:id,name,email']);

            return response()->json([
                'success' => true,
                'message' => 'Group updated successfully',
                'data' => [
                    'id' => $group->id,
                    'name' => $group->name,
                    'total_commission' => $group->total_commission,
                    'created_by' => $group->created_by,
                    'creator' => $group->creator ? [
                        'id' => $group->creator->id,
                        'name' => $group->creator->name,
                        'email' => $group->creator->email,
                    ] : null,
                    'users' => $group->users->map(function ($user) {
                        return [
                            'id' => $user->id,
                            'name' => $user->name,
                            'role' => $user->role,
                            'status' => $user->status,
                        ];
                    }),
                    'created_at' => $group->created_at,
                    'updated_at' => $group->updated_at,
                ],
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Failed to update group',
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    /**
     * Delete a group.
     */
    public function deleteGroup(Request $request, int $id): JsonResponse
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
            // Find the group and verify ownership
            $group = Group::where('id', $id)
                ->where('created_by', $admin->id)
                ->first();

            if (!$group) {
                return response()->json([
                    'success' => false,
                    'message' => 'Group not found or you do not have permission to delete it.',
                ], 404);
            }

            // Delete the group (relationships will be cascade deleted)
            $group->delete();

            return response()->json([
                'success' => true,
                'message' => 'Group deleted successfully',
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Failed to delete group',
                'error' => $e->getMessage(),
            ], 500);
        }
    }
}
