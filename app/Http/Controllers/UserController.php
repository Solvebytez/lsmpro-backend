<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Models\Group;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;

class UserController extends Controller
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
     * Create a new user (only admin can create users).
     */
    public function createUser(Request $request): JsonResponse
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
                'role' => 'required|string|in:user,admin,manager,editor,viewer',
                'commission' => 'required_if:commission_type,profit_loss,entrywise|numeric|min:0|max:100',
                'partnership' => 'required|numeric|min:0|max:100',
                'commission_type' => 'required|string|in:no_commission,profit_loss,entrywise',
                'session_commission' => 'required_if:session_commission_type,profit_loss,entrywise|numeric|min:0|max:100',
                'session_commission_type' => 'required|string|in:no_commission,profit_loss,entrywise',
                'group_id' => 'nullable|integer|exists:groups,id',
                'mark_as_cut' => 'nullable|string|in:no,yes',
            ]);
        } catch (ValidationException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $e->errors(),
            ], 422);
        }

        try {
            // Validate group assignment if group_id is provided
            if (isset($validated['group_id']) && $validated['group_id']) {
                // Verify the group exists and belongs to this admin
                $group = Group::where('id', $validated['group_id'])
                    ->where('created_by', $admin->id)
                    ->first();
                
                if (!$group) {
                    return response()->json([
                        'success' => false,
                        'message' => 'Group not found or you do not have permission to assign users to this group.',
                    ], 403);
                }
            }
            
            // Set commission to 0 if no_commission is selected, partnership always uses the value
            $commission = $validated['commission_type'] === 'no_commission' ? 0 : ($validated['commission'] ?? 0);
            $sessionCommission = $validated['session_commission_type'] === 'no_commission' ? 0 : ($validated['session_commission'] ?? 0);
            
            // Create the user
            $user = User::create([
                'name' => $validated['name'],
                'email' => null, // No longer required
                'mobile' => null, // No longer required
                'password' => null, // No longer required
                'role' => $validated['role'],
                'commission' => $commission,
                'partnership' => $validated['partnership'],
                'commission_type' => $validated['commission_type'],
                'session_commission' => $sessionCommission,
                'session_commission_type' => $validated['session_commission_type'],
                'status' => 'active', // Default status
                'created_by' => $admin->id, // Track which admin created this user
                'mark_as_cut' => $validated['mark_as_cut'] ?? 'no', // Default to 'no'
            ]);

            // Assign user to group if group_id is provided
            if (isset($validated['group_id']) && $validated['group_id']) {
                // For new users, check if they're already in any group (shouldn't happen, but safety check)
                $existingGroups = $user->groups()->where('groups.id', '!=', $validated['group_id'])->get();
                if ($existingGroups->count() > 0) {
                    $existingGroupNames = $existingGroups->pluck('name')->join(', ');
                    return response()->json([
                        'success' => false,
                        'message' => "User is already assigned to group(s): {$existingGroupNames}. Please remove the user from the existing group(s) first.",
                    ], 422);
                }
                
                // Check if user is already in the target group
                $isAlreadyInGroup = $user->groups()->where('groups.id', $validated['group_id'])->exists();
                if (!$isAlreadyInGroup) {
                    // Attach user to the group
                    $user->groups()->attach($validated['group_id']);
                }
            }

            // Reload relationships to get groups if assigned
            $user->load(['creator:id,name,email', 'groups']);

            // Prepare response data
            $responseData = [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
                'mobile' => $user->mobile,
                'role' => $user->role,
                'commission' => $user->commission,
                'partnership' => $user->partnership,
                'commission_type' => $user->commission_type,
                'session_commission' => $user->session_commission,
                'session_commission_type' => $user->session_commission_type,
                'status' => $user->status,
                'created_by' => $user->created_by,
                'mark_as_cut' => $user->mark_as_cut ?? 'no',
                'creator' => $user->creator ? [
                    'id' => $user->creator->id,
                    'name' => $user->creator->name,
                    'email' => $user->creator->email,
                ] : null,
                'group_id' => $user->groups->first()?->id ?? null,
                'groups' => $user->groups->map(function ($group) {
                    return [
                        'id' => $group->id,
                        'name' => $group->name,
                    ];
                })->toArray(),
                'created_at' => $user->created_at,
                'updated_at' => $user->updated_at,
            ];

            return response()->json([
                'success' => true,
                'message' => 'User created successfully',
                'data' => $responseData,
            ], 201);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Failed to create user',
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    /**
     * Get all users created by the authenticated admin.
     * Each admin can only see users they created.
     */
    public function listUsers(Request $request): JsonResponse
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
            // Filter users to only show those created by this admin
            $users = User::with(['creator:id,name,email', 'groups'])
                ->where('created_by', $admin->id) // Only show users created by this admin
                ->select([
                    'id',
                    'name',
                    'email',
                    'mobile',
                    'role',
                    'commission',
                    'partnership',
                    'commission_type',
                    'session_commission',
                    'session_commission_type',
                    'last_login',
                    'status',
                    'created_by',
                    'mark_as_cut',
                    'created_at',
                    'updated_at',
                ])
                ->orderBy('created_at', 'desc')
                ->get()
                ->map(function ($user) {
                    $userArray = $user->toArray();
                    // Add group_id from the first group (since user can only be in one group)
                    $userArray['group_id'] = $user->groups->first()?->id ?? null;
                    // Ensure groups array is included with id and name
                    $userArray['groups'] = $user->groups->map(function ($group) {
                        return [
                            'id' => $group->id,
                            'name' => $group->name,
                        ];
                    })->toArray();
                    return $userArray;
                });

            return response()->json([
                'success' => true,
                'data' => $users,
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Failed to fetch users',
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    /**
     * Update user status (only admin can update status of users they created).
     */
    public function updateStatus(Request $request, $id): JsonResponse
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
            // Validate request data
            $validated = $request->validate([
                'status' => 'required|string|in:active,inactive',
            ]);
        } catch (ValidationException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $e->errors(),
            ], 422);
        }

        try {
            // Find the user - only allow updating users created by this admin
            $user = User::where('id', $id)
                ->where('created_by', $admin->id)
                ->first();

            if (!$user) {
                return response()->json([
                    'success' => false,
                    'message' => 'User not found or you do not have permission to update this user.',
                ], 404);
            }

            // Update status
            $user->status = $validated['status'];
            $user->save();

            return response()->json([
                'success' => true,
                'message' => 'User status updated successfully',
                'data' => [
                    'id' => $user->id,
                    'name' => $user->name,
                    'email' => $user->email,
                    'status' => $user->status,
                ],
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Failed to update user status',
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    /**
     * Update a user (only admin can update users they created).
     */
    public function updateUser(Request $request, $id): JsonResponse
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
                'role' => 'sometimes|required|string|in:user,admin,manager,editor,viewer',
                'commission' => 'required_if:commission_type,profit_loss,entrywise|numeric|min:0|max:100',
                'partnership' => 'sometimes|required|numeric|min:0|max:100',
                'commission_type' => 'sometimes|required|string|in:no_commission,profit_loss,entrywise',
                'session_commission' => 'nullable|numeric|min:0|max:100',
                'session_commission_type' => 'sometimes|required|string|in:no_commission,profit_loss,entrywise',
                'group_id' => 'nullable|integer|exists:groups,id',
                'mark_as_cut' => 'nullable|string|in:no,yes',
            ]);
        } catch (ValidationException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $e->errors(),
            ], 422);
        }

        try {
            // Find the user - only allow updating users created by this admin
            $user = User::where('id', $id)
                ->where('created_by', $admin->id)
                ->first();

            if (!$user) {
                return response()->json([
                    'success' => false,
                    'message' => 'User not found or you do not have permission to update this user.',
                ], 404);
            }

            // Update only provided fields
            if (isset($validated['name'])) {
                $user->name = $validated['name'];
            }
            if (isset($validated['role'])) {
                $user->role = $validated['role'];
            }
            if (isset($validated['commission_type'])) {
                $user->commission_type = $validated['commission_type'];
                // Set commission to 0 if no_commission is selected
                if ($validated['commission_type'] === 'no_commission') {
                    $user->commission = 0;
                } elseif (isset($validated['commission'])) {
                    $user->commission = $validated['commission'];
                }
            } elseif (isset($validated['commission'])) {
                // Only update commission if commission_type is not no_commission
                if ($user->commission_type !== 'no_commission') {
                    $user->commission = $validated['commission'];
                }
            }
            if (isset($validated['partnership'])) {
                $user->partnership = $validated['partnership'];
            }
            if (isset($validated['mark_as_cut'])) {
                $user->mark_as_cut = $validated['mark_as_cut'];
            }
            if (isset($validated['session_commission_type'])) {
                $user->session_commission_type = $validated['session_commission_type'];
                // Set session_commission to 0 if no_commission is selected
                if ($validated['session_commission_type'] === 'no_commission') {
                    $user->session_commission = 0;
                } elseif (isset($validated['session_commission']) && $validated['session_commission'] !== null) {
                    // Update session_commission if provided
                    $user->session_commission = $validated['session_commission'];
                }
                // If session_commission_type is not 'no_commission' but session_commission is not provided,
                // keep the existing value (don't reset to 0)
            } elseif (isset($validated['session_commission']) && $validated['session_commission'] !== null) {
                // Only update session_commission if session_commission_type is not no_commission
                if ($user->session_commission_type !== 'no_commission') {
                    $user->session_commission = $validated['session_commission'];
                }
            }

            $user->save();
            
            // Handle group assignment if group_id is provided
            if (isset($validated['group_id'])) {
                $newGroupId = $validated['group_id'] ? (int)$validated['group_id'] : null;
                
                if ($newGroupId) {
                    // Verify the group exists and belongs to this admin
                    $group = Group::where('id', $newGroupId)
                        ->where('created_by', $admin->id)
                        ->first();
                    
                    if (!$group) {
                        return response()->json([
                            'success' => false,
                            'message' => 'Group not found or you do not have permission to assign users to this group.',
                        ], 403);
                    }
                    
                    // Check if user is already in this group
                    $isAlreadyInGroup = $user->groups()->where('groups.id', $newGroupId)->exists();
                    
                    if (!$isAlreadyInGroup) {
                        // First, detach user from all existing groups (to allow changing groups)
                        $user->groups()->detach();
                        
                        // Then attach user to the new group
                        $user->groups()->attach($newGroupId);
                    }
                    // If user is already in this group, no action needed
                } else {
                    // If group_id is null, remove user from all groups
                    $user->groups()->detach();
                }
            }

            // Reload relationships to get updated groups
            $user->load(['creator:id,name,email', 'groups']);

            // Prepare response data
            $responseData = [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
                'mobile' => $user->mobile,
                'role' => $user->role,
                'commission' => $user->commission,
                'partnership' => $user->partnership,
                'commission_type' => $user->commission_type,
                'session_commission' => $user->session_commission,
                'session_commission_type' => $user->session_commission_type,
                'status' => $user->status,
                'created_by' => $user->created_by,
                'mark_as_cut' => $user->mark_as_cut ?? 'no',
                'creator' => $user->creator ? [
                    'id' => $user->creator->id,
                    'name' => $user->creator->name,
                    'email' => $user->creator->email,
                ] : null,
                'group_id' => $user->groups->first()?->id ?? null,
                'groups' => $user->groups->map(function ($group) {
                    return [
                        'id' => $group->id,
                        'name' => $group->name,
                    ];
                })->toArray(),
                'created_at' => $user->created_at,
                'updated_at' => $user->updated_at,
            ];

            return response()->json([
                'success' => true,
                'message' => 'User updated successfully',
                'data' => $responseData,
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Failed to update user',
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    /**
     * Delete a user (only admin can delete users they created).
     */
    public function deleteUser(Request $request, $id): JsonResponse
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
            // Find the user - only allow deleting users created by this admin
            $user = User::where('id', $id)
                ->where('created_by', $admin->id)
                ->first();

            if (!$user) {
                return response()->json([
                    'success' => false,
                    'message' => 'User not found or you do not have permission to delete this user.',
                ], 404);
            }

            // Store user name for success message
            $userName = $user->name;

            // Delete the user
            $user->delete();

            return response()->json([
                'success' => true,
                'message' => "User '{$userName}' deleted successfully",
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Failed to delete user',
                'error' => $e->getMessage(),
            ], 500);
        }
    }
}

