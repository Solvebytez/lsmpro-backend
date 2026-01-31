<?php

namespace App\Http\Controllers;

use App\Models\Entry;
use App\Models\GameMatch;
use App\Models\User;
use App\Models\Group;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use Illuminate\Validation\ValidationException;

class EntryController extends Controller
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
     * Create a new entry.
     */
    public function createEntry(Request $request): JsonResponse
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
                'match_id' => 'required|integer|exists:matches,id',
                'user_scope' => 'required|in:all,customer,group',
                'user_id' => 'required_if:user_scope,customer|nullable|integer|exists:users,id',
                'group_id' => 'required_if:user_scope,group|nullable|integer|exists:groups,id',
                'favourite_team' => 'required|in:team1,team2',
                'team1_rate' => 'nullable|numeric|min:0',
                'team1_amount' => 'nullable|numeric|min:0',
                'team2_rate' => 'nullable|numeric|min:0',
                'team2_amount' => 'nullable|numeric|min:0',
            ]);
        } catch (ValidationException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $e->errors(),
            ], 422);
        }

        // Verify match belongs to this admin
        $match = GameMatch::where('id', $validated['match_id'])
            ->where('created_by', $admin->id)
            ->first();

        if (!$match) {
            return response()->json([
                'success' => false,
                'message' => 'Match not found or you do not have permission to create entries for it.',
            ], 403);
        }

        // Validate that at least one team has both rate and amount
        $hasTeam1Bet = !is_null($validated['team1_rate']) && !is_null($validated['team1_amount']);
        $hasTeam2Bet = !is_null($validated['team2_rate']) && !is_null($validated['team2_amount']);

        if (!$hasTeam1Bet && !$hasTeam2Bet) {
            return response()->json([
                'success' => false,
                'message' => 'At least one team must have both rate and amount.',
            ], 422);
        }

        // Verify user or group belongs to this admin based on user_scope
        if ($validated['user_scope'] === 'customer') {
            // Individual user entry
            $user = User::where('id', $validated['user_id'])
                ->where('created_by', $admin->id)
                ->first();

            if (!$user) {
                return response()->json([
                    'success' => false,
                    'message' => 'User not found or you do not have permission to create entries for this user.',
                ], 403);
            }
            $validated['group_id'] = null;
        } elseif ($validated['user_scope'] === 'group') {
            // Group entry
            $group = Group::where('id', $validated['group_id'])
                ->where('created_by', $admin->id)
                ->first();

            if (!$group) {
                return response()->json([
                    'success' => false,
                    'message' => 'Group not found or you do not have permission to create entries for this group.',
                ], 403);
            }
            $validated['user_id'] = null;
        } else {
            // All user entry - both user_id and group_id should be null
            $validated['user_id'] = null;
            $validated['group_id'] = null;
        }

        try {
            // Create entry
            $entry = Entry::create([
                'match_id' => $validated['match_id'],
                'user_scope' => $validated['user_scope'],
                'user_id' => $validated['user_id'] ?? null,
                'group_id' => $validated['group_id'] ?? null,
                'favourite_team' => $validated['favourite_team'],
                'team1_rate' => $validated['team1_rate'] ?? null,
                'team1_amount' => $validated['team1_amount'] ?? null,
                'team2_rate' => $validated['team2_rate'] ?? null,
                'team2_amount' => $validated['team2_amount'] ?? null,
                'created_by' => $admin->id,
            ]);

            // Load relationships
            $entry->load([
                'match.team1',
                'match.team2',
                'user',
                'group',
                'creator'
            ]);

            return response()->json([
                'success' => true,
                'message' => 'Entry created successfully',
                'data' => $this->formatEntry($entry),
            ], 201);
        } catch (\Exception $e) {
            \Log::error('Failed to create entry', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Failed to create entry',
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    /**
     * Get all entries for a match.
     */
    public function listEntries(Request $request, $matchId): JsonResponse
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
            // Verify match belongs to this admin
            $match = GameMatch::where('id', $matchId)
                ->where('created_by', $admin->id)
                ->first();

            if (!$match) {
                return response()->json([
                    'success' => false,
                    'message' => 'Match not found or you do not have permission to view entries for it.',
                ], 404);
            }

            // Get entries for this match
            $entries = Entry::with([
                'user',
                'group',
                'creator'
            ])
                ->where('match_id', $matchId)
                ->orderBy('created_at', 'desc')
                ->get()
                ->map(function ($entry) {
                    return $this->formatEntry($entry);
                });

            return response()->json([
                'success' => true,
                'data' => $entries,
            ], 200);
        } catch (\Exception $e) {
            \Log::error('Failed to list entries', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Failed to fetch entries',
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    /**
     * Get a single entry by ID.
     */
    public function getEntry(Request $request, $id): JsonResponse
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
            // Get entry and verify it belongs to this admin's match
            $entry = Entry::with([
                'match.team1',
                'match.team2',
                'user',
                'group',
                'creator'
            ])
                ->where('id', $id)
                ->whereHas('match', function ($query) use ($admin) {
                    $query->where('created_by', $admin->id);
                })
                ->first();

            if (!$entry) {
                return response()->json([
                    'success' => false,
                    'message' => 'Entry not found or you do not have permission to view it.',
                ], 404);
            }

            return response()->json([
                'success' => true,
                'data' => $this->formatEntry($entry),
            ], 200);
        } catch (\Exception $e) {
            \Log::error('Failed to get entry', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Failed to fetch entry',
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    /**
     * Update an entry.
     */
    public function updateEntry(Request $request, $id): JsonResponse
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
                'favourite_team' => 'sometimes|in:team1,team2',
                'team1_rate' => 'nullable|numeric|min:0',
                'team1_amount' => 'nullable|numeric|min:0',
                'team2_rate' => 'nullable|numeric|min:0',
                'team2_amount' => 'nullable|numeric|min:0',
            ]);
        } catch (ValidationException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $e->errors(),
            ], 422);
        }

        try {
            // Get entry and verify it belongs to this admin's match
            $entry = Entry::where('id', $id)
                ->whereHas('match', function ($query) use ($admin) {
                    $query->where('created_by', $admin->id);
                })
                ->first();

            if (!$entry) {
                return response()->json([
                    'success' => false,
                    'message' => 'Entry not found or you do not have permission to update it.',
                ], 404);
            }

            // Validate that at least one team has both rate and amount
            $team1Rate = $validated['team1_rate'] ?? $entry->team1_rate;
            $team1Amount = $validated['team1_amount'] ?? $entry->team1_amount;
            $team2Rate = $validated['team2_rate'] ?? $entry->team2_rate;
            $team2Amount = $validated['team2_amount'] ?? $entry->team2_amount;

            $hasTeam1Bet = !is_null($team1Rate) && !is_null($team1Amount);
            $hasTeam2Bet = !is_null($team2Rate) && !is_null($team2Amount);

            if (!$hasTeam1Bet && !$hasTeam2Bet) {
                return response()->json([
                    'success' => false,
                    'message' => 'At least one team must have both rate and amount.',
                ], 422);
            }

            // Update entry
            $entry->update($validated);

            // Load relationships
            $entry->load([
                'match.team1',
                'match.team2',
                'user',
                'group',
                'creator'
            ]);

            return response()->json([
                'success' => true,
                'message' => 'Entry updated successfully',
                'data' => $this->formatEntry($entry),
            ], 200);
        } catch (\Exception $e) {
            \Log::error('Failed to update entry', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Failed to update entry',
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    /**
     * Delete an entry.
     */
    public function deleteEntry(Request $request, $id): JsonResponse
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
            // Get entry and verify it belongs to this admin's match
            $entry = Entry::where('id', $id)
                ->whereHas('match', function ($query) use ($admin) {
                    $query->where('created_by', $admin->id);
                })
                ->first();

            if (!$entry) {
                return response()->json([
                    'success' => false,
                    'message' => 'Entry not found or you do not have permission to delete it.',
                ], 404);
            }

            $entry->delete();

            return response()->json([
                'success' => true,
                'message' => 'Entry deleted successfully',
            ], 200);
        } catch (\Exception $e) {
            \Log::error('Failed to delete entry', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Failed to delete entry',
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    /**
     * Format entry for API response.
     */
    private function formatEntry(Entry $entry): array
    {
        // Determine customer name based on user_scope
        $customer = null;
        if ($entry->user_scope === 'customer' && $entry->user_id) {
            $customer = $entry->user ? $entry->user->name : 'Unknown';
        } elseif ($entry->user_scope === 'group' && $entry->group_id) {
            $customer = $entry->group ? $entry->group->name : 'Unknown';
        } elseif ($entry->user_scope === 'all') {
            $customer = 'All Users';
        }

        // Format team values based on favourite_team
        $team1Fav = null;
        $team1Nfav = null;
        $team2Fav = null;
        $team2Nfav = null;

        if ($entry->favourite_team === 'team1') {
            // Team 1 is favorite
            $team1Fav = $entry->team1_rate && $entry->team1_amount 
                ? $entry->team1_rate . '/' . number_format($entry->team1_amount, 0, '.', '') 
                : '0/0000';
            $team1Nfav = $entry->team1_rate && $entry->team1_amount ? '0' : '0';
            $team2Fav = $entry->team2_rate && $entry->team2_amount ? '0' : '0';
            $team2Nfav = $entry->team2_rate && $entry->team2_amount 
                ? $entry->team2_rate . '/' . number_format($entry->team2_amount, 0, '.', '') 
                : '0/0000';
        } else {
            // Team 2 is favorite
            $team1Fav = $entry->team1_rate && $entry->team1_amount ? '0' : '0';
            $team1Nfav = $entry->team1_rate && $entry->team1_amount 
                ? $entry->team1_rate . '/' . number_format($entry->team1_amount, 0, '.', '') 
                : '0/0000';
            $team2Fav = $entry->team2_rate && $entry->team2_amount 
                ? $entry->team2_rate . '/' . number_format($entry->team2_amount, 0, '.', '') 
                : '0/0000';
            $team2Nfav = $entry->team2_rate && $entry->team2_amount ? '0' : '0';
        }

        return [
            'id' => $entry->id,
            'match_id' => $entry->match_id,
            'user_scope' => $entry->user_scope,
            'user_id' => $entry->user_id,
            'group_id' => $entry->group_id,
            'customer' => $customer,
            'favourite_team' => $entry->favourite_team,
            'team1_rate' => $entry->team1_rate,
            'team1_amount' => $entry->team1_amount,
            'team2_rate' => $entry->team2_rate,
            'team2_amount' => $entry->team2_amount,
            // Formatted values for display
            'team1Fav' => $team1Fav,
            'team1Nfav' => $team1Nfav,
            'team2Fav' => $team2Fav,
            'team2Nfav' => $team2Nfav,
            'created_by' => $entry->created_by,
            'created_at' => $entry->created_at ? $entry->created_at->format('Y-m-d H:i:s') : null,
            'updated_at' => $entry->updated_at ? $entry->updated_at->format('Y-m-d H:i:s') : null,
        ];
    }
}
