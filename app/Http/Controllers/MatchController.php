<?php

namespace App\Http\Controllers;

use App\Models\GameMatch;
use App\Models\Team;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use Illuminate\Validation\ValidationException;

class MatchController extends Controller
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
     * Create a new match.
     */
    public function createMatch(Request $request): JsonResponse
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
                'team1_id' => 'required|integer|exists:teams,id',
                'team2_id' => 'required|integer|exists:teams,id|different:team1_id',
                'match_date' => 'required|date',
            ]);
        } catch (ValidationException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $e->errors(),
            ], 422);
        }

        // Verify both teams are created by this admin
        $team1 = Team::where('id', $validated['team1_id'])
            ->where('created_by', $admin->id)
            ->first();
        
        $team2 = Team::where('id', $validated['team2_id'])
            ->where('created_by', $admin->id)
            ->first();

        if (!$team1 || !$team2) {
            return response()->json([
                'success' => false,
                'message' => 'One or both teams not found or you do not have permission to use them.',
            ], 403);
        }

        try {
            // Create match
            $match = GameMatch::create([
                'team1_id' => $validated['team1_id'],
                'team2_id' => $validated['team2_id'],
                'match_date' => $validated['match_date'],
                'status' => 'scheduled',
                'created_by' => $admin->id,
            ]);

            // Load relationships
            $match->load([
                'team1:id,name,logo,status',
                'team2:id,name,logo,status',
                'creator:id,name,email'
            ]);

            return response()->json([
                'success' => true,
                'message' => 'Match created successfully',
                'data' => [
                    'id' => $match->id,
                    'team1_id' => $match->team1_id,
                    'team2_id' => $match->team2_id,
                    'team1' => [
                        'id' => $match->team1->id,
                        'name' => $match->team1->name,
                        'logo' => $match->team1->logo_url ?? null,
                    ],
                    'team2' => [
                        'id' => $match->team2->id,
                        'name' => $match->team2->name,
                        'logo' => $match->team2->logo_url ?? null,
                    ],
                    'match_between' => $match->match_between,
                    'match_date' => $match->match_date->format('Y-m-d'),
                    'winner_id' => $match->winner_id,
                    'status' => $match->status,
                    'created_by' => $match->created_by,
                    'creator' => $match->creator ? [
                        'id' => $match->creator->id,
                        'name' => $match->creator->name,
                        'email' => $match->creator->email,
                    ] : null,
                    'created_at' => $match->created_at,
                    'updated_at' => $match->updated_at,
                ],
            ], 201);
        } catch (\Exception $e) {
            \Log::error('Failed to create match', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Failed to create match',
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    /**
     * Get all matches created by the current admin.
     */
    public function listMatches(Request $request): JsonResponse
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
            // Build query for matches created by this admin
            $query = GameMatch::with([
                'team1.logoImage',
                'team2.logoImage',
                'winner',
                'creator'
            ])
                ->where('created_by', $admin->id); // Only show matches created by this admin
            
            // Filter by date if provided (format: YYYY-MM-DD)
            if ($request->has('date') && $request->date) {
                $query->whereDate('match_date', $request->date);
            }
            
            $matches = $query
                ->orderBy('match_date', 'desc')
                ->orderBy('created_at', 'desc')
                ->get()
                ->map(function ($match) {
                    try {
                        return [
                            'id' => $match->id,
                            'team1_id' => $match->team1_id,
                            'team2_id' => $match->team2_id,
                            'team1' => $match->team1 ? [
                                'id' => $match->team1->id,
                                'name' => $match->team1->name,
                                'logo' => $match->team1->logo_url ?? null,
                            ] : null,
                            'team2' => $match->team2 ? [
                                'id' => $match->team2->id,
                                'name' => $match->team2->name,
                                'logo' => $match->team2->logo_url ?? null,
                            ] : null,
                            'match_between' => ($match->team1 ? ($match->team1->name ?? 'Unknown') : 'Unknown') . ' vs ' . ($match->team2 ? ($match->team2->name ?? 'Unknown') : 'Unknown'),
                            'match_date' => $match->match_date ? $match->match_date->format('Y-m-d') : null,
                            'winner_id' => $match->winner_id,
                            'winner' => $match->winner ? [
                                'id' => $match->winner->id,
                                'name' => $match->winner->name,
                            ] : null,
                            'status' => $match->status,
                            'created_by' => $match->created_by,
                            'creator' => $match->creator ? [
                                'id' => $match->creator->id,
                                'name' => $match->creator->name,
                                'email' => $match->creator->email,
                            ] : null,
                            'created_at' => $match->created_at,
                            'updated_at' => $match->updated_at,
                        ];
                    } catch (\Exception $e) {
                        \Log::error('Error mapping match', [
                            'match_id' => $match->id ?? 'unknown',
                            'error' => $e->getMessage(),
                            'trace' => $e->getTraceAsString(),
                        ]);
                        throw $e;
                    }
                });

            return response()->json([
                'success' => true,
                'data' => $matches,
            ], 200);
        } catch (\Exception $e) {
            \Log::error('Failed to list matches', [
                'error' => $e->getMessage(),
                'file' => $e->getFile(),
                'line' => $e->getLine(),
                'trace' => $e->getTraceAsString(),
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Failed to fetch matches',
                'error' => $e->getMessage(),
                'file' => $e->getFile(),
                'line' => $e->getLine(),
            ], 500);
        }
    }

    /**
     * Get a single match by ID.
     */
    public function getMatch(Request $request, $id): JsonResponse
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
            // Get match and verify it belongs to this admin
            $match = GameMatch::with([
                'team1.logoImage',
                'team2.logoImage',
                'winner',
                'creator'
            ])
                ->where('id', $id)
                ->where('created_by', $admin->id) // Only show matches created by this admin
                ->first();

            if (!$match) {
                return response()->json([
                    'success' => false,
                    'message' => 'Match not found or you do not have permission to view it.',
                ], 404);
            }

            $matchData = [
                'id' => $match->id,
                'team1_id' => $match->team1_id,
                'team2_id' => $match->team2_id,
                'team1' => $match->team1 ? [
                    'id' => $match->team1->id,
                    'name' => $match->team1->name,
                    'logo' => $match->team1->logo_url ?? null,
                ] : null,
                'team2' => $match->team2 ? [
                    'id' => $match->team2->id,
                    'name' => $match->team2->name,
                    'logo' => $match->team2->logo_url ?? null,
                ] : null,
                'match_between' => ($match->team1 ? ($match->team1->name ?? 'Unknown') : 'Unknown') . ' vs ' . ($match->team2 ? ($match->team2->name ?? 'Unknown') : 'Unknown'),
                'match_date' => $match->match_date ? $match->match_date->format('Y-m-d') : null,
                'winner_id' => $match->winner_id,
                'winner' => $match->winner ? [
                    'id' => $match->winner->id,
                    'name' => $match->winner->name,
                ] : null,
                'status' => $match->status,
                'created_by' => $match->created_by,
                'creator' => $match->creator ? [
                    'id' => $match->creator->id,
                    'name' => $match->creator->name,
                    'email' => $match->creator->email,
                ] : null,
                'created_at' => $match->created_at,
                'updated_at' => $match->updated_at,
            ];

            return response()->json([
                'success' => true,
                'data' => $matchData,
            ], 200);
        } catch (\Exception $e) {
            \Log::error('Failed to get match', [
                'error' => $e->getMessage(),
                'file' => $e->getFile(),
                'line' => $e->getLine(),
                'trace' => $e->getTraceAsString(),
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Failed to fetch match',
                'error' => $e->getMessage(),
            ], 500);
        }
    }
}
