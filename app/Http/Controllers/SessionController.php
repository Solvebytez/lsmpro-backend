<?php

namespace App\Http\Controllers;

use App\Models\Session;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use Illuminate\Validation\ValidationException;

class SessionController extends Controller
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
     * Calculate net profit/loss based on entry run, result, amount, and yes/no.
     */
    private function calculateNetProfitLoss(int $entryRun, ?int $result, float $amount, bool $isYes): float
    {
        if ($result === null) {
            return 0; // No result yet, so no profit/loss
        }

        if ($isYes) {
            // If Yes: profit if result >= entryRun, loss if result < entryRun
            return $result >= $entryRun ? $amount : -$amount;
        } else {
            // If No: profit if result < entryRun, loss if result >= entryRun
            return $result < $entryRun ? $amount : -$amount;
        }
    }

    /**
     * Create a new session entry.
     */
    public function createSession(Request $request): JsonResponse
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
                'user_id' => 'required|integer|exists:users,id',
                'inning_over' => 'required|string|max:255',
                'entry_run' => 'required|integer|min:0',
                'amount' => 'required|numeric|min:0',
                'is_yes' => 'required|boolean',
                'result' => 'nullable|integer|min:0', // Optional
            ]);
        } catch (ValidationException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $e->errors(),
            ], 422);
        }

        try {
            // Calculate net profit/loss
            $netProfitLoss = $this->calculateNetProfitLoss(
                $validated['entry_run'],
                $validated['result'] ?? null,
                $validated['amount'],
                $validated['is_yes']
            );

            // Create the session entry
            $session = Session::create([
                'match_id' => $validated['match_id'],
                'user_id' => $validated['user_id'],
                'inning_over' => $validated['inning_over'],
                'entry_run' => $validated['entry_run'],
                'amount' => $validated['amount'],
                'is_yes' => $validated['is_yes'],
                'result' => $validated['result'] ?? null,
                'net_profit_loss' => $netProfitLoss,
                'created_by' => $admin->id,
            ]);

            // Load relationships
            $session->load(['match.team1', 'match.team2', 'user', 'creator:id,name,email']);

            return response()->json([
                'success' => true,
                'message' => 'Session entry created successfully',
                'data' => [
                    'id' => $session->id,
                    'match_id' => $session->match_id,
                    'match_name' => $session->match ? "{$session->match->team1->name} vs {$session->match->team2->name}" : null,
                    'user_id' => $session->user_id,
                    'user_name' => $session->user ? $session->user->name : null,
                    'inning_over' => $session->inning_over,
                    'entry_run' => $session->entry_run,
                    'amount' => $session->amount,
                    'is_yes' => $session->is_yes,
                    'result' => $session->result,
                    'net_profit_loss' => $session->net_profit_loss,
                    'created_by' => $session->created_by,
                    'creator' => $session->creator ? [
                        'id' => $session->creator->id,
                        'name' => $session->creator->name,
                        'email' => $session->creator->email,
                    ] : null,
                    'created_at' => $session->created_at,
                    'updated_at' => $session->updated_at,
                ],
            ], 201);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Failed to create session entry',
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    /**
     * Get all session entries created by the authenticated admin.
     */
    public function listSessions(Request $request): JsonResponse
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
            // Filter sessions to only show those created by this admin
            $query = Session::with(['match.team1', 'match.team2', 'user', 'creator:id,name,email'])
                ->where('created_by', $admin->id);
            
            // Filter by match_id if provided
            if ($request->has('match_id') && $request->match_id) {
                $query->where('match_id', $request->match_id);
            }
            
            $sessions = $query->orderBy('created_at', 'desc')
                ->get()
                ->map(function ($session) {
                    return [
                        'id' => $session->id,
                        'match_id' => $session->match_id,
                        'match_name' => $session->match ? "{$session->match->team1->name} vs {$session->match->team2->name}" : null,
                        'user_id' => $session->user_id,
                        'user_name' => $session->user ? $session->user->name : null,
                        'inning_over' => $session->inning_over,
                        'entry_run' => $session->entry_run,
                        'amount' => $session->amount,
                        'is_yes' => $session->is_yes,
                        'result' => $session->result,
                        'net_profit_loss' => $session->net_profit_loss,
                        'created_by' => $session->created_by,
                        'creator' => $session->creator ? [
                            'id' => $session->creator->id,
                            'name' => $session->creator->name,
                            'email' => $session->creator->email,
                        ] : null,
                        'created_at' => $session->created_at,
                        'updated_at' => $session->updated_at,
                    ];
                });

            return response()->json([
                'success' => true,
                'data' => $sessions,
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Failed to fetch sessions',
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    /**
     * Update an existing session entry.
     */
    public function updateSession(Request $request, int $id): JsonResponse
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
                'match_id' => 'sometimes|required|integer|exists:matches,id',
                'user_id' => 'sometimes|required|integer|exists:users,id',
                'inning_over' => 'sometimes|required|string|max:255',
                'entry_run' => 'sometimes|required|integer|min:0',
                'amount' => 'sometimes|required|numeric|min:0',
                'is_yes' => 'sometimes|required|boolean',
                'result' => 'nullable|integer|min:0', // Optional
            ]);
        } catch (ValidationException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $e->errors(),
            ], 422);
        }

        try {
            // Find the session entry and verify ownership
            $session = Session::where('id', $id)
                ->where('created_by', $admin->id)
                ->first();

            if (!$session) {
                return response()->json([
                    'success' => false,
                    'message' => 'Session entry not found or you do not have permission to update it.',
                ], 404);
            }

            // Update fields if provided
            if (isset($validated['match_id'])) {
                $session->match_id = $validated['match_id'];
            }
            if (isset($validated['user_id'])) {
                $session->user_id = $validated['user_id'];
            }
            if (isset($validated['inning_over'])) {
                $session->inning_over = $validated['inning_over'];
            }
            if (isset($validated['entry_run'])) {
                $session->entry_run = $validated['entry_run'];
            }
            if (isset($validated['amount'])) {
                $session->amount = $validated['amount'];
            }
            if (isset($validated['is_yes'])) {
                $session->is_yes = $validated['is_yes'];
            }
            if (array_key_exists('result', $validated)) {
                $session->result = $validated['result'];
            }

            // Recalculate net profit/loss if any relevant field changed
            $session->net_profit_loss = $this->calculateNetProfitLoss(
                $session->entry_run,
                $session->result,
                $session->amount,
                $session->is_yes
            );

            // Save the entry
            $session->save();

            // Load relationships
            $session->load(['match.team1', 'match.team2', 'user', 'creator:id,name,email']);

            return response()->json([
                'success' => true,
                'message' => 'Session entry updated successfully',
                'data' => [
                    'id' => $session->id,
                    'match_id' => $session->match_id,
                    'match_name' => $session->match ? "{$session->match->team1->name} vs {$session->match->team2->name}" : null,
                    'user_id' => $session->user_id,
                    'user_name' => $session->user ? $session->user->name : null,
                    'inning_over' => $session->inning_over,
                    'entry_run' => $session->entry_run,
                    'amount' => $session->amount,
                    'is_yes' => $session->is_yes,
                    'result' => $session->result,
                    'net_profit_loss' => $session->net_profit_loss,
                    'created_by' => $session->created_by,
                    'creator' => $session->creator ? [
                        'id' => $session->creator->id,
                        'name' => $session->creator->name,
                        'email' => $session->creator->email,
                    ] : null,
                    'created_at' => $session->created_at,
                    'updated_at' => $session->updated_at,
                ],
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Failed to update session entry',
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    /**
     * Delete a session entry.
     */
    public function deleteSession(Request $request, int $id): JsonResponse
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
            // Find the session entry and verify ownership
            $session = Session::where('id', $id)
                ->where('created_by', $admin->id)
                ->first();

            if (!$session) {
                return response()->json([
                    'success' => false,
                    'message' => 'Session entry not found or you do not have permission to delete it.',
                ], 404);
            }

            // Delete the entry
            $session->delete();

            return response()->json([
                'success' => true,
                'message' => 'Session entry deleted successfully',
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Failed to delete session entry',
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    /**
     * Update result for all session entries matching a specific innings/over.
     * This will update the result and recalculate net_profit_loss for all matching entries.
     */
    public function updateResultByInningsOver(Request $request): JsonResponse
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
                'inning_over' => 'required|string|max:255',
                'result' => 'required|integer|min:0',
            ]);
        } catch (ValidationException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $e->errors(),
            ], 422);
        }

        try {
            // Find all session entries with the specified innings/over created by this admin
            $sessions = Session::where('inning_over', $validated['inning_over'])
                ->where('created_by', $admin->id)
                ->get();

            if ($sessions->isEmpty()) {
                return response()->json([
                    'success' => false,
                    'message' => 'No session entries found for the specified Innings/Over.',
                ], 404);
            }

            $updatedCount = 0;
            $updatedSessions = [];

            // Update each session entry
            foreach ($sessions as $session) {
                // Update the result
                $session->result = $validated['result'];
                
                // Recalculate net profit/loss based on the new result
                $session->net_profit_loss = $this->calculateNetProfitLoss(
                    $session->entry_run,
                    $validated['result'],
                    $session->amount,
                    $session->is_yes
                );
                
                // Save the entry
                $session->save();
                
                $updatedCount++;
                $updatedSessions[] = [
                    'id' => $session->id,
                    'user_id' => $session->user_id,
                    'entry_run' => $session->entry_run,
                    'is_yes' => $session->is_yes,
                    'amount' => $session->amount,
                    'result' => $session->result,
                    'net_profit_loss' => $session->net_profit_loss,
                ];
            }

            return response()->json([
                'success' => true,
                'message' => "Result updated successfully for {$updatedCount} session entry/entries",
                'data' => [
                    'inning_over' => $validated['inning_over'],
                    'result' => $validated['result'],
                    'updated_count' => $updatedCount,
                    'updated_sessions' => $updatedSessions,
                ],
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Failed to update result',
                'error' => $e->getMessage(),
            ], 500);
        }
    }
}
