<?php

namespace App\Http\Controllers;

use App\Models\GameMatch;
use App\Models\ReportRowSelection;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;

class ReportRowSelectionController extends Controller
{
    /**
     * Manually authenticate admin from token to avoid Sanctum recursion issues.
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
                if ($user instanceof \App\Models\Admin) {
                    return $user;
                }
            }
        } catch (\Exception $e) {
            // Return null on auth errors.
        }

        return null;
    }

    private function normalizeContext(array $validated): array
    {
        return [
            'selection_type' => (string) ($validated['selection_type'] ?? ''),
            'selected_group_id' => (int) ($validated['selected_group_id'] ?? 0),
            'inning_over' => (string) ($validated['inning_over'] ?? ''),
            'winning_team_id' => (int) ($validated['winning_team_id'] ?? 0),
        ];
    }

    /**
     * List selected rows for a report context.
     */
    public function listSelections(Request $request): JsonResponse
    {
        $admin = $this->getAuthenticatedAdmin($request);
        if (!$admin) {
            return response()->json([
                'success' => false,
                'message' => 'Unauthenticated. Please login first.',
            ], 401);
        }

        try {
            $validated = $request->validate([
                'report_type' => 'required|in:match,session',
                'match_id' => 'required|integer|exists:matches,id',
                'selection_type' => 'nullable|string|max:20',
                'selected_group_id' => 'nullable|integer|min:0',
                'inning_over' => 'nullable|string|max:50',
                'winning_team_id' => 'nullable|integer|min:0',
            ]);
        } catch (ValidationException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $e->errors(),
            ], 422);
        }

        $match = GameMatch::where('id', $validated['match_id'])
            ->where('created_by', $admin->id)
            ->first();

        if (!$match) {
            return response()->json([
                'success' => false,
                'message' => 'Match not found or you do not have permission to access it.',
            ], 403);
        }

        $context = $this->normalizeContext($validated);

        $rows = ReportRowSelection::query()
            ->where('created_by', $admin->id)
            ->where('report_type', $validated['report_type'])
            ->where('match_id', $validated['match_id'])
            ->where('selection_type', $context['selection_type'])
            ->where('selected_group_id', $context['selected_group_id'])
            ->where('inning_over', $context['inning_over'])
            ->where('winning_team_id', $context['winning_team_id'])
            ->orderBy('id')
            ->get(['id', 'selected_user_id']);

        return response()->json([
            'success' => true,
            'data' => [
                'selected_user_ids' => $rows->pluck('selected_user_id')->map(fn ($id) => (int) $id)->values(),
                'rows' => $rows,
            ],
        ]);
    }

    /**
     * Toggle a single selected row in DB.
     */
    public function toggleSelection(Request $request): JsonResponse
    {
        $admin = $this->getAuthenticatedAdmin($request);
        if (!$admin) {
            return response()->json([
                'success' => false,
                'message' => 'Unauthenticated. Please login first.',
            ], 401);
        }

        try {
            $validated = $request->validate([
                'report_type' => 'required|in:match,session',
                'match_id' => 'required|integer|exists:matches,id',
                'match_date' => 'nullable|date',
                'selected_user_id' => 'required|integer|exists:users,id',
                'is_selected' => 'required|boolean',
                'selection_type' => 'nullable|string|max:20',
                'selected_group_id' => 'nullable|integer|min:0',
                'inning_over' => 'nullable|string|max:50',
                'winning_team_id' => 'nullable|integer|min:0',
            ]);
        } catch (ValidationException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $e->errors(),
            ], 422);
        }

        $match = GameMatch::where('id', $validated['match_id'])
            ->where('created_by', $admin->id)
            ->first();

        if (!$match) {
            return response()->json([
                'success' => false,
                'message' => 'Match not found or you do not have permission to access it.',
            ], 403);
        }

        $selectedUser = User::where('id', $validated['selected_user_id'])
            ->where('created_by', $admin->id)
            ->first();

        if (!$selectedUser) {
            return response()->json([
                'success' => false,
                'message' => 'User not found or you do not have permission to select this user.',
            ], 403);
        }

        $context = $this->normalizeContext($validated);
        $baseWhere = [
            'created_by' => $admin->id,
            'report_type' => $validated['report_type'],
            'match_id' => (int) $validated['match_id'],
            'selected_user_id' => (int) $validated['selected_user_id'],
            'selection_type' => $context['selection_type'],
            'selected_group_id' => $context['selected_group_id'],
            'inning_over' => $context['inning_over'],
            'winning_team_id' => $context['winning_team_id'],
        ];

        if ($validated['is_selected']) {
            $selection = ReportRowSelection::firstOrCreate(
                $baseWhere,
                [
                    'match_date' => $validated['match_date'] ?? $match->match_date,
                ]
            );

            return response()->json([
                'success' => true,
                'message' => 'Row selection saved successfully',
                'data' => [
                    'is_selected' => true,
                    'selection' => $selection,
                ],
            ], 201);
        }

        ReportRowSelection::where($baseWhere)->delete();

        return response()->json([
            'success' => true,
            'message' => 'Row selection removed successfully',
            'data' => [
                'is_selected' => false,
            ],
        ]);
    }

    /**
     * Sync all selected rows for a report context in one call.
     */
    public function syncSelections(Request $request): JsonResponse
    {
        $admin = $this->getAuthenticatedAdmin($request);
        if (!$admin) {
            return response()->json([
                'success' => false,
                'message' => 'Unauthenticated. Please login first.',
            ], 401);
        }

        try {
            $validated = $request->validate([
                'report_type' => 'required|in:match,session',
                'match_id' => 'required|integer|exists:matches,id',
                'match_date' => 'nullable|date',
                'selected_user_ids' => 'required|array',
                'selected_user_ids.*' => 'integer|exists:users,id',
                'selection_type' => 'nullable|string|max:20',
                'selected_group_id' => 'nullable|integer|min:0',
                'inning_over' => 'nullable|string|max:50',
                'winning_team_id' => 'nullable|integer|min:0',
            ]);
        } catch (ValidationException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $e->errors(),
            ], 422);
        }

        $match = GameMatch::where('id', $validated['match_id'])
            ->where('created_by', $admin->id)
            ->first();

        if (!$match) {
            return response()->json([
                'success' => false,
                'message' => 'Match not found or you do not have permission to access it.',
            ], 403);
        }

        $selectedUserIds = array_values(array_unique(array_map('intval', $validated['selected_user_ids'])));
        if (!empty($selectedUserIds)) {
            $allowedCount = User::where('created_by', $admin->id)
                ->whereIn('id', $selectedUserIds)
                ->count();

            if ($allowedCount !== count($selectedUserIds)) {
                return response()->json([
                    'success' => false,
                    'message' => 'One or more selected users are invalid for this admin.',
                ], 403);
            }
        }

        $context = $this->normalizeContext($validated);

        $query = ReportRowSelection::query()
            ->where('created_by', $admin->id)
            ->where('report_type', $validated['report_type'])
            ->where('match_id', $validated['match_id'])
            ->where('selection_type', $context['selection_type'])
            ->where('selected_group_id', $context['selected_group_id'])
            ->where('inning_over', $context['inning_over'])
            ->where('winning_team_id', $context['winning_team_id']);

        if (empty($selectedUserIds)) {
            $query->delete();

            return response()->json([
                'success' => true,
                'message' => 'Selections synced successfully',
                'data' => [
                    'selected_user_ids' => [],
                ],
            ]);
        }

        $query->whereNotIn('selected_user_id', $selectedUserIds)->delete();

        foreach ($selectedUserIds as $userId) {
            ReportRowSelection::firstOrCreate(
                [
                    'created_by' => $admin->id,
                    'report_type' => $validated['report_type'],
                    'match_id' => (int) $validated['match_id'],
                    'selected_user_id' => $userId,
                    'selection_type' => $context['selection_type'],
                    'selected_group_id' => $context['selected_group_id'],
                    'inning_over' => $context['inning_over'],
                    'winning_team_id' => $context['winning_team_id'],
                ],
                [
                    'match_date' => $validated['match_date'] ?? $match->match_date,
                ]
            );
        }

        return response()->json([
            'success' => true,
            'message' => 'Selections synced successfully',
            'data' => [
                'selected_user_ids' => $selectedUserIds,
            ],
        ]);
    }
}

