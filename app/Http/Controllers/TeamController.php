<?php

namespace App\Http\Controllers;

use App\Models\Team;
use App\Models\Image;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Storage;
use Illuminate\Validation\ValidationException;

class TeamController extends Controller
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
     * Create a new team with logo upload.
     */
    public function createTeam(Request $request): JsonResponse
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
                'name' => 'required|string|max:255|unique:teams,name',
                'logo' => 'required|image|mimes:jpeg,png,jpg,gif,webp|max:2048', // 2MB max
            ]);
        } catch (ValidationException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $e->errors(),
            ], 422);
        }

        try {
            // Handle file upload
            $logoFile = $request->file('logo');
            $logoPath = $logoFile->store('teams/logos', 'public');
            
            // Create the team
            $team = Team::create([
                'name' => $validated['name'],
                'logo' => $logoPath, // Store path for backward compatibility
                'status' => 'active', // Default status
                'created_by' => $admin->id, // Track which admin created this team
            ]);

            // Create image record in images table
            $image = Image::create([
                'file_path' => $logoPath,
                'file_name' => $logoFile->getClientOriginalName(),
                'mime_type' => $logoFile->getMimeType(),
                'file_size' => $logoFile->getSize(),
                'imageable_id' => $team->id,
                'imageable_type' => Team::class,
                'created_by' => $admin->id, // Track which admin uploaded this image
            ]);

            // Load the image and creator relationships
            $team->load(['logoImage.creator:id,name,email', 'creator:id,name,email']);

            return response()->json([
                'success' => true,
                'message' => 'Team created successfully',
                'data' => [
                    'id' => $team->id,
                    'name' => $team->name,
                    'logo' => $team->logo_url,
                    'status' => $team->status,
                    'created_by' => $team->created_by,
                    'creator' => $team->creator ? [
                        'id' => $team->creator->id,
                        'name' => $team->creator->name,
                        'email' => $team->creator->email,
                    ] : null,
                    'logo_image' => $image ? [
                        'id' => $image->id,
                        'file_path' => $image->file_path,
                        'file_name' => $image->file_name,
                        'mime_type' => $image->mime_type,
                        'file_size' => $image->file_size,
                        'created_by' => $image->created_by,
                        'uploader' => $image->creator ? [
                            'id' => $image->creator->id,
                            'name' => $image->creator->name,
                            'email' => $image->creator->email,
                        ] : null,
                        'url' => asset('storage/' . $image->file_path),
                    ] : null,
                    'created_at' => $team->created_at,
                    'updated_at' => $team->updated_at,
                ],
            ], 201);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Failed to create team',
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    /**
     * Get all teams.
     */
    public function listTeams(Request $request): JsonResponse
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
            // Filter teams to only show those created by this admin
            $teams = Team::with(['logoImage.creator:id,name,email', 'creator:id,name,email'])
                ->where('created_by', $admin->id) // Only show teams created by this admin
                ->select([
                    'id',
                    'name',
                    'logo',
                    'status',
                    'created_by',
                    'created_at',
                    'updated_at',
                ])
                ->orderBy('created_at', 'desc')
                ->get()
                ->map(function ($team) {
                    return [
                        'id' => $team->id,
                        'name' => $team->name,
                        'logo' => $team->logo_url,
                        'status' => $team->status,
                        'created_by' => $team->created_by,
                        'creator' => $team->creator ? [
                            'id' => $team->creator->id,
                            'name' => $team->creator->name,
                            'email' => $team->creator->email,
                        ] : null,
                        'logo_image' => $team->logoImage ? [
                            'id' => $team->logoImage->id,
                            'file_path' => $team->logoImage->file_path,
                            'file_name' => $team->logoImage->file_name,
                            'mime_type' => $team->logoImage->mime_type,
                            'file_size' => $team->logoImage->file_size,
                            'created_by' => $team->logoImage->created_by,
                            'uploader' => $team->logoImage->creator ? [
                                'id' => $team->logoImage->creator->id,
                                'name' => $team->logoImage->creator->name,
                                'email' => $team->logoImage->creator->email,
                            ] : null,
                            'url' => asset('storage/' . $team->logoImage->file_path),
                        ] : null,
                        'created_at' => $team->created_at,
                        'updated_at' => $team->updated_at,
                    ];
                });

            return response()->json([
                'success' => true,
                'data' => $teams,
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Failed to fetch teams',
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    /**
     * Update a team.
     */
    public function updateTeam(Request $request, $id): JsonResponse
    {
        \Log::info('🔄 UPDATE TEAM REQUEST START', [
            'team_id' => $id,
            'has_name' => $request->has('name'),
            'has_logo_file' => $request->hasFile('logo'),
        ]);

        // Manually authenticate to avoid infinite recursion
        $admin = $this->getAuthenticatedAdmin($request);
        
        if (!$admin) {
            \Log::warning('❌ Unauthenticated update attempt');
            return response()->json([
                'success' => false,
                'message' => 'Unauthenticated. Please login first.',
            ], 401);
        }

        \Log::info('✅ Admin authenticated', ['admin_id' => $admin->id]);

        try {
            $validated = $request->validate([
                'name' => 'sometimes|required|string|max:255|unique:teams,name,' . $id,
                'logo' => 'sometimes|image|mimes:jpeg,png,jpg,gif,webp|max:2048',
            ]);
            \Log::info('✅ Validation passed', [
                'validated_keys' => array_keys($validated),
                'has_name' => isset($validated['name']),
                'has_logo' => isset($validated['logo']),
            ]);
        } catch (ValidationException $e) {
            \Log::error('❌ Validation failed', [
                'errors' => $e->errors(),
            ]);
            return response()->json([
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $e->errors(),
            ], 422);
        }

        try {
            // Find the team - only allow updating teams created by this admin
            $team = Team::where('id', $id)
                ->where('created_by', $admin->id)
                ->first();

            if (!$team) {
                \Log::warning('❌ Team not found or no permission', [
                    'team_id' => $id,
                    'admin_id' => $admin->id,
                ]);
                return response()->json([
                    'success' => false,
                    'message' => 'Team not found or you do not have permission to update this team.',
                ], 404);
            }

            \Log::info('✅ Team found', [
                'team_id' => $team->id,
                'current_name' => $team->name,
                'current_logo' => $team->logo,
                'has_logo_image' => $team->logoImage ? true : false,
            ]);

            // Update name if provided
            if (isset($validated['name'])) {
                \Log::info('📝 Updating name', [
                    'old_name' => $team->name,
                    'new_name' => $validated['name'],
                ]);
                $team->name = $validated['name'];
            }

            // Handle logo update if provided
            if ($request->hasFile('logo')) {
                $logoFile = $request->file('logo');
                
                \Log::info('🖼️ Logo file detected in request', [
                    'file_name' => $logoFile->getClientOriginalName(),
                    'file_size' => $logoFile->getSize(),
                    'file_mime' => $logoFile->getMimeType(),
                ]);

                // Delete old logo if exists
                if ($team->logoImage) {
                    \Log::info('🗑️ Deleting old logo image record', [
                        'old_file_path' => $team->logoImage->file_path,
                    ]);
                    Storage::disk('public')->delete($team->logoImage->file_path);
                    $team->logoImage->delete();
                } elseif ($team->logo) {
                    \Log::info('🗑️ Deleting old logo file', [
                        'old_logo' => $team->logo,
                    ]);
                    Storage::disk('public')->delete($team->logo);
                }

                // Upload new logo
                $logoPath = $logoFile->store('teams/logos', 'public');
                
                \Log::info('💾 New logo stored', [
                    'new_logo_path' => $logoPath,
                ]);
                
                $team->logo = $logoPath;

                // Create new image record
                $image = Image::create([
                    'file_path' => $logoPath,
                    'file_name' => $logoFile->getClientOriginalName(),
                    'mime_type' => $logoFile->getMimeType(),
                    'file_size' => $logoFile->getSize(),
                    'imageable_id' => $team->id,
                    'imageable_type' => Team::class,
                    'created_by' => $admin->id, // Track which admin uploaded this image
                ]);

                \Log::info('✅ New image record created', [
                    'image_id' => $image->id,
                    'file_path' => $image->file_path,
                ]);
            } else {
                \Log::info('ℹ️ No logo file in request - keeping existing logo');
            }

            $team->save();
            \Log::info('💾 Team saved', [
                'team_id' => $team->id,
                'final_name' => $team->name,
                'final_logo' => $team->logo,
            ]);

            $team->load(['logoImage.creator:id,name,email', 'creator:id,name,email']);

            // Log final state
            \Log::info('✅ UPDATE TEAM COMPLETE', [
                'team_id' => $team->id,
                'logo_updated' => $request->hasFile('logo'),
            ]);
            
            return response()->json([
                'success' => true,
                'message' => 'Team updated successfully',
                'data' => [
                    'id' => $team->id,
                    'name' => $team->name,
                    'logo' => $team->logo_url,
                    'status' => $team->status,
                    'created_by' => $team->created_by,
                    'creator' => $team->creator ? [
                        'id' => $team->creator->id,
                        'name' => $team->creator->name,
                        'email' => $team->creator->email,
                    ] : null,
                    'logo_image' => $team->logoImage ? [
                        'id' => $team->logoImage->id,
                        'file_path' => $team->logoImage->file_path,
                        'file_name' => $team->logoImage->file_name,
                        'mime_type' => $team->logoImage->mime_type,
                        'file_size' => $team->logoImage->file_size,
                        'created_by' => $team->logoImage->created_by,
                        'uploader' => $team->logoImage->creator ? [
                            'id' => $team->logoImage->creator->id,
                            'name' => $team->logoImage->creator->name,
                            'email' => $team->logoImage->creator->email,
                        ] : null,
                        'url' => asset('storage/' . $team->logoImage->file_path),
                    ] : null,
                    'created_at' => $team->created_at,
                    'updated_at' => $team->updated_at,
                ],
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Failed to update team',
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    /**
     * Delete a team.
     */
    public function deleteTeam(Request $request, $id): JsonResponse
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
            $team = Team::findOrFail($id);

            // Delete associated image
            if ($team->logoImage) {
                Storage::disk('public')->delete($team->logoImage->file_path);
                $team->logoImage->delete();
            } elseif ($team->logo) {
                Storage::disk('public')->delete($team->logo);
            }

            // Delete the team
            $team->delete();

            return response()->json([
                'success' => true,
                'message' => 'Team deleted successfully',
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Failed to delete team',
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    /**
     * Update team status.
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
            // Find the team - only allow updating teams created by this admin
            $team = Team::where('id', $id)
                ->where('created_by', $admin->id)
                ->first();

            if (!$team) {
                return response()->json([
                    'success' => false,
                    'message' => 'Team not found or you do not have permission to update this team.',
                ], 404);
            }

            // Update status
            $team->status = $validated['status'];
            $team->save();

            return response()->json([
                'success' => true,
                'message' => 'Team status updated successfully',
                'data' => [
                    'id' => $team->id,
                    'name' => $team->name,
                    'status' => $team->status,
                ],
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Failed to update team status',
                'error' => $e->getMessage(),
            ], 500);
        }
    }
}
