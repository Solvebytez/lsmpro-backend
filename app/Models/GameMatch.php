<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class GameMatch extends Model
{
    protected $table = 'matches';

    protected $fillable = [
        'team1_id',
        'team2_id',
        'match_date',
        'winner_id',
        'status',
        'created_by',
    ];

    protected $casts = [
        'match_date' => 'date',
    ];

    /**
     * Get team1.
     */
    public function team1(): BelongsTo
    {
        return $this->belongsTo(Team::class, 'team1_id');
    }

    /**
     * Get team2.
     */
    public function team2(): BelongsTo
    {
        return $this->belongsTo(Team::class, 'team2_id');
    }

    /**
     * Get winner team.
     */
    public function winner(): BelongsTo
    {
        return $this->belongsTo(Team::class, 'winner_id');
    }

    /**
     * Get the admin who created this match.
     */
    public function creator(): BelongsTo
    {
        return $this->belongsTo(Admin::class, 'created_by');
    }

    /**
     * Get all entries for this match.
     */
    public function entries(): HasMany
    {
        return $this->hasMany(Entry::class, 'match_id');
    }

    /**
     * Get match between string (e.g., "Team A vs Team B").
     */
    public function getMatchBetweenAttribute(): string
    {
        try {
            $team1Name = 'Unknown';
            $team2Name = 'Unknown';
            
            if ($this->relationLoaded('team1') && $this->team1) {
                $team1Name = $this->team1->name ?? 'Unknown';
            }
            
            if ($this->relationLoaded('team2') && $this->team2) {
                $team2Name = $this->team2->name ?? 'Unknown';
            }
            
            return "{$team1Name} vs {$team2Name}";
        } catch (\Exception $e) {
            return 'Unknown vs Unknown';
        }
    }
}
