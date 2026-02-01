<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class Entry extends Model
{
    protected $fillable = [
        'match_id',
        'user_scope',
        'user_id',
        'favourite_team',
        'team1_rate',
        'team1_amount',
        'team2_rate',
        'team2_amount',
        'created_by',
    ];

    protected $casts = [
        'team1_rate' => 'decimal:2',
        'team1_amount' => 'decimal:2',
        'team2_rate' => 'decimal:2',
        'team2_amount' => 'decimal:2',
    ];

    /**
     * Get the match this entry belongs to.
     */
    public function match(): BelongsTo
    {
        return $this->belongsTo(GameMatch::class, 'match_id');
    }

    /**
     * Get the user this entry belongs to (if individual entry).
     */
    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class, 'user_id');
    }

    /**
     * Get the admin who created this entry.
     */
    public function creator(): BelongsTo
    {
        return $this->belongsTo(Admin::class, 'created_by');
    }

    /**
     * Check if entry is for favorite team.
     */
    public function isBetOnFavorite(): bool
    {
        if ($this->favourite_team === 'team1') {
            return !is_null($this->team1_rate) && !is_null($this->team1_amount);
        } else {
            return !is_null($this->team2_rate) && !is_null($this->team2_amount);
        }
    }

    /**
     * Check if entry is for non-favorite team.
     */
    public function isBetOnNonFavorite(): bool
    {
        if ($this->favourite_team === 'team1') {
            return !is_null($this->team2_rate) && !is_null($this->team2_amount);
        } else {
            return !is_null($this->team1_rate) && !is_null($this->team1_amount);
        }
    }
}
