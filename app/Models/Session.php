<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class Session extends Model
{
    protected $table = 'session_entries';

    protected $fillable = [
        'match_id',
        'user_id',
        'inning_over',
        'entry_run',
        'amount',
        'is_yes',
        'result',
        'net_profit_loss',
        'created_by',
    ];

    protected $casts = [
        'entry_run' => 'integer',
        'amount' => 'decimal:2',
        'is_yes' => 'boolean',
        'result' => 'integer',
        'net_profit_loss' => 'decimal:2',
    ];

    /**
     * Get the match that this session belongs to.
     */
    public function match(): BelongsTo
    {
        return $this->belongsTo(\App\Models\GameMatch::class, 'match_id');
    }

    /**
     * Get the user that this session belongs to.
     */
    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    /**
     * Get the admin who created this session.
     */
    public function creator(): BelongsTo
    {
        return $this->belongsTo(Admin::class, 'created_by');
    }
}
