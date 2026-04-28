<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class ReportRowSelection extends Model
{
    protected $fillable = [
        'created_by',
        'report_type',
        'match_id',
        'match_date',
        'selected_user_id',
        'selection_type',
        'selected_group_id',
        'inning_over',
        'winning_team_id',
    ];

    protected $casts = [
        'match_date' => 'date',
    ];

    public function admin(): BelongsTo
    {
        return $this->belongsTo(Admin::class, 'created_by');
    }

    public function match(): BelongsTo
    {
        return $this->belongsTo(GameMatch::class, 'match_id');
    }

    public function selectedUser(): BelongsTo
    {
        return $this->belongsTo(User::class, 'selected_user_id');
    }
}

