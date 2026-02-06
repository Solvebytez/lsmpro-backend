<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class InningsOver extends Model
{
    protected $fillable = [
        'inning',
        'over',
        'created_by',
    ];

    protected $casts = [
        'inning' => 'integer',
        'over' => 'integer',
    ];

    /**
     * Get the admin who created this innings/over entry.
     */
    public function creator(): BelongsTo
    {
        return $this->belongsTo(Admin::class, 'created_by');
    }
}

