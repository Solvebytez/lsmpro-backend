<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphOne;

class Team extends Model
{
    protected $fillable = [
        'name',
        'logo',
        'status',
        'created_by',
    ];

    /**
     * Get the admin who created this team.
     */
    public function creator()
    {
        return $this->belongsTo(Admin::class, 'created_by');
    }

    /**
     * Get the team's logo image.
     */
    public function logoImage(): MorphOne
    {
        return $this->morphOne(Image::class, 'imageable');
    }

    /**
     * Get the logo URL (from images table or fallback to logo field).
     */
    public function getLogoUrlAttribute(): ?string
    {
        if ($this->logoImage) {
            return asset('storage/' . $this->logoImage->file_path);
        }
        
        // Fallback to logo field if it exists
        return $this->logo ? asset('storage/' . $this->logo) : null;
    }
}
