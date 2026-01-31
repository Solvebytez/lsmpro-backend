<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Image extends Model
{
    protected $fillable = [
        'file_path',
        'file_name',
        'mime_type',
        'file_size',
        'imageable_id',
        'imageable_type',
        'created_by',
    ];

    /**
     * Get the parent imageable model (Team, User, etc.).
     */
    public function imageable()
    {
        return $this->morphTo();
    }

    /**
     * Get the admin who uploaded this image.
     */
    public function creator()
    {
        return $this->belongsTo(Admin::class, 'created_by');
    }
}
