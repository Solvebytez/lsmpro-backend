<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('images', function (Blueprint $table) {
            $table->id();
            $table->string('file_path'); // Storage path of the image
            $table->string('file_name'); // Original filename
            $table->string('mime_type'); // Image MIME type (e.g., image/png, image/jpeg)
            $table->unsignedBigInteger('file_size')->nullable(); // File size in bytes
            $table->morphs('imageable'); // Creates imageable_id and imageable_type for polymorphic relationship
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('images');
    }
};
