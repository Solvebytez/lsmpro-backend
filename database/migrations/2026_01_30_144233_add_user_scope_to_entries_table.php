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
        Schema::table('entries', function (Blueprint $table) {
            // Add user_scope column if it doesn't exist
            if (!Schema::hasColumn('entries', 'user_scope')) {
                $table->enum('user_scope', ['all', 'customer', 'group'])->after('group_id')->default('all');
            } else {
                // If column exists, modify it to include 'group'
                $table->enum('user_scope', ['all', 'customer', 'group'])->change();
            }
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('entries', function (Blueprint $table) {
            // Revert to original enum values if needed
            $table->enum('user_scope', ['all', 'customer'])->change();
        });
    }
};
