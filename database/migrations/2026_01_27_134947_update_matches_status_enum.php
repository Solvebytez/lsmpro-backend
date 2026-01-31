<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        // For MySQL, we need to alter the enum column
        // First, update existing 'yet_to_start' values to 'scheduled'
        DB::table('matches')
            ->where('status', 'yet_to_start')
            ->update(['status' => 'scheduled']);
        
        // Then alter the enum column
        DB::statement("ALTER TABLE `matches` MODIFY COLUMN `status` ENUM('scheduled', 'in_progress', 'completed', 'cancelled') NOT NULL DEFAULT 'scheduled'");
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        // Revert 'scheduled' back to 'yet_to_start'
        DB::table('matches')
            ->where('status', 'scheduled')
            ->update(['status' => 'yet_to_start']);
        
        // Revert the enum column
        DB::statement("ALTER TABLE `matches` MODIFY COLUMN `status` ENUM('yet_to_start', 'in_progress', 'completed', 'cancelled') NOT NULL DEFAULT 'yet_to_start'");
    }
};
