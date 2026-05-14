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
        // `matches` is already created by 2024_01_01_000030_create_matches_table.
        // This migration was a duplicate schema; keep a no-op so later migrations can run.
        if (Schema::hasTable('matches')) {
            return;
        }

        Schema::create('matches', function (Blueprint $table) {
            $table->id();
            $table->foreignId('team1_id')->constrained('teams')->onDelete('cascade');
            $table->foreignId('team2_id')->constrained('teams')->onDelete('cascade');
            $table->date('match_date');
            $table->foreignId('winner_id')->nullable()->constrained('teams')->onDelete('set null');
            $table->enum('status', ['scheduled', 'in_progress', 'completed', 'cancelled'])->default('scheduled');
            $table->foreignId('created_by')->nullable()->constrained('admins')->onDelete('set null');
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        // Do not drop `matches`; table is owned by 2024_01_01_000030_create_matches_table.
    }
};
