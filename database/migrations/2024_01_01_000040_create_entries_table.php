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
        Schema::create('entries', function (Blueprint $table) {
            $table->id();
            $table->foreignId('match_id')->constrained('matches')->onDelete('cascade');
            $table->foreignId('user_id')->nullable()->constrained('users')->onDelete('set null');
            $table->foreignId('admin_id')->nullable()->constrained('admins')->onDelete('set null');
            $table->enum('user_scope', ['customer', 'all'])->default('all');
            $table->foreignId('favourite_team_id')->constrained('teams')->onDelete('cascade');
            $table->foreignId('non_favourite_team_id')->constrained('teams')->onDelete('cascade');
            $table->decimal('fav_rate', 8, 2)->nullable();
            $table->decimal('fav_amount', 12, 2)->default(0);
            $table->decimal('nfav_rate', 8, 2)->nullable();
            $table->decimal('nfav_amount', 12, 2)->default(0);
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('entries');
    }
};

