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
        Schema::create('session_entries', function (Blueprint $table) {
            $table->id();
            $table->foreignId('match_id')->constrained('matches')->onDelete('cascade');
            $table->foreignId('user_id')->constrained('users')->onDelete('cascade');
            $table->string('inning_over'); // e.g., "1/5 Over"
            $table->integer('entry_run')->unsigned();
            $table->decimal('amount', 10, 2)->unsigned();
            $table->boolean('is_yes')->default(true);
            $table->integer('result')->unsigned()->nullable(); // Optional, can be null initially
            $table->decimal('net_profit_loss', 10, 2)->default(0);
            $table->foreignId('created_by')->nullable()->constrained('admins')->onDelete('set null');
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('session_entries');
    }
};
