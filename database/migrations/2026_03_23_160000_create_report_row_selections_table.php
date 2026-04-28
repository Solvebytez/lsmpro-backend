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
        Schema::create('report_row_selections', function (Blueprint $table) {
            $table->id();
            $table->foreignId('created_by')->constrained('admins')->onDelete('cascade');
            $table->enum('report_type', ['match', 'session']);
            $table->foreignId('match_id')->constrained('matches')->onDelete('cascade');
            $table->date('match_date')->nullable();
            $table->foreignId('selected_user_id')->constrained('users')->onDelete('cascade');

            // Context fields used to persist selection per report/filter state.
            $table->string('selection_type', 20)->default('');
            $table->unsignedBigInteger('selected_group_id')->default(0);
            $table->string('inning_over', 50)->default('');
            $table->unsignedBigInteger('winning_team_id')->default(0);

            $table->timestamps();

            $table->index(['created_by', 'report_type', 'match_id'], 'rrs_admin_report_match_idx');
            $table->unique(
                [
                    'created_by',
                    'report_type',
                    'match_id',
                    'selected_user_id',
                    'selection_type',
                    'selected_group_id',
                    'inning_over',
                    'winning_team_id',
                ],
                'rrs_unique_selection_context'
            );
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('report_row_selections');
    }
};

