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
        Schema::table('entries', function (Blueprint $table) {
            // Drop old foreign keys if they exist
            if (DB::getSchemaBuilder()->hasColumn('entries', 'favourite_team_id')) {
                $table->dropForeign(['favourite_team_id']);
            }
            if (DB::getSchemaBuilder()->hasColumn('entries', 'non_favourite_team_id')) {
                $table->dropForeign(['non_favourite_team_id']);
            }
            if (DB::getSchemaBuilder()->hasColumn('entries', 'admin_id')) {
                $table->dropForeign(['admin_id']);
            }
            
            // Drop old columns if they exist
            $columnsToDrop = [
                'favourite_team_id',
                'non_favourite_team_id',
                'fav_rate',
                'fav_amount',
                'nfav_rate',
                'nfav_amount',
                'admin_id',
                'user_scope',
            ];
            
            foreach ($columnsToDrop as $column) {
                if (DB::getSchemaBuilder()->hasColumn('entries', $column)) {
                    $table->dropColumn($column);
                }
            }

            // Add new columns if they don't exist
            if (!DB::getSchemaBuilder()->hasColumn('entries', 'group_id')) {
                $table->foreignId('group_id')->nullable()->after('user_id')->constrained('groups')->onDelete('set null');
            }
            if (!DB::getSchemaBuilder()->hasColumn('entries', 'favourite_team')) {
                $table->enum('favourite_team', ['team1', 'team2'])->after('group_id');
            }
            if (!DB::getSchemaBuilder()->hasColumn('entries', 'team1_rate')) {
                $table->decimal('team1_rate', 10, 2)->nullable()->after('favourite_team');
            }
            if (!DB::getSchemaBuilder()->hasColumn('entries', 'team1_amount')) {
                $table->decimal('team1_amount', 10, 2)->nullable()->after('team1_rate');
            }
            if (!DB::getSchemaBuilder()->hasColumn('entries', 'team2_rate')) {
                $table->decimal('team2_rate', 10, 2)->nullable()->after('team1_amount');
            }
            if (!DB::getSchemaBuilder()->hasColumn('entries', 'team2_amount')) {
                $table->decimal('team2_amount', 10, 2)->nullable()->after('team2_rate');
            }
            if (!DB::getSchemaBuilder()->hasColumn('entries', 'created_by')) {
                $table->foreignId('created_by')->after('team2_amount')->constrained('admins')->onDelete('restrict');
            }
        });

        // Note: Check constraint for user_id OR group_id is handled in application layer
        // MySQL doesn't allow check constraints on foreign key columns
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('entries', function (Blueprint $table) {
            // Drop new columns
            $table->dropForeign(['group_id']);
            $table->dropForeign(['created_by']);
            $table->dropColumn([
                'group_id',
                'favourite_team',
                'team1_rate',
                'team1_amount',
                'team2_rate',
                'team2_amount',
                'created_by',
            ]);

            // Restore old columns
            $table->enum('user_scope', ['customer', 'all'])->default('all')->after('user_id');
            $table->foreignId('favourite_team_id')->after('user_scope')->constrained('teams')->onDelete('cascade');
            $table->foreignId('non_favourite_team_id')->after('favourite_team_id')->constrained('teams')->onDelete('cascade');
            $table->decimal('fav_rate', 8, 2)->nullable()->after('non_favourite_team_id');
            $table->decimal('fav_amount', 12, 2)->default(0)->after('fav_rate');
            $table->decimal('nfav_rate', 8, 2)->nullable()->after('fav_amount');
            $table->decimal('nfav_amount', 12, 2)->default(0)->after('nfav_rate');
            $table->foreignId('admin_id')->nullable()->after('nfav_amount')->constrained('admins')->onDelete('set null');
        });
    }
};
