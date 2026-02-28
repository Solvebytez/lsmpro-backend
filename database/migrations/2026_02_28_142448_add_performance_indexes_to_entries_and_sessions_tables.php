<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Check if an index exists on a table using raw SQL
     */
    private function indexExists(string $table, string $indexName): bool
    {
        $connection = Schema::getConnection();
        $databaseName = $connection->getDatabaseName();
        
        $result = $connection->selectOne(
            "SELECT COUNT(*) as count 
             FROM information_schema.statistics 
             WHERE table_schema = ? 
             AND table_name = ? 
             AND index_name = ?",
            [$databaseName, $table, $indexName]
        );
        
        return $result->count > 0;
    }

    /**
     * Run the migrations.
     */
    public function up(): void
    {
        // Add indexes to entries table for faster filtering
        Schema::table('entries', function (Blueprint $table) {
            // Composite index for match_id and user_id (most common filter combination)
            // Note: Foreign keys already create indexes, but composite index helps with combined queries
            if (!$this->indexExists('entries', 'entries_match_id_user_id_index')) {
                $table->index(['match_id', 'user_id'], 'entries_match_id_user_id_index');
            }
            // Index for created_by (used for admin filtering)
            if (!$this->indexExists('entries', 'entries_created_by_index')) {
                $table->index('created_by', 'entries_created_by_index');
            }
        });

        // Add indexes to session_entries table for faster filtering
        Schema::table('session_entries', function (Blueprint $table) {
            // Composite index for match_id and created_by (most common filter)
            if (!$this->indexExists('session_entries', 'session_entries_match_id_created_by_index')) {
                $table->index(['match_id', 'created_by'], 'session_entries_match_id_created_by_index');
            }
            // Composite index for inning_over and created_by (used for filtering sessions)
            if (!$this->indexExists('session_entries', 'session_entries_inning_over_created_by_index')) {
                $table->index(['inning_over', 'created_by'], 'session_entries_inning_over_created_by_index');
            }
            // Index for user_id (used when filtering by user)
            if (!$this->indexExists('session_entries', 'session_entries_user_id_index')) {
                $table->index('user_id', 'session_entries_user_id_index');
            }
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('entries', function (Blueprint $table) {
            if ($this->indexExists('entries', 'entries_match_id_user_id_index')) {
                $table->dropIndex('entries_match_id_user_id_index');
            }
            if ($this->indexExists('entries', 'entries_created_by_index')) {
                $table->dropIndex('entries_created_by_index');
            }
        });

        Schema::table('session_entries', function (Blueprint $table) {
            if ($this->indexExists('session_entries', 'session_entries_match_id_created_by_index')) {
                $table->dropIndex('session_entries_match_id_created_by_index');
            }
            if ($this->indexExists('session_entries', 'session_entries_inning_over_created_by_index')) {
                $table->dropIndex('session_entries_inning_over_created_by_index');
            }
            if ($this->indexExists('session_entries', 'session_entries_user_id_index')) {
                $table->dropIndex('session_entries_user_id_index');
            }
        });
    }
};
