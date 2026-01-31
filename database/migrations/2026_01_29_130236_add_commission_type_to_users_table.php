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
        Schema::table('users', function (Blueprint $table) {
            // Make email, mobile, password nullable
            $table->string('email')->nullable()->change();
            $table->string('mobile')->nullable()->change();
            $table->string('password')->nullable()->change();
            
            // Add commission_type enum field
            $table->enum('commission_type', ['no_commission', 'profit_loss', 'entrywise'])
                ->default('no_commission')
                ->after('partnership');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('users', function (Blueprint $table) {
            // Revert email, mobile, password to not nullable (if needed)
            $table->string('email')->nullable(false)->change();
            $table->string('mobile')->nullable()->change(); // Keep nullable as it was originally
            $table->string('password')->nullable(false)->change();
            
            // Drop commission_type column
            $table->dropColumn('commission_type');
        });
    }
};
