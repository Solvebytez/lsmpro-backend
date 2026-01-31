<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Hash;
use App\Models\Admin;

class AdminSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        // Create Super Admin
        Admin::create([
            'name' => 'Super Admin',
            'email' => 'superadmin@example.com',
            'mobile' => '1234567890',
            'password' => Hash::make('password'),
            'role' => 'superadmin',
            'commission' => 0.00,
            'partnership' => 0.00,
        ]);

        // Create a regular Admin (optional, for testing)
        Admin::create([
            'name' => 'Admin User',
            'email' => 'admin@example.com',
            'mobile' => '0987654321',
            'password' => Hash::make('password'),
            'role' => 'admin',
            'commission' => 5.00,
            'partnership' => 10.00,
        ]);

        $this->command->info('Admins seeded successfully!');
        $this->command->info('Super Admin: superadmin@example.com / password');
        $this->command->info('Admin: admin@example.com / password');
    }
}
