<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use App\Models\Admin;

class AdminSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        // Idempotent: safe to run multiple times (upsert by email).
        // Plain password is hashed via Admin model cast.
        Admin::updateOrCreate(
            ['email' => 'superadmin@example.com'],
            [
                'name' => 'Super Admin',
                'mobile' => '1234567890',
                'password' => 'password',
                'role' => 'superadmin',
                'status' => 'active',
                'commission' => 0.00,
                'partnership' => 0.00,
            ]
        );

        Admin::updateOrCreate(
            ['email' => 'sahinh013@gmail.com'],
            [
                'name' => 'Admin',
                'mobile' => null,
                'password' => 'qwerty@1234',
                'role' => 'admin',
                'status' => 'active',
                'commission' => 5.00,
                'partnership' => 10.00,
            ]
        );

        $this->command->info('Admins seeded successfully!');
        $this->command->info('Super Admin: superadmin@example.com / password');
        $this->command->info('Admin: sahinh013@gmail.com / qwerty@1234');
    }
}
