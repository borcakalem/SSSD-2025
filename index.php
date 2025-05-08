<?php

require 'vendor/autoload.php'; // Only Composer's autoloader is needed

// Load environment variables from .env
use Dotenv\Dotenv;
$dotenv = Dotenv::createImmutable(__DIR__);
$dotenv->load();

// Start session
session_start();

// Database connection
require 'src/Config/Database.php';

// Helper to get current user from session
function getCurrentUser() {
    if (!isset($_SESSION['user_id'])) return null;
    $userModel = new App\Models\User();
    return $userModel->findById($_SESSION['user_id']);
}

// Initialize Flight
Flight::set('flight.base_url', '/newwebsite');

// Routes
Flight::route('GET /', function() {
    echo '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Welcome</title></head><body><h1>Welcome to NewWebsite</h1><p>Your API is running!</p></body></html>';
});

Flight::route('POST /api/register', function() {
    $controller = new App\Controllers\AuthController();
    $controller->register();
});

Flight::route('POST /api/login', function() {
    $controller = new App\Controllers\AuthController();
    $controller->login();
    // After successful login, set session
    // $_SESSION['user_id'] = $user['id'];
});

Flight::route('POST /api/setup-2fa', function() {
    $controller = new App\Controllers\AuthController();
    $controller->setup2fa();
});

Flight::route('POST /api/verify-2fa', function() {
    $controller = new App\Controllers\AuthController();
    $controller->verify2fa();
});

Flight::route('POST /api/forgot-password', function() {
    $controller = new App\Controllers\AuthController();
    $controller->forgotPassword();
});

Flight::route('POST /api/reset-password', function() {
    $controller = new App\Controllers\AuthController();
    $controller->resetPassword();
});

Flight::route('POST /api/send-sms-code', function() {
    $controller = new App\Controllers\AuthController();
    $controller->sendSmsCode();
});

Flight::route('POST /api/verify-sms-code', function() {
    $controller = new App\Controllers\AuthController();
    $controller->verifySmsCode();
});

// API: Get current user info
Flight::route('GET /api/user', function() {
    $user = getCurrentUser();
    if (!$user) {
        Flight::json(['error' => 'Not authenticated'], 401);
        return;
    }
    unset($user['password_hash'], $user['email_verification_token'], $user['totp_secret'], $user['recovery_codes']);
    Flight::json(['user' => $user]);
});

// API: Logout
Flight::route('POST /api/logout', function() {
    session_destroy();
    Flight::json(['message' => 'Logged out']);
});

// API: Change password
Flight::route('POST /api/change-password', function() {
    $user = getCurrentUser();
    if (!$user) {
        Flight::json(['error' => 'Not authenticated'], 401);
        return;
    }
    $data = Flight::request()->data;
    $current = $data['current_password'] ?? '';
    $new = $data['new_password'] ?? '';
    if (!$current || !$new) {
        Flight::json(['error' => 'Current and new password required.'], 400);
        return;
    }
    if (!password_verify($current, $user['password_hash'])) {
        Flight::json(['error' => 'Current password is incorrect.'], 403);
        return;
    }
    if (strlen($new) < 8 || !preg_match('/[A-Z]/', $new) || !preg_match('/[a-z]/', $new)) {
        Flight::json(['error' => 'New password must be at least 8 characters and contain upper and lower case letters.'], 400);
        return;
    }
    $userModel = new App\Models\User();
    $userModel->changePassword($user['id'], $new);
    Flight::json(['message' => 'Password changed successfully.']);
});

// API: 2FA status (enable/disable)
Flight::route('POST /api/2fa-status', function() {
    $user = getCurrentUser();
    if (!$user) {
        Flight::json(['error' => 'Not authenticated'], 401);
        return;
    }
    $data = Flight::request()->data;
    $enable = (bool)($data['enable'] ?? false);
    $userModel = new App\Models\User();
    if ($enable) {
        $userModel->enable2FA($user['id']);
    } else {
        $userModel->disable2FA($user['id']);
    }
    Flight::json(['message' => $enable ? '2FA enabled.' : '2FA disabled.']);
});

Flight::start();