<?php
namespace App\Controllers;

use App\Models\User;
use Flight;
use libphonenumber\PhoneNumberUtil;
use libphonenumber\PhoneNumberType;
use libphonenumber\NumberParseException;
use RobThree\Auth\TwoFactorAuth;
use RobThree\Auth\Providers\Qr\EndroidQrCodeProvider;

class AuthController {
    public function register() {
        $data = Flight::request()->data;
        $username = trim($data['username'] ?? '');
        $email = trim($data['email'] ?? '');
        $password = $data['password'] ?? '';
        $phone = trim($data['phone'] ?? '');

        // Username validation
        $reserved = ['admin', 'root', 'system', 'administrator', 'support', 'test'];
        if (!$username || !$email || !$password || !$phone) {
            Flight::json(['error' => 'All fields are required.'], 400);
            return;
        }
        if (!is_string($username) || strlen($username) <= 3) {
            Flight::json(['error' => 'Username must be longer than 3 characters.'], 400);
            return;
        }

        if (in_array(strtolower($username), $reserved)) {
            Flight::json(['error' => 'This username is reserved.'], 400);
            return;
        }

        // Email validation
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            Flight::json(['error' => 'Invalid email format.'], 400);
            return;
        }
        // Validate domain extension
        $emailParts = explode('@', $email);
        $domain = array_pop($emailParts);
        $domainParts = explode('.', $domain);
        $tld = strtoupper(array_pop($domainParts));
        $tlds = file(__DIR__ . '/../../tlds-alpha-by-domain.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $tlds = array_filter($tlds, function($line) { return $line && $line[0] !== '#'; });
        if (!in_array($tld, $tlds)) {
            Flight::json(['error' => 'Invalid or unsupported email domain extension.'], 400);
            return;
        }
        // Validate MX record
        if (!checkdnsrr($domain, 'MX')) {
            Flight::json(['error' => 'Email domain does not have valid MX records.'], 400);
            return;
        }

        // Password validation
        if (!is_string($password) || strlen($password) < 8) {
            Flight::json(['error' => 'Password must be at least 8 characters long.'], 400);
            return;
        }
        if (!\preg_match('/[A-Z]/', $password) || !\preg_match('/[a-z]/', $password)) {
            Flight::json(['error' => 'Password must contain at least one uppercase and one lowercase letter.'], 400);
            return;
        }

        // Phone validation
        $phoneUtil = PhoneNumberUtil::getInstance();
        try {
            $phoneProto = $phoneUtil->parse($phone, 'US'); // Change 'US' to your default region if needed
            if (!$phoneUtil->isValidNumber($phoneProto) || $phoneUtil->getNumberType($phoneProto) !== PhoneNumberType::MOBILE) {
                Flight::json(['error' => 'Invalid or non-mobile phone number.'], 400);
                return;
            }
        } catch (NumberParseException $e) {
            Flight::json(['error' => 'Invalid phone number format.'], 400);
            return;
        }

        $userModel = new User();
        if ($userModel->findByPhone($phone)) {
            Flight::json(['error' => 'Phone number already exists.'], 409);
            return;
        }

        // Generate email verification token
        $emailVerificationToken = bin2hex(\random_bytes(32));

        if ($userModel->findByUsernameOrEmail($username) || $userModel->findByUsernameOrEmail($email)) {
            Flight::json(['error' => 'Username or email already exists.'], 409);
            return;
        }

        $userModel->create($username, $email, $password, $phone, $emailVerificationToken);

        // Send confirmation email using Postmark
        $verificationLink = 'http://' . $_SERVER['HTTP_HOST'] . '/newwebsite/public/verify-email.php?token=' . $emailVerificationToken;
        $subject = 'Verify your email address';
        $htmlBody = '<p>Thank you for registering! Please <a href="' . $verificationLink . '">click here to verify your email</a>.</p>';
        \App\Config\Mailer::send($email, $subject, $htmlBody);

        Flight::json(['message' => 'Registration successful. Please check your email for verification.'], 201);
    }

    public function setup2fa() {
        // Use session for authentication
        if (session_status() === PHP_SESSION_NONE) session_start();
        $userId = $_SESSION['user_id'] ?? null;
        if (!$userId) {
            Flight::json(['error' => 'Not authenticated'], 401);
            return;
        }
        $userModel = new User();
        $user = $userModel->findById($userId);
        if (!$user) {
            Flight::json(['error' => 'User not found.'], 404);
            return;
        }
        $tfa = new TwoFactorAuth(new EndroidQrCodeProvider(), 'NewWebsite');
        $secret = $tfa->createSecret();
        $qrCodeUrl = $tfa->getQRCodeImageAsDataUri($user['email'], $secret);
        // Generate recovery codes
        $recoveryCodes = [];
        for ($i = 0; $i < 5; $i++) {
            $recoveryCodes[] = bin2hex(\random_bytes(4));
        }
        $userModel->set2FA($user['id'], $secret, $recoveryCodes);
        Flight::json([
            'secret' => $secret,
            'qr' => $qrCodeUrl,
            'recovery_codes' => $recoveryCodes
        ]);
    }

    public function verify2fa() {
        $data = Flight::request()->data;
        $usernameOrEmail = trim($data['username'] ?? $data['email'] ?? '');
        $code = $data['code'] ?? '';
        $userModel = new User();
        $user = $userModel->findByUsernameOrEmail($usernameOrEmail);
        if (!$user || !$user['totp_secret']) {
            Flight::json(['error' => '2FA not enabled.'], 400);
            return;
        }
        $tfa = new TwoFactorAuth(new EndroidQrCodeProvider(), 'NewWebsite');
        if ($tfa->verifyCode($user['totp_secret'], $code)) {
            $userModel->enable2FA($user['id']);
            Flight::json(['message' => '2FA verified and enabled.']);
        } else if ($userModel->useRecoveryCode($user['id'], $code)) {
            $userModel->enable2FA($user['id']);
            Flight::json(['message' => '2FA verified with recovery code.']);
        } else {
            Flight::json(['error' => 'Invalid 2FA or recovery code.'], 401);
        }
    }

    public function sendSmsCode() {
        $data = Flight::request()->data;
        $purpose = $data['purpose'] ?? '2fa'; // '2fa' or 'reset'
        $phone = trim($data['phone'] ?? '');
        $userId = null;
        $userModel = new User();
        if ($purpose === '2fa') {
            // Use session user for 2FA
            if (session_status() === PHP_SESSION_NONE) session_start();
            $userId = $_SESSION['user_id'] ?? null;
            if (!$userId) {
                Flight::json(['error' => 'Not authenticated'], 401);
                return;
            }
            $user = $userModel->findById($userId);
            $phone = $user['phone'];
        } else if ($purpose === 'reset') {
            // For password reset, find user by phone
            $user = $userModel->findByPhone($phone);
            if (!$user) {
                Flight::json(['error' => 'Phone not found.'], 404);
                return;
            }
            $userId = $user['id'];
        }
        if (!$phone) {
            Flight::json(['error' => 'Phone number required.'], 400);
            return;
        }
        // Generate code
        $code = str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);
        $expires = date('Y-m-d H:i:s', time() + 300); // 5 minutes
        $db = \App\Config\Database::getConnection();
        $db->prepare('INSERT INTO sms_verifications (user_id, phone, code, expires_at) VALUES (?, ?, ?, ?)')->execute([$userId, $phone, $code, $expires]);
        // Send SMS
        $msg = ($purpose === 'reset') ? "Your password reset code is: $code" : "Your 2FA code is: $code";
        \App\Config\Sms::send($phone, $msg);
        Flight::json(['message' => 'SMS code sent.']);
    }

    public function verifySmsCode() {
        $data = Flight::request()->data;
        $phone = trim($data['phone'] ?? '');
        $code = trim($data['code'] ?? '');
        $purpose = $data['purpose'] ?? '2fa';
        $userModel = new User();
        $user = $userModel->findByPhone($phone);
        if (!$user) {
            Flight::json(['error' => 'Phone not found.'], 404);
            return;
        }
        $db = \App\Config\Database::getConnection();
        $stmt = $db->prepare('SELECT * FROM sms_verifications WHERE user_id = ? AND phone = ? AND code = ? AND used = 0 AND expires_at > NOW() ORDER BY id DESC LIMIT 1');
        $stmt->execute([$user['id'], $phone, $code]);
        $row = $stmt->fetch();
        if (!$row) {
            Flight::json(['error' => 'Invalid or expired code.'], 400);
            return;
        }
        // Mark as used
        $db->prepare('UPDATE sms_verifications SET used = 1 WHERE id = ?')->execute([$row['id']]);
        Flight::json(['message' => 'SMS code verified.', 'user_id' => $user['id']]);
    }

    private function logLoginAttempt($usernameOrEmail, $ip, $success) {
        $db = \App\Config\Database::getConnection();
        $stmt = $db->prepare('INSERT INTO login_attempts (username_or_email, ip_address, success) VALUES (?, ?, ?)');
        $stmt->execute([$usernameOrEmail, $ip, $success ? 1 : 0]);
    }

    private function countRecentFailedAttempts($usernameOrEmail, $ip) {
        $db = \App\Config\Database::getConnection();
        $stmt = $db->prepare('SELECT COUNT(*) FROM login_attempts WHERE (username_or_email = ? OR ip_address = ?) AND success = 0 AND attempt_time > (NOW() - INTERVAL 15 MINUTE)');
        $stmt->execute([$usernameOrEmail, $ip]);
        return (int)$stmt->fetchColumn();
    }

    private function verifyRecaptcha($token) {
        $secret = $_ENV['RECAPTCHA_SECRET_KEY'] ?? '';
        if (!$secret) return false;
        $response = file_get_contents('https://www.google.com/recaptcha/api/siteverify?secret=' . $secret . '&response=' . $token);
        $result = json_decode($response, true);
        return $result['success'] ?? false;
    }

    public function login() {
        $data = Flight::request()->data;
        $usernameOrEmail = trim($data['username'] ?? $data['email'] ?? '');
        $password = $data['password'] ?? '';
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        $captchaToken = $data['captcha'] ?? null;

        if (!$usernameOrEmail || !$password) {
            Flight::json(['error' => 'Username/email and password are required.'], 400);
            return;
        }

        $failedAttempts = $this->countRecentFailedAttempts($usernameOrEmail, $ip);
        if ($failedAttempts >= 3) {
            if (!$captchaToken || !$this->verifyRecaptcha($captchaToken)) {
                $this->logLoginAttempt($usernameOrEmail, $ip, false);
                Flight::json(['error' => 'Captcha required or invalid.'], 429);
                return;
            }
        }

        $userModel = new User();
        $user = $userModel->findByUsernameOrEmail($usernameOrEmail);
        if (!$user || !password_verify($password, $user['password_hash'])) {
            $this->logLoginAttempt($usernameOrEmail, $ip, false);
            Flight::json(['error' => 'Invalid credentials.'], 401);
            return;
        }
        if (empty($user['email_verified'])) {
            $this->logLoginAttempt($usernameOrEmail, $ip, false);
            Flight::json(['error' => 'Please verify your email before logging in.'], 403);
            return;
        }
        if (!empty($user['is_2fa_enabled'])) {
            // For testing: show a message instead of requiring 2FA code
            Flight::json(['message' => '2FA is enabled. (SMS/TOTP verification would be required here in production.)'], 200);
            $_SESSION['user_id'] = $user['id'];
            return;
        }
        $this->logLoginAttempt($usernameOrEmail, $ip, true);
        $_SESSION['user_id'] = $user['id']; // Set session after successful login
        Flight::json(['message' => 'Login successful.']);
    }

    public function forgotPassword() {
        $data = Flight::request()->data;
        $email = trim($data['email'] ?? '');
        $captchaToken = $data['captcha'] ?? null;
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        if (!$email) {
            Flight::json(['error' => 'Email is required.'], 400);
            return;
        }
        $userModel = new User();
        $user = $userModel->findByUsernameOrEmail($email);
        if (!$user || empty($user['email_verified'])) {
            Flight::json(['error' => 'Account not found or not verified.'], 404);
            return;
        }
        // Limit attempts: 2 per 10 minutes per email/IP
        $db = \App\Config\Database::getConnection();
        $stmt = $db->prepare('SELECT COUNT(*) FROM password_resets WHERE (user_id = ? OR ip_address = ?) AND created_at > (NOW() - INTERVAL 10 MINUTE)');
        $stmt->execute([$user['id'], $ip]);
        $attempts = (int)$stmt->fetchColumn();
        if ($attempts >= 2) {
            // Require captcha
            if (!$captchaToken || !$this->verifyRecaptcha($captchaToken)) {
                Flight::json(['error' => 'Captcha required or invalid.'], 429);
                return;
            }
        }
        // Generate token
        $token = bin2hex(\random_bytes(32));
        $expires = date('Y-m-d H:i:s', time() + 300); // 5 minutes
        $stmt = $db->prepare('INSERT INTO password_resets (user_id, token, expires_at, ip_address) VALUES (?, ?, ?, ?)');
        $stmt->execute([$user['id'], $token, $expires, $ip]);
        // Send reset email
        $resetLink = 'http://' . $_SERVER['HTTP_HOST'] . '/newwebsite/public/reset-password.php?token=' . $token;
        $subject = 'Password Reset Request';
        $htmlBody = '<p>Click <a href="' . $resetLink . '">here</a> to reset your password. This link expires in 5 minutes and can only be used once.</p>';
        \App\Config\Mailer::send($user['email'], $subject, $htmlBody);
        Flight::json(['message' => 'If your email is registered and verified, a reset link has been sent.'], 200);
    }

    public function resetPassword() {
        $data = Flight::request()->data;
        $token = $data['token'] ?? '';
        $newPassword = $data['password'] ?? '';
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        if (!$token || !$newPassword) {
            Flight::json(['error' => 'Token and new password are required.'], 400);
            return;
        }
        $db = \App\Config\Database::getConnection();
        $stmt = $db->prepare('SELECT * FROM password_resets WHERE token = ?');
        $stmt->execute([$token]);
        $reset = $stmt->fetch();
        if (!$reset || $reset['used'] || strtotime($reset['expires_at']) < time()) {
            Flight::json(['error' => 'Invalid or expired token.'], 400);
            return;
        }
        // Limit to 2 tries per token
        if ($reset['attempts'] >= 2) {
            Flight::json(['error' => 'Too many attempts for this reset link.'], 429);
            return;
        }
        // Password validation
        if (strlen($newPassword) < 8 || !\preg_match('/[A-Z]/', $newPassword) || !\preg_match('/[a-z]/', $newPassword)) {
            $db->prepare('UPDATE password_resets SET attempts = attempts + 1 WHERE id = ?')->execute([$reset['id']]);
            Flight::json(['error' => 'Password must be at least 8 characters and contain upper and lower case letters.'], 400);
            return;
        }
        // Update password
        $userModel = new User();
        $userModel->changePassword($reset['user_id'], $newPassword);
        // Mark token as used
        $db->prepare('UPDATE password_resets SET used = 1 WHERE id = ?')->execute([$reset['id']]);
        // Send confirmation email
        $stmt = $db->prepare('SELECT email FROM users WHERE id = ?');
        $stmt->execute([$reset['user_id']]);
        $email = $stmt->fetchColumn();
        $subject = 'Your password has been changed';
        $htmlBody = '<p>Your password was successfully changed. If you did not do this, please contact support immediately.</p>';
        \App\Config\Mailer::send($email, $subject, $htmlBody);
        Flight::json(['message' => 'Password reset successful. You may now log in.']);
    }
}
