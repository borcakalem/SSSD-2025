<?php
namespace App\Models;

use App\Config\Database;
use PDO;

class User {
    private $db;

    public function __construct() {
        $this->db = Database::getConnection();
    }

    public function findByUsernameOrEmail($usernameOrEmail) {
        $stmt = $this->db->prepare('SELECT * FROM users WHERE username = :ue OR email = :ue LIMIT 1');
        $stmt->execute(['ue' => $usernameOrEmail]);
        return $stmt->fetch();
    }

    public function findByPhone($phone) {
        $stmt = $this->db->prepare('SELECT * FROM users WHERE phone = :phone LIMIT 1');
        $stmt->execute(['phone' => $phone]);
        return $stmt->fetch();
    }

    public function create($username, $email, $password, $phone, $emailVerificationToken) {
        $passwordHash = password_hash($password, PASSWORD_DEFAULT);
        $stmt = $this->db->prepare('INSERT INTO users (username, email, password_hash, phone, email_verification_token) VALUES (?, ?, ?, ?, ?)');
        return $stmt->execute([$username, $email, $passwordHash, $phone, $emailVerificationToken]);
    }

    public function set2FA($userId, $secret, $recoveryCodes) {
        $db = Database::getConnection();
        $stmt = $db->prepare('UPDATE users SET totp_secret = ?, recovery_codes = ?, is_2fa_enabled = 0 WHERE id = ?');
        $stmt->execute([$secret, json_encode($recoveryCodes), $userId]);
    }

    public function enable2FA($userId) {
        $db = Database::getConnection();
        $stmt = $db->prepare('UPDATE users SET is_2fa_enabled = 1 WHERE id = ?');
        $stmt->execute([$userId]);
    }

    public function useRecoveryCode($userId, $code) {
        $db = Database::getConnection();
        $stmt = $db->prepare('SELECT recovery_codes FROM users WHERE id = ?');
        $stmt->execute([$userId]);
        $row = $stmt->fetch();
        if (!$row) return false;
        $codes = json_decode($row['recovery_codes'], true);
        if (!is_array($codes) || !in_array($code, $codes)) return false;
        // Remove used code
        $codes = array_values(array_diff($codes, [$code]));
        $stmt = $db->prepare('UPDATE users SET recovery_codes = ? WHERE id = ?');
        $stmt->execute([json_encode($codes), $userId]);
        return true;
    }

    public function changePassword($userId, $newPassword) {
        $db = Database::getConnection();
        $passwordHash = password_hash($newPassword, PASSWORD_DEFAULT);
        $stmt = $db->prepare('UPDATE users SET password_hash = ? WHERE id = ?');
        $stmt->execute([$passwordHash, $userId]);
    }

    public function disable2FA($userId) {
        $db = Database::getConnection();
        $stmt = $db->prepare('UPDATE users SET is_2fa_enabled = 0, totp_secret = NULL, recovery_codes = NULL WHERE id = ?');
        $stmt->execute([$userId]);
    }

    public function findById($id) {
        $stmt = $this->db->prepare('SELECT * FROM users WHERE id = ? LIMIT 1');
        $stmt->execute([$id]);
        return $stmt->fetch();
    }
}
