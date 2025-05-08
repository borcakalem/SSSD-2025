<?php
class Auth {
    private $db;

    public function __construct($db) {
        $this->db = $db;
    }

    public function register() {
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $stmt = $this->db->connection->prepare(
                "INSERT INTO users (username, email, password) 
                 VALUES (?, ?, ?)"
            );
            $stmt->execute([
                $_POST['username'],
                $_POST['email'],
                password_hash($_POST['password'], PASSWORD_DEFAULT)
            ]);
            echo "Registration successful!";
            return;
        }
        
        // Show registration form
        echo '
        <form method="POST">
            <input type="text" name="username" required>
            <input type="email" name="email" required>
            <input type="password" name="password" required>
            <button type="submit">Register</button>
        </form>';
    }
}
