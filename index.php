<?php
require __DIR__.'/../vendor/autoload.php';
require __DIR__.'/../src/Database.php';

$db = new App\Database();

// Handle actions based on URL
$action = $_GET['action'] ?? '';

switch ($action) {
    case 'login':
        handleLogin($db);
        break;
    case 'register':
        handleRegister($db);
        break;
    default:
        showHomepage();
}

// Functions
function handleLogin($db) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $user = $db->getUser($_POST['username']);
        
        if ($user && password_verify($_POST['password'], $user['password'])) {
            echo "Login successful!";
        } else {
            echo "Invalid credentials";
        }
        exit;
    }
    showLoginForm();
}

function handleRegister($db) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $stmt = $db->connection->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
        $stmt->execute([
            $_POST['username'],
            $_POST['email'],
            password_hash($_POST['password'], PASSWORD_DEFAULT)
        ]);
        echo "Registration successful!";
        exit;
    }
    showRegistrationForm();
}

function showHomepage() {
    echo '<h3>Choose an action:</h3>';
    echo '<a href="?action=login">Login</a> | ';
    echo '<a href="?action=register">Register</a>';
}

function showLoginForm() {
    echo '<h3>Login</h3>';
    echo '<form method="POST" action="?action=login">';
    echo '<input type="text" name="username" placeholder="Username" required><br>';
    echo '<input type="password" name="password" placeholder="Password" required><br>';
    echo '<button type="submit">Login</button>';
    echo '</form>';
}

function showRegistrationForm() {
    echo '<h3>Register</h3>';
    echo '<form method="POST" action="?action=register">';
    echo '<input type="text" name="username" placeholder="Username" required><br>';
    echo '<input type="email" name="email" placeholder="Email" required><br>';
    echo '<input type="password" name="password" placeholder="Password" required><br>';
    echo '<button type="submit">Register</button>';
    echo '</form>';
}