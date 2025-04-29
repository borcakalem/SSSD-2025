<?php
namespace App;

class Database {
    public $connection;

    public function __construct() {
        $this->connection = new \PDO(
            "mysql:host=localhost;dbname=newwebsite_db",
            "root",
            "",
            [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION]
        );
    }
    public function getUser($username) {
        $stmt = $this->connection->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$username]);
        return $stmt->fetch(\PDO::FETCH_ASSOC);
    }
}
