<?php
require_once ($_SERVER['DOCUMENT_ROOT'] . '/database.php');
require_once ($_SERVER['DOCUMENT_ROOT'] . '/vendor/autoload.php');
require_once ($_SERVER['DOCUMENT_ROOT'] . '/middleware/middleware.php');
require_once ($_SERVER['DOCUMENT_ROOT'] . '/helper/response_helper.php');
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class UserController {


    private $conn;

    public function __construct() {
        $database = new Database();
        $this->conn = $database->connect();
    }

    public function createUser($data) {
        if (!$data['username'] || !$data['password'] || !$data['nick_name']) {
            echo json_encode(["message" => "Thiếu dữ liệu"]);
            return;
        }

        $password_hash = md5($data['password']);  // Không an toàn, nên dùng password_hash()
        $stmt = $this->conn->prepare("
            INSERT INTO user (username, password_hash, nick_name) 
            VALUES (:username, :password_hash, :nick_name)
        ");
        $stmt->bindParam(':username', $data['username']);
        $stmt->bindParam(':password_hash', $password_hash);
        $stmt->bindParam(':nick_name', $data['nick_name']);
        
        if ($stmt->execute()) {
            echo json_encode(["message" => "User created successfully"]);
        } else {
            echo json_encode(["message" => "Failed to create user"]);
        }
    }

    public function getUsers() {
        $decoded = checkToken();
        $stmt = $this->conn->prepare("SELECT uid, username, nick_name FROM User");
        $stmt->execute();
        $result = $stmt->fetchAll(PDO::FETCH_ASSOC);
        if (!empty($result)) {
            jsonResponse(200,'Success',$result);
        } else {
            jsonResponse(404,'Not found');
        }
    }

    public function getMyProfile() {
        $decoded = checkToken();
        $stmt = $this->conn->prepare("SELECT uid, username, nick_name FROM User WHERE uid=:uid   LIMIT 1");

        $stmt->bindParam(':uid', $decoded->sub);
        $stmt->execute();
        $result = $stmt->fetchAll(PDO::FETCH_ASSOC);
        if (!empty($result)) {
            jsonResponse(200,'Success',$result[0]);
        } else {
            jsonResponse(404,'Not found');
        }

        
    }


    public function updateUser($id, $data) {
        $stmt = $this->conn->prepare("
            UPDATE user SET username=:username, nick_name=:nick_name 
            WHERE uid=:id
        ");
        $stmt->bindParam(':username', $data['username']);
        $stmt->bindParam(':nick_name', $data['nick_name']);
        $stmt->bindParam(':id', $id);
        
        if ($stmt->execute()) {
            echo json_encode(["message" => "User updated successfully"]);
        } else {
            echo json_encode(["message" => "Failed to update user"]);
        }
    }

    public function deleteUser($id) {
        $stmt = $this->conn->prepare("DELETE FROM users WHERE uid=:id");
        $stmt->bindParam(':id', $id);
        if ($stmt->execute()) {
            echo json_encode(["message" => "User deleted successfully"]);
        } else {
            echo json_encode(["message" => "Failed to delete user"]);
        }
    }
}
?>
