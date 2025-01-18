<?php
require_once ($_SERVER['DOCUMENT_ROOT'] . '/database.php');
require_once ($_SERVER['DOCUMENT_ROOT'] . '/vendor/autoload.php');
require_once ($_SERVER['DOCUMENT_ROOT'] . '/middleware/middleware.php');
require_once ($_SERVER['DOCUMENT_ROOT'] . '/helper/response_helper.php');
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class AuthController {


    private $conn;

    public function __construct() {
        $database = new Database();
        $this->conn = $database->connect();
    }

    public function createUser($data) {
        if (!$data['username'] || !$data['password'] || !$data['nick_name']) {
            echo jsonResponse(403, 'Params are wrong');
            return;
        }
        $stmt = $this->conn->prepare("
        SELECT * FROM User WHERE username=:username
        ");
        $stmt->bindParam(':username', $data['username']);
        $stmt->execute();
        $result = $stmt->fetchAll(PDO::FETCH_ASSOC);
        if (!empty($result)) {
            echo jsonResponse(409, 'Account already exists');
            exit;
        }


        $password_hash = md5($data['password']);  // Không an toàn, nên dùng password_hash()
        $stmt = $this->conn->prepare("
            INSERT INTO User (username, password_hash, nick_name) 
            VALUES (:username, :password_hash, :nick_name)
        ");
        $stmt->bindParam(':username', $data['username']);
        $stmt->bindParam(':password_hash', $password_hash);
        $stmt->bindParam(':nick_name', $data['nick_name']);
        
        if ($stmt->execute()) {
            echo jsonResponse(200, 'User created successfully');
            exit;
        } else {
            echo jsonResponse(500, 'Failed to create user');
            exit;
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
            echo jsonResponse(200, 'User updated successfully');
        } else {
            echo jsonResponse(500, 'Failed to update user');
        }
    }

    public function deleteUser($id) {
        $stmt = $this->conn->prepare("DELETE FROM users WHERE uid=:id");
        $stmt->bindParam(':id', $id);
        if ($stmt->execute()) {
            echo jsonResponse(200, 'User deleted successfully');
        } else {
            echo jsonResponse(500, 'Failed to delete user');
        }
    }

    public function login($data) {
        // Get the POST data
        $username = $data['username'] ?? '';
        $password = $data['password'] ?? '';
    
        // Check if username and password are provided
        if (empty($username) || empty($password)) {
            echo jsonResponse(401, 'Username and password are required.');
            return;
        }
    
        // Prepare and execute the query to get the user
        $stmt = $this->conn->prepare("SELECT * FROM User WHERE username=:username LIMIT 1");
        $stmt->bindParam(':username', $username);
        $stmt->execute();
        
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        // Check if user exists and password matches
        if ($user && md5($password) == $user['password_hash']) {
            // You can set a session or token here for login
            // $json = json_encode($this->generateLoginResponse($user['uid'], $user['username']), JSON_PRETTY_PRINT);
            
            echo jsonResponse(200, 'Success',$this->generateLoginResponse($user['uid'], $user['username']));
        } else {

            echo jsonResponse(401, 'Invalid credentials');
        }
    }

    public function generateLoginResponse($userId, $username) {
        $accessToken = $this->generateAccessToken($userId, time());
        $refreshToken = $this->generateRefreshToken($userId, time());
        
      
        global $accessExpIn; 
        global $refreshExpIn;
    
        // Lưu refresh token vào database
        $this->saveToken($userId,$accessToken,date('Y-m-d H:i:s', time() + $accessExpIn));
        $this->saveRefreshToken($userId, $refreshToken, date('Y-m-d H:i:s', time() + $refreshExpIn));
    
        // Trả về payload cho người dùng sau khi đăng nhập
        return [
            "user_id" => $userId,
            "username" => $username,
            "access_token" => $accessToken,
            "refresh_token" => $refreshToken,
            "token_type" => "Bearer",
            "expires_in" => $accessExpIn,
            "refresh_expires_in" => $refreshExpIn
        ];
    }

    // Tạo refresh token
    function generateRefreshToken($userId, $timestamp) {
        global $refreshTokenSK, $tokenAlg;
        global $refreshExpIn;
        $payload = [
            'sub' => $userId,
            'iat' => $timestamp,
            'exp' => $timestamp + $refreshExpIn // Hết hạn sau 30 ngày
        ];
        return JWT::encode($payload, $refreshTokenSK, $tokenAlg);
    }

    public function generateAccessToken($userId, $timestamp) {
        // Khóa bí mật (SECRET_KEY) – cần bảo mật và lưu trữ an toàn
        global $accessTokenSK,$tokenAlg; // Nên lưu trong biến môi trường (ENV)
        
        global $accessExpIn; 
        // Thời gian hết hạn (1 giờ kể từ thời điểm tạo token)
        $issuedAt = $timestamp;
        $expiresAt = $issuedAt + $accessExpIn;  // Token có hiệu lực trong 1 giờ (3600 giây)
    
        // Dữ liệu payload của token
        $payload = [
            'iss' => 'your-app.com',      // Issuer (Người phát hành token)
            'aud' => 'your-app.com',      // Audience (Người nhận token)
            'iat' => $issuedAt,           // Issued at (Thời điểm phát hành)
            'exp' => $expiresAt,          // Expiration (Thời điểm hết hạn)
            'sub' => $userId              // Subject (ID người dùng)
        ];
    
        // Tạo token với thuật toán HS256
        $accessToken = JWT::encode($payload, $accessTokenSK, $tokenAlg);
    
        return $accessToken;
    }

    function saveRefreshToken($userId, $refreshToken, $expiresAt) {


        $stmt = $this->conn->prepare("DELETE FROM refresh_tokens WHERE user_id = ?");
        $stmt->execute([$userId]);

        $sql = "INSERT INTO refresh_tokens (user_id, refresh_token, expires_at) VALUES (?, ?, ?)";
        $stmt = $this->conn->prepare($sql);
        $stmt->execute([$userId, $refreshToken, $expiresAt]);
    }

    function saveToken($userId, $token, $expiresAt) {
        $stmt = $this->conn->prepare("DELETE FROM tokens WHERE user_id = ?");
        $stmt->execute([$userId]);


        $sql = "INSERT INTO tokens (user_id, token, expires_at) VALUES (?, ?, ?)";
        $stmt = $this->conn->prepare($sql);
        $stmt->execute([$userId, $token, $expiresAt]);
    }

    function refreshAccessToken($refreshToken) {
        global $refreshTokenSK, $secretKey, $tokenAlg;
        global $expiresIn, $refreshExpiresIn;
    
        try {
            // Giải mã refresh token
            $decoded = JWT::decode($refreshToken, new Key($refreshTokenSK, $tokenAlg));
            $userId = $decoded->sub;
    
            // Kiểm tra token trong database
            
            $stmt = $this->conn->prepare("SELECT refresh_token FROM refresh_tokens WHERE user_id = ?");
            $stmt->execute([$userId]);
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
    
            if (!$result || $result['refresh_token'] !== $refreshToken) {
                jsonResponse(401,'Refresh token invalid');
                exit;
            }
            $issuedAt = time();
            // Tạo access token mới
            $newAccessToken = $this->generateAccessToken($userId, $issuedAt);
            
            $this->saveToken($userId,$newAccessToken,date('Y-m-d H:i:s', $issuedAt + $expiresIn));

            
            // **Tùy chọn:** Làm mới refresh token
            // $newRefreshToken = $this->generateRefreshToken($userId, $issuedAt);
            // $this->saveRefreshToken($userId, $newRefreshToken, date('Y-m-d H:i:s', $issuedAt + $refreshExpiresIn));
    
            $result = [
                "access_token" => $newAccessToken,
                // "refresh_token" => $newRefreshToken
            ];

            jsonResponse(200,'Success', $result);
    
        } catch (Exception $e) {
            jsonResponse(401,'Refresh token invalid error: "'.$e->getMessage().'"');
            exit;
        }
    }
    
}
?>
