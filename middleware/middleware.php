<?php

require_once ($_SERVER['DOCUMENT_ROOT'] . '/vendor/autoload.php');
require_once ($_SERVER['DOCUMENT_ROOT'] . '/helper/response_helper.php');
use Firebase\JWT\JWT;
use Firebase\JWT\Key;


$accessTokenSK = $_ENV['SECRET_KEY'];
$refreshTokenSK = $_ENV['REFRESH_SECRET_KEY'];
$accessExpIn = $_ENV['ACCESS_TOKEN_EXP_IN'];
$refreshExpIn = $_ENV['REFRESH_TOKEN_EXP_IN'];
$tokenAlg = $_ENV['TOKEN_ALG'];

function checkToken() {
    global $accessTokenSK, $tokenAlg;

    $headers = getallheaders();
    if (!isset($headers['Authorization'])) {
        http_response_code(401);
        echo json_encode(["message" => "No access token"]);
        exit;
    }

    $authHeader = $headers['Authorization'];
    if (!preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
        http_response_code(401);
        echo json_encode(["message" => "Token không hợp lệ"]);
        exit;
    }

    $token = $matches[1];

    try {
        $decoded = JWT::decode($token, new Key($accessTokenSK, $tokenAlg));

        $current_time = time();
        if ($decoded->exp < $current_time) {
            jsonResponse(401, 'Token expiried');
            exit;
        }
        if (!isTokenValid($decoded->sub, $token)) {
            jsonResponse(401, 'Token invalid or expiried');
            exit;
        }

        return $decoded;
    } catch (Exception $e) {
        jsonResponse(401, 'Token invalid or expiried error: '.$e->getMessage().'');
        exit;
    }

   
}

function isTokenValid($userId, $refreshToken) {

    $database = new Database();
    $pdo = $database->connect();
    

    $stmt = $pdo->prepare("SELECT token FROM tokens WHERE user_id = ?");
    $stmt->execute([$userId]);

    $result = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$result || $result['token'] !== $refreshToken) {
        return false;
    }
    return true; 
}
?>
