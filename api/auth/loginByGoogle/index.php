<?php
// header("Content-Type: application/json");
require_once ($_SERVER['DOCUMENT_ROOT'] . '/controllers/auth_controller.php');

$controller = new AuthController();
$method = $_SERVER['REQUEST_METHOD'];
// $request = explode('/', trim($_SERVER['REQUEST_URI'], '/api/'));

switch ($method) {
    case 'POST':
        $data = json_decode(file_get_contents("php://input"), true);
        $controller->loginByGoogle($data);
        break;
    default:
        $controller->jsonResponse(405, 'Method Not Allowed');
        break;
}
?>
