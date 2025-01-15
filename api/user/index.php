<?php
// header("Content-Type: application/json");
require_once ($_SERVER['DOCUMENT_ROOT'] . '/controllers/user_controller.php');

$controller = new UserController();
$method = $_SERVER['REQUEST_METHOD'];
$request = explode('/', trim($_SERVER['REQUEST_URI'], '/api/'));

switch ($method) {
    case 'GET':
        $controller->getUsers();
        break;
    default:
        $controller->jsonResponse(405, 'Method Not Allowed');
        break;
}
?>
