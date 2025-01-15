<?php
// header("Content-Type: application/json");
require_once ($_SERVER['DOCUMENT_ROOT'] . '/controllers/user_controller.php');

$controller = new UserController();
$method = $_SERVER['REQUEST_METHOD'];
$request = explode('/', trim($_SERVER['REQUEST_URI'], '/api/'));

switch ($method) {
    case 'GET':
        $controller->getMyProfile();
        break;
    // case 'POST':
    //     $data = json_decode(file_get_contents("php://input"), true);
    //     $controller->createUser($data);
    //     break;
    // case 'PUT':
    //     $data = json_decode(file_get_contents("php://input"), true);
    //     $controller->updateUser($request[1], $data);
    //     break;
    // case 'DELETE':
    //     $controller->deleteUser($request[1]);
    //     break;
    default:
        $controller->jsonResponse(405, 'Method Not Allowed');
        break;
}
?>
