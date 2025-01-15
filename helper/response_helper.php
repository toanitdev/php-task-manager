<?php
    function jsonResponse($httpCode, $message, $data = null) {
        http_response_code($httpCode); // Đặt mã HTTP trả về
        header('Content-Type: application/json'); // Đảm bảo định dạng JSON
    
        // Tạo đối tượng JSON chuẩn
        $response = [];

        if($data != null) {
            $response = [
                "http_code" => $httpCode,
                "message" => $message,
                "data" => $data
            ];
        } else {
            $response = [
                "http_code" => $httpCode,
                "message" => $message
            ];
        }
    
        // In ra kết quả dưới dạng JSON
        echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
        exit;
    }
?>