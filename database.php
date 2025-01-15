<?php


require __DIR__ . '/vendor/autoload.php';

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

// Sử dụng các biến môi trường
$dbHost = $_ENV['DB_HOST'];
$dbName = $_ENV['DB_NAME'];
$dbUser = $_ENV['DB_USER'];
$dbPassword = $_ENV['DB_PASSWORD'];

class Database {
    private $host;
    private $db_name;
    private $username;
    private $password;
    public $conn;


    // Constructor để khởi tạo giá trị từ biến môi trường
    public function __construct() {

        global $dbHost, $dbName, $dbUser, $dbPassword;

        $this->host = $dbHost;
        $this->db_name = $dbName;
        $this->username = $dbUser;
        $this->password = $dbPassword;
    }

    public function connect() {
        $this->conn = null;
        try {
            $this->conn = new PDO("mysql:host=" . $this->host . ";dbname=" . $this->db_name, 
                                  $this->username, $this->password);
            $this->conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        } catch(PDOException $e) {
            echo "Lỗi kết nối: " . $e->getMessage();
        }
        return $this->conn;
    }
}
?>