<?php
session_start();
require_once('../config/database.php');
require_once 'vendor/autoload.php'; // You'll need to install Google API PHP client library

// Google API client configuration
$client = new Google_Client([
    'client_id' => '45592183048-24gcf76rhb00kfbbo1k690g13h6bh54h.apps.googleusercontent.com',
    'client_secret' => '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'
]);

// Get POST data
$data = json_decode(file_get_contents('php://input'), true);

if (isset($data['token']) && isset($data['email'])) {
    try {
        // Verify the token
        $payload = $client->verifyIdToken($data['token']);
        
        if ($payload) {
            $email = filter_var($data['email'], FILTER_SANITIZE_EMAIL);
            $name = $data['name'];
            
            // Check if user exists
            $query = "SELECT user_id, role FROM users WHERE email = ?";
            $stmt = $conn->prepare($query);
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $result = $stmt->get_result();
            
            if ($row = $result->fetch_assoc()) {
                // User exists - log them in
                $_SESSION['user_id'] = $row['user_id'];
                $_SESSION['role'] = $row['role'];
                echo json_encode(['success' => true]);
            } else {
                // Create new user
                $conn->begin_transaction();
                
                try {
                    // Insert into users table
                    $role = 'user';
                    $password_hash = password_hash(uniqid(), PASSWORD_DEFAULT); // Random password
                    
                    $userQuery = "INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)";
                    $userStmt = $conn->prepare($userQuery);
                    $userStmt->bind_param("sss", $email, $password_hash, $role);
                    $userStmt->execute();
                    
                    $userId = $conn->insert_id;
                    
                    // Split name into first and last name
                    $names = explode(" ", $name, 2);
                    $firstName = $names[0];
                    $lastName = isset($names[1]) ? $names[1] : '';
                    
                    // Insert into user_profiles table
                    $profileQuery = "INSERT INTO user_profiles (user_id, first_name, last_name) VALUES (?, ?, ?)";
                    $profileStmt = $conn->prepare($profileQuery);
                    $profileStmt->bind_param("iss", $userId, $firstName, $lastName);
                    $profileStmt->execute();
                    
                    $conn->commit();
                    
                    $_SESSION['user_id'] = $userId;
                    $_SESSION['role'] = 'user';
                    
                    echo json_encode(['success' => true]);
                    
                } catch (Exception $e) {
                    $conn->rollback();
                    echo json_encode(['success' => false, 'message' => 'Registration failed']);
                }
            }
        } else {
            echo json_encode(['success' => false, 'message' => 'Invalid token']);
        }
    } catch (Exception $e) {
        echo json_encode(['success' => false, 'message' => 'Token verification failed']);
    }
} else {
    echo json_encode(['success' => false, 'message' => 'Invalid data']);
}
?>