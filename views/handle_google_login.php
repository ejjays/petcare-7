<?php
session_start();
require_once('../config/database.php');

// Verify the Google token
$token = json_decode(file_get_contents('php://input'), true)['token'];

// Verify token using Google API Client Library
// You'll need to install Google API Client Library via composer
require_once 'vendor/autoload.php';
$client = new Google_Client(['client_id' => 'your-client-id']);

try {
    $payload = $client->verifyIdToken($token);
    if ($payload) {
        $email = $payload['email'];
        
        // Check if user exists
        $query = "SELECT user_id, role FROM users WHERE email = ?";
        $stmt = $conn->prepare($query);
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($row = $result->fetch_assoc()) {
            // Existing user - create session
            $_SESSION['user_id'] = $row['user_id'];
            $_SESSION['role'] = $row['role'];
        } else {
            // New user - create account
            $role = 'user';
            $stmt = $conn->prepare("INSERT INTO users (email, role) VALUES (?, ?)");
            $stmt->bind_param("ss", $email, $role);
            $stmt->execute();
            
            $_SESSION['user_id'] = $conn->insert_id;
            $_SESSION['role'] = $role;
        }
        
        echo json_encode(['success' => true]);
    }
} catch (Exception $e) {
    echo json_encode(['success' => false, 'error' => $e->getMessage()]);
}