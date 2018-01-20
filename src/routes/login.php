<?php

// Test the user's login credentials and return a jwt if valid
$app->post('/login', function ($request, $response, $args) {
    
    $requestArgs = $request->getParsedBody();

    // SQL query to get db data for user with entered email
    $getUserSql = "SELECT *
                   FROM users
                   WHERE email = :email";

    $stmt = $this->db->prepare($getUserSql);
    $stmt->bindParam("email", $requestArgs['email']);
    
    try {
        $stmt->execute();
        $user = $stmt->fetch();
    } catch (Exception $e) {
        return $this->response->withJson($e);
    }
    // Return error if email does not exist in database
    if($user == NULL) {
        return $this->response->withJson(array("element" => "email", "error" => "noUserGivenEmail"), 403);
    }

    // Check if hash of entered password matches hashed password in database
    if(!password_verify($requestArgs['password'], $user['password'])) {
        // If no, return invalid password error
        return $this->response->withJson(array("element" => "password", "error" => "wrongPassword"), 403);
    }

    // Generate new token
    $token = generateToken($requestArgs['email'], $this);
    
    // Return combined array with token and data about user
    return $this->response->withJson(array("token" => $token, "user" => $user));

});
