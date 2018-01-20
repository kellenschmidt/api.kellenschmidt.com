<?php

// Create a new user in the database and return the new user and a jwt
$app->post('/register', function ($request, $response, $args) {
    
    $requestArgs = $request->getParsedBody();

    $getExisitingUserSql = "SELECT email
                            FROM users
                            WHERE email = :email";

    $stmt = $this->db->prepare($getExisitingUserSql);
    $stmt->bindParam("email", $requestArgs['email']);
    
    try {
        $stmt->execute();
    } catch (Exception $e) {
        return $this->response->withJson($e);
    }

    // Return error if email already exists in database
    if($stmt->fetchObject() != NULL) {
        return $this->response->withJson(array("element" => "email", "error" => "emailAlreadyExists"), 403);
    }

    // Hash user's password
    $hashedPassword = password_hash($requestArgs['password'], PASSWORD_DEFAULT);

    // Continue as normal because account does already exist
    $insertUserSql = "INSERT INTO users
                        SET email = :email,
                            name = :name,
                            phone = :phone,
                            password = :password"; // Defaults set for creation_date, updated_date, verified_phone

    $stmt = $this->db->prepare($insertUserSql);
    $stmt->bindParam("email", $requestArgs['email']);
    $stmt->bindParam("name", $requestArgs['name']);
    $stmt->bindParam("phone", $requestArgs['phone']);
    $stmt->bindParam("password", $hashedPassword);

    try {
        $stmt->execute();
    } catch (Exception $e) {
        return $this->response->withJson($e);
    }

    // Generate token
    $token = generateToken($requestArgs['email'], $this);

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

    // Return combined array with token and data about user
    return $this->response->withJson(array("token" => $token, "user" => $user));
    
});
