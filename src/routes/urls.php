<?php

// Return all visible URLs
$app->get('/urls', function ($request, $response, $args) {

    try {
        $isAuth = isAuthenticated($request, $this);
        $userId = getUserIdFromToken($request);
    } catch (Exception $e) {
        return $this->response->withJson(array("error" => $e->getMessage()), 403);
    }

    $getUrlsSql = "SELECT * 
                   FROM links
                   WHERE visible = 1
                   AND user_id = :user_id
                   ORDER BY date_created DESC";
    
    $stmt = $this->db->prepare($getUrlsSql);
    $stmt->bindParam("user_id", $userId);

    try {
        $stmt->execute();
        $urls = $stmt->fetchAll();
    } catch (Exception $e) {
        return $this->response->withJson($e);
    }

    $return = array(
        "data" => $urls
    );

    return $this->response->withJson($return);

});

// Add new short URL to database
$app->post('/url', function ($request, $response, $args) {

    try {
        $isAuth = isAuthenticated($request, $this);
        $userId = getUserIdFromToken($request);
    } catch (Exception $e) {
        return $this->response->withJson(array("error" => $e->getMessage()), 403);
    }

    // Get request body
    $input = $request->getParsedBody();
    $longUrl = $input['long_url'];

    // Prepend long url with http:// if it doesn't have it already
    $prefix = substr($longUrl, 0, 4);
    if($prefix != 'http' && $prefix != 'file') {
        $longUrl = 'http://' . $longUrl;
    }

    // Test if long URL is already in database
    $existingUrlsSql = "SELECT code 
                        FROM links 
                        WHERE long_url = BINARY :long_url
                        AND user_id = :user_id";

    $stmt = $this->db->prepare($existingUrlsSql);
    $stmt->bindParam("long_url", $longUrl);
    $stmt->bindParam("user_id", $userId);

    try {
        $stmt->execute();
        $code = $stmt->fetchObject();
    } catch (Exception $e) {
        return $this->response->withJson($e);
    }

    // Get current datetime
    $currentDateTime = date('Y/m/d H:i:s');

    // If URL is new, generate new code
    if($code == NULL) {
        // Generate new URL code
        do {
            $code = random_str(3);
        } while (isUnusedCode($this, $code) == false);

        $insertUrlSql = "INSERT INTO links 
                         SET code = :code,
                             user_id = :user_id,
                             long_url = :long_url,
                             date_created = :date_created";

        $stmt = $this->db->prepare($insertUrlSql);
        $stmt->bindParam("code", $code);
        $stmt->bindParam("user_id", $userId);
        $stmt->bindParam("long_url", $longUrl);
        $stmt->bindParam("date_created", $currentDateTime);
    }

    // Update URL, URL is already in database
    else {
        $updateUrlSql = "UPDATE links
                         SET date_created = :date_created,
                             visible = 1
                         WHERE code = BINARY :code
                         AND user_id = :user_id";

        $stmt = $this->db->prepare($updateUrlSql);
        $stmt->bindParam("date_created", $currentDateTime);
        $code = $code->code;
        $stmt->bindParam("code", $code);
        $stmt->bindParam("user_id", $userId);
    }

    try {
        $stmt->execute();
    } catch (Exception $e) {
        return $this->response->withJson($e);
    }

    // Get count for newly added/updated link
    $getCountSql = "SELECT count
                    FROM links
                    WHERE code = BINARY :code
                    AND user_id = :user_id";

    $stmt = $this->db->prepare($getCountSql);
    $stmt->bindParam("code", $code);
    $stmt->bindParam("user_id", $userId);

    try {
        $stmt->execute();
        $count = $stmt->fetchObject()->count;
    } catch (Exception $e) {
        return $this->response->withJson($e);
    }

    // Log "create link" interaction
    logInteraction($this, 3, $code);

    $return = array(
        "code" => $code,
        "user_id" => $userId,
        "long_url" => $longUrl,
        "date_created" => $currentDateTime,
        "count" => $count
    );

    return $this->response->withJson($return);

});

// Change the visibility state to hidden
$app->put('/url', function ($request, $response, $args) {

    try {
        $isAuth = isAuthenticated($request, $this);
        $userId = getUserIdFromToken($request);
    } catch (Exception $e) {
        return $this->response->withJson(array("error" => $e->getMessage()), 403);
    }

    $input = $request->getParsedBody();

    $setVisibleSql = "UPDATE links
                      SET visible = 0
                      WHERE code = BINARY :code
                      AND user_id = :user_id";
    
    $stmt = $this->db->prepare($setVisibleSql);
    $stmt->bindParam("code", $input['code']);
    $stmt->bindParam("user_id", $userId);

    try {
        $stmt->execute();
    } catch (Exception $e) {
        return $this->response->withJson($e);
    }

    // Log "remove link" interaction
    logInteraction($this, 1, $input['code']);

    return $this->response->withJson(array("rows_affected" => $stmt->rowCount()));

});
