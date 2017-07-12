<?php

/*************************************
                Functions
*************************************/

/* Generate a random string, using a cryptographically secure 
 * pseudorandom number generator (random_int)
 *
 * @param int $length      How many characters do we want?
 * @param string $keyspace A string of all possible characters
 *                         to select from
 * @return string
 */
 function random_str($length, $keyspace = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_') {
    $str = '';
    $max = mb_strlen($keyspace, '8bit') - 1;
    for ($i = 0; $i < $length; ++$i) {
        $str .= $keyspace[random_int(0, $max)];
    }
    return $str;
}

// Test whether URL code is already in use or not
function isUnusedCode($_this, $testCode) {
    // Create and execute query to get all codes in database
    $get_all_codes_query = "SELECT * 
                            FROM links
                            WHERE code = :code";

    $stmt = $_this->db->prepare($get_all_codes_query);
    $stmt->bindParam("code", $testCode);

    try {
        $stmt->execute();
        $code = $stmt->fetchObject();
    } catch (Exception $e) {
        return $_this->response->withJson($e);
    }

    if($code == NULL) {
        return true;
    } else {
        return false;
    }
}

// Add row to database with data about interaction
function logInteraction($_this, $type, $code) {
    // Get user data
    $ip_address = $_SERVER['REMOTE_ADDR'];
    $user_agent = $_SERVER['HTTP_USER_AGENT'];
    preg_match('#\((.*?)\)#', $user_agent, $match);
    $start = strrpos($user_agent, ')') + 2;
    $end = strrpos($user_agent, ' ');
    $browser = substr($user_agent, $start, $end-$start);
    $operating_system = $match[1];

    $add_interaction_sql = "INSERT INTO interactions
                            SET interaction_type = :interaction_type,
                                code = :code,
                                ip_address = :ip_address,
                                browser = :browser,
                                operating_system = :operating_system,
                                interaction_date = :interaction_date";
    
    $stmt = $_this->db->prepare($add_interaction_sql);
    $stmt->bindParam("interaction_type", $type);
    $stmt->bindParam("code", $code);
    $stmt->bindParam("ip_address", $ip_address);
    $stmt->bindParam("browser", $browser);
    $stmt->bindParam("operating_system", $operating_system);
    $stmt->bindParam("interaction_date", date('Y-m-d H:i:s'));

    try {
        $stmt->execute();
    } catch (Exception $e) {
        return $_this->response->withJson($e);
    }
    
}

/*************************************
                Routes
*************************************/

// Home page
$app->get('/', function ($request, $response, $args) {

    // Get ServerName user is hitting
    $server_name = $_SERVER['SERVER_NAME'];
    
    // Log "visit page" interaction
    logInteraction($this, 0, $server_name);

    // Render index view
    return $this->renderer->render($response, 'index.phtml', $args);
    
});

// Log home page visit interaction
$app->post('/page-visit', function ($request, $response, $args) {
    
    // Get ServerName user is hitting
    $server_name = $_SERVER['SERVER_NAME'];
    
    // Log "visit page" interaction
    logInteraction($this, 0, $server_name);

});

// Get content to put in modal
$app->get('/modal/[{name}]', function ($request, $response, $args) {

    $get_modal_sql = "SELECT * 
                      FROM modal_content
                      WHERE name = :name";

    $stmt = $this->db->prepare($get_modal_sql);
    $stmt->bindParam("name", $args['name']);

    try {
        $stmt->execute();
        $modal = $stmt->fetchObject();
    } catch (Exception $e) {
        return $this->response->withJson($e);
    }

    return $this->response->withJson($modal);

});

// Return all URLs
$app->get('/urls', function ($request, $response, $args) {

    $get_urls_sql = "SELECT * 
                     FROM links";
    $stmt = $this->db->prepare($get_urls_sql);

    try {
        $stmt->execute();
        $urls = $stmt->fetchAll();
    } catch (Exception $e) {
        return $this->response->withJson($e);
    }

    return $this->response->withJson($urls);

});

// Add new short URL to database
$app->post('/url', function ($request, $response, $args) {

    $input = $request->getParsedBody();

    // Test if long URL is already in database
    $existing_urls_query = "SELECT code 
                            FROM links 
                            WHERE long_url = :long_url";

    $stmt = $this->db->prepare($existing_urls_query);
    $stmt->bindParam("long_url", $input['long_url']);

    try {
        $stmt->execute();
        $code = $stmt->fetchObject();
    } catch (Exception $e) {
        return $this->response->withJson($e);
    }

    // Get current datetime
    $currentDateTime = date('Y-m-d H:i:s');

    // If URL is new, generate new code
    if($code == NULL) {
        // Generate new URL code
        do {
            $code = random_str(3);
        } while (isUnusedCode($this, $code) == false);

        $insert_url_sql = "INSERT INTO links 
                           SET code = :code,
                               long_url = :long_url,
                               date_created = :date_created";

        $stmt = $this->db->prepare($insert_url_sql);
        $stmt->bindParam("code", $code);
        $stmt->bindParam("long_url", $input['long_url']);
        $stmt->bindParam("date_created", $currentDateTime);
    }

    // Update URL, URL is already in database
    else {
        $update_url_sql = "UPDATE links
                           SET date_created = :date_created,
                               visible = 1
                           WHERE code = :code";

        $stmt = $this->db->prepare($update_url_sql);
        $stmt->bindParam("date_created", $currentDateTime);
        $code = $code->code;
        $stmt->bindParam("code", $code);
    }

    try {
        $stmt->execute();
    } catch (Exception $e) {
        return $this->response->withJson($e);
    }

    // Log "create link" interaction
    logInteraction($this, 3, $code);

    $return = array(
        "code" => $code,
        "date_created" => $currentDateTime
    );

    return $this->response->withJson($return);

});

// Change the visibility state to hidden
$app->put('/url', function ($request, $response, $args) {

    $input = $request->getParsedBody();

    $set_visible_sql = "UPDATE links
                        SET visible = 0
                        WHERE code = :code";
    
    $stmt = $this->db->prepare($set_visible_sql);
    $stmt->bindParam("code", $input['code']);

    try {
        $stmt->execute();
    } catch (Exception $e) {
        return $this->response->withJson($e);
    }

    // Log "remove link" interaction
    logInteraction($this, 1, $input['code']);

    return $this->response->withJson(array("rows affected" => $stmt->rowCount()));

});

// Increment number of page visits when page is visited
$app->put('/hit/[{code}]', function ($request, $response, $args) {

    $increment_count_sql = "UPDATE links
                            SET count = count + 1
                            WHERE code = :code";
    
    $stmt = $this->db->prepare($increment_count_sql);
    $stmt->bindParam("code", $args['code']);
    
    try {
        $stmt->execute();
    } catch (Exception $e) {
        return $this->response->withJson($e);
    }

    // Log "click link" interaction
    logInteraction($this, 2, $args['code']);

    return $this->response->withJson(array("rows affected" => $stmt->rowCount()));

});