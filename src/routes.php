<?php

use \Firebase\JWT\JWT;

/*************************************
                Headers
*************************************/

// Set header to allow CORS for cross-domain requests
$http_origin = $_SERVER['HTTP_ORIGIN'];
$regex = "/^(https?:\/\/(?:.+\.)?kellenschmidt\.com(?::\d{1,5})?)$/";

if(preg_match($regex, $http_origin)) {
    header("Access-Control-Allow-Origin: $http_origin");
} else if($_SERVER['HTTP_ORIGIN'] == 'http://localhost:4200') {
    header("Access-Control-Allow-Origin: http://localhost:4200");
} else {
    header("Access-Control-Allow-Origin: null");
}

header('Access-Control-Allow-Methods: GET,PUT,POST,DELETE,PATCH,OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

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
                            WHERE code = BINARY :code";

    $stmt = $_this->db->prepare($get_all_codes_query);
    $stmt->bindParam("code", $testCode);

    try {
        $stmt->execute();
        $code = $stmt->fetchObject();
    } catch (Exception $e) {
        echo json_encode($e);
        return NULL;
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
    $currentDateTime = date('Y/m/d H:i:s');
    $stmt->bindParam("interaction_date", $currentDateTime);

    try {
        $stmt->execute();
    } catch (Exception $e) {
        echo json_encode($e);
        return NULL;
    }
    
}

// Log information about the user and the page that was visited
function logPageVisit($_this, $input) {
    // Get values for setting browser and operating system
    $user_agent = $_SERVER['HTTP_USER_AGENT'];
    preg_match('#\((.*?)\)#', $user_agent, $match);
    $start = strrpos($user_agent, ')') + 2;
    $end = strrpos($user_agent, ' ');

    // If document.referrer exists
    if(isset($input['referrer'])) {
        $referrer = $input['referrer'];
    } else if(isset($_SERVER['HTTP_REFERER'])) {
        $referrer = $_SERVER['HTTP_REFERER'];
    } else {
        $referrer = "";
    }

    // If referrer and site are the same set referrer to blank
    if($input['site'] == substr($referrer, 8, -1)) {
        $referrer = "";
    }
    
    $log_visit_sql = "INSERT INTO page_visits
                      SET site = :site,
                          ip_address = :ip_address,
                          browser = :browser,
                          operating_system = :operating_system,
                          referrer = :referrer,
                          page_visit_datetime = :page_visit_datetime";

    $stmt = $_this->db->prepare($log_visit_sql);
    $stmt->bindParam("site", $input['site']);
    $stmt->bindParam("ip_address", $_SERVER['REMOTE_ADDR']);
    $stmt->bindParam("browser", substr($user_agent, $start, $end-$start));
    $stmt->bindParam("operating_system", $match[1]);
    $stmt->bindParam("referrer", $referrer);
    $currentDateTime = date('Y/m/d H:i:s');
    $stmt->bindParam("page_visit_datetime", $currentDateTime);

    try {
        $stmt->execute();
    } catch (Exception $e) {
        echo json_encode($e);
        return NULL;
    }

    return array('rows_affected' => $stmt->rowCount());
}

function generateToken($email, $_this) {

    // Get token_id for next token to be inserted
    $getNextTokenIdSql = "SHOW TABLE STATUS LIKE 'tokens'";

    $stmt = $_this->db->prepare($getNextTokenIdSql);

    try {
        $stmt->execute();
        $nextTokenId = $stmt->fetchObject()->Auto_increment;
    } catch (Exception $e) {
        echo json_encode($e);
        return NULL;
    }

    // Get user_id for sub of JWT
    $getUserIdSql = "SELECT user_id
                     FROM users
                     WHERE email = :email";

    $stmt = $_this->db->prepare($getUserIdSql);
    $stmt->bindParam("email", $email);
    
    try {
        $stmt->execute();
        $userId = $stmt->fetchObject()->user_id;
    } catch (Exception $e) {
        echo json_encode($e);
        return NULL;
    }

    // Create JWT claims
    $header = array(
        "alg" => "HS256",
        "typ" => "JWT"
    );

    // Get IP address of current browsing session
    $ipAddress = $_SERVER['REMOTE_ADDR'];

    $payload = array(
        "iss" => $_SERVER['HTTP_ORIGIN'], // Domain name that issued the token i.e. https://kellenschmidt.com
        "iat" => time(),
        "exp" => time() + (3600 * 24 * 30), // Expiration time: 30 days
        "jti" => $nextTokenId, // token_id of the token that is being created
        "sub" => $userId, // user_id of the user that the token is being created for
        "ipa" => $ipAddress
    );

    $claims = array_merge($header, $payload);

    // Create JWT
    try {
        $jwt = JWT::encode($claims, getenv('JWT_SECRET'));
    } catch (Exception $e) {
        echo json_encode($e);
        return NULL;
    }

    // Remove old JWTs from database
    $removeOldTokensSql = "DELETE FROM tokens
                           WHERE user_id = :user_id
                           AND ip_address = :ip_address";

    $stmt = $_this->db->prepare($removeOldTokensSql);
    $stmt->bindParam("user_id", $payload['sub']);
    $stmt->bindParam("ip_address", $ipAddress);

    try {
        $stmt->execute();
    } catch (Exception $e) {
        echo json_encode($e);
        return NULL;
    }

    // Insert JWT into database
    $insertTokenSql = "INSERT INTO tokens
                       SET user_id = :user_id,
                           token = :token,
                           ip_address = :ip_address,
                           creation_date = :creation_date,
                           expiration_date = :expiration_date";

    $stmt = $_this->db->prepare($insertTokenSql);
    $stmt->bindParam("user_id", $payload['sub']);
    $stmt->bindParam("token", $jwt);
    $stmt->bindParam("ip_address", $ipAddress);
    $stmt->bindParam("creation_date", $payload['iat']);
    $stmt->bindParam("expiration_date", $payload['exp']);

    try {
        $stmt->execute();
    } catch (Exception $e) {
        echo json_encode($e);
        return NULL;
    }

    // Return JWT
    return $jwt;
}

function isAuthenticated($jwt, $_this) {

}


// Use token to get user_id from tokens table
function getUserIdFromToken($_request, $_this) {

    $jwt = $_request->getHeaders()['HTTP_AUTHORIZATION'][0];

    // Return user_id of -1 when no authorization given
    if(empty($jwt)) {
        return -1;
    }
    
    $getUser = "SELECT user_id
                FROM tokens
                WHERE token = :token";
    
    $stmt = $_this->db->prepare($getUser);
    $stmt->bindParam("token", $jwt);
    
    try {
        $stmt->execute();
        $userId = $stmt->fetchObject()->user_id;
    } catch (Exception $e) {
        echo json_encode($e);
        return NULL;
    }

    // Return error if token could not be found
    if(empty($userId)) {
        echo json_encode(array("error" => "Token could not be found"));
        return NULL;
    }

    return $userId;
}

/*************************************
                Routes
*************************************/

// Home page
$app->get('/', function ($request, $response, $args) {
    $input = array('site' => 'api.kellenschmidt.com', 'referrer' => null);
    
    // Log information about the visitor whenever the homepage is visited
    logPageVisit($this, $input);

    // Render index view
    return $this->renderer->render($response, 'index.phtml', $args);
    
});

// Log information whenever a home page is visited
$app->get('/test', function ($request, $response, $args) {
    
    return $this->response->withJson(array("Does_it_work" => true));
});

// Log information whenever a home page is visited
$app->post('/page-visit', function ($request, $response, $args) {
    $input = $request->getParsedBody();
    
    $return = logPageVisit($this, $input);

    return $this->response->withJson($return);
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

// Return all visible URLs
$app->get('/urls', function ($request, $response, $args) {

    // Get user_id from jwt in authorization header
    $userId = getUserIdFromToken($request, $this);

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

    // Get user_id from jwt in authorization header
    $userId = getUserIdFromToken($request, $this);

    // Get request body
    $input = $request->getParsedBody();
    $longUrl = $input['long_url'];

    // Prepend long url with http:// if it doesn't have it already
    if(substr($longUrl, 0, 4) != 'http') {
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

    // Get user_id from jwt in authorization header
    $userId = getUserIdFromToken($request, $this);

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

// Increment number of page visits when page is visited
$app->post('/hit/[{code}]', function ($request, $response, $args) {

    $incrementCountSql = "UPDATE links
                          SET count = count + 1
                          WHERE code = BINARY :code";
    
    $stmt = $this->db->prepare($incrementCountSql);
    $stmt->bindParam("code", $args['code']);
    
    try {
        $stmt->execute();
    } catch (Exception $e) {
        return $this->response->withJson($e);
    }

    $getLinkSql = "SELECT long_url
                   FROM links
                   WHERE code = BINARY :code";

    $stmt = $this->db->prepare($getLinkSql);
    $stmt->bindParam("code", $args['code']);

    try {
        $stmt->execute();
        $long_url = $stmt->fetchObject()->long_url;
    } catch (Exception $e) {
        return $this->response->withJson($e);
    }

    // Log "click link" interaction
    logInteraction($this, 2, $args['code']);

    return $this->response->withJson(array("long_url" => $long_url));

});

$app->post('/urlshortener/register', function ($request, $response, $args) {
    
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
        return $this->response->withJson(array("error" => "Email already exists"));
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

$app->post('/urlshortener/login', function ($request, $response, $args) {
    
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
        return $this->response->withJson(array("error" => "No user with the given email"));
    }

    // Check if hash of entered password matches hashed password in database
    if(!password_verify($requestArgs['password'], $user['password'])) {
        // If no, return invalid password error
        return $this->response->withJson(array("error" => "Email/password combination is incorrect"));
    }

    // Delete exisiting token(s) for user_id retrieved from SQL query
    $deleteOldTokensSql = "DELETE FROM tokens
                           WHERE user_id = :user_id
                           AND ip_address = :ip_address";

    $stmt = $this->db->prepare($deleteOldTokensSql);
    $stmt->bindParam("user_id", $user['user_id']);
    $stmt->bindParam("ip_address", $_SERVER['REMOTE_ADDR']);
    
    try {
        $stmt->execute();
    } catch (Exception $e) {
        return $this->response->withJson($e);
    }

    // Generate new token
    $token = generateToken($requestArgs['email'], $this);
    
    // Return combined array with token and data about user
    return $this->response->withJson(array("token" => $token, "user" => $user));

});

$app->post('/urlshortener/logout', function ($request, $response, $args) {
    
    $token = $request->getHeaders()['HTTP_AUTHORIZATION'][0];
    
    $deleteToken = "DELETE FROM tokens
                    WHERE token = :token";
    
    $stmt = $this->db->prepare($deleteToken);
    $stmt->bindParam("token", $token);
    
    try {
        $stmt->execute();
    } catch (Exception $e) {
        return $this->response->withJson($e);
    }

    return $this->response->withJson(array("rows_affected" => $stmt->rowCount()));

});
