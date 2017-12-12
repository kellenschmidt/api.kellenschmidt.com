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

    if($input['site'] === "localhost") {
        return array('rows_affected' => 0);
    }

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

// Generate a JWT using info about the current user and session
function generateToken($email, $_this) {

    // Get user_id for sub of JWT
    $getUserIdSql = "SELECT user_id, password
                     FROM users
                     WHERE email = :email";

    $stmt = $_this->db->prepare($getUserIdSql);
    $stmt->bindParam("email", $email);
    
    try {
        $stmt->execute();
        $object = $stmt->fetchObject();
        $userId = $object->user_id;
        $password = $object->password;
    } catch (Exception $e) {
        echo json_encode($e);
        return NULL;
    }

    // Create JWT claims
    $header = array(
        "alg" => "HS256",
        "typ" => "JWT"
    );

    // Get data about current browsing session
    $ipAddress = $_SERVER['REMOTE_ADDR'];
    $user_agent = $_SERVER['HTTP_USER_AGENT'];
    preg_match('#\((.*?)\)#', $user_agent, $match);
    $start = strrpos($user_agent, ')') + 2;
    $end = strrpos($user_agent, ' ');
    $browser = substr($user_agent, $start, $end-$start);
    $operating_system = $match[1];

    $payload = array(
        "iss" => $_SERVER['HTTP_ORIGIN'], // Domain name that issued the token i.e. https://kellenschmidt.com
        "iat" => time(),
        "exp" => time() + (3600 * 24 * 30), // Expiration time: 30 days
        "sub" => $userId, // user_id of the user that the token is being created for
        "pwd" => $password,
        "ipa" => $ipAddress,
        "bwr" => $browser,
        "os"  => $operating_system
    );

    $claims = array_merge($header, $payload);

    // Create JWT
    try {
        $jwt = JWT::encode($claims, getenv('JWT_SECRET'));
    } catch (Exception $e) {
        echo json_encode($e);
        return NULL;
    }

    // Return JWT
    return $jwt;
}

// Test whether JWT from http header is valid
function isAuthenticated($_request, $_this) {

    $jwt = $_request->getHeaders()['HTTP_AUTHORIZATION'][0];

    // Throw exception when no authorization given
    if(empty($jwt)) {
        return false;
    }

    // Get claims from JWT
    try {
        $decoded = JWT::decode($jwt, getenv('JWT_SECRET'), array('HS256'));
        $iss = $decoded->iss;
        $sub = $decoded->sub;
        $pwd = $decoded->pwd;
        $exp = $decoded->exp;
        $ipa = $decoded->ipa;
        $bwr = $decoded->bwr;
        $os  = $decoded->os;
    } catch (Exception $e) {
        throw new Exception("Malformed/invalid token");
    }

    $getUserPasswordSql = "SELECT password
                           FROM users
                           WHERE user_id = :user_id";

    $stmt = $_this->db->prepare($getUserPasswordSql);
    $stmt->bindParam("user_id", $sub);

    try {
        $stmt->execute();
        $password = $stmt->fetchObject()->password;
    } catch (Exception $e) {
        echo json_encode($e);
        return NULL;
    }

    // Get data about current browsing session
    $domain = $_SERVER['HTTP_ORIGIN'];
    $ipAddress = $_SERVER['REMOTE_ADDR'];
    $user_agent = $_SERVER['HTTP_USER_AGENT'];
    preg_match('#\((.*?)\)#', $user_agent, $match);
    $start = strrpos($user_agent, ')') + 2;
    $end = strrpos($user_agent, ' ');
    $browser = substr($user_agent, $start, $end-$start);
    $operating_system = $match[1];

    // Check if jwt claims match current user's session
    if($iss != $domain || $ipa != $ipAddress || $bwr != $browser || $os != $operating_system || $pwd != $password || $exp < time()) {
        throw new Exception("Invalid/expired token");
    }

    // Return true (is authenticated)
    return true;
}


// Get user_id from token claim given token is already authenticated
function getUserIdFromToken($_request) {

    $jwt = $_request->getHeaders()['HTTP_AUTHORIZATION'][0];

    // Return user_id of -1 when no authorization given
    if(empty($jwt)) {
        return -1;
    }

    // Get user_id from sub (subject) claim of JWT
    try {
        $decoded = JWT::decode($jwt, getenv('JWT_SECRET'), array('HS256'));
        $userId = $decoded->sub;
    } catch (Exception $e) {
        throw new Exception("Malformed/invalid token");
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

// Return true if the API is not broken
$app->get('/status', function ($request, $response, $args) {
    
    return $this->response->withJson(array("Does it work?" => true));
});

// Log information whenever a home page is visited
$app->post('/page-visit', function ($request, $response, $args) {
    $input = $request->getParsedBody();
    
    $return = logPageVisit($this, $input);

    return $this->response->withJson($return);
});

// Get content to put in modal
$app->get('/modal/[{name}]', function ($request, $response, $args) {

    $getModalSql = "SELECT * 
                    FROM modal_content
                    WHERE name = :name";

    $stmt = $this->db->prepare($getModalSql);
    $stmt->bindParam("name", $args['name']);

    try {
        $stmt->execute();
        $modal = $stmt->fetchObject();
    } catch (Exception $e) {
        return $this->response->withJson($e);
    }

    return $this->response->withJson($modal);

});

// Get content for project or work experience cards
$app->get('/cards/[{type}]', function ($request, $response, $args) {
    
    $getCardsSql = "SELECT *
                    FROM card_content
                    WHERE card_type = :card_type
                    AND visible = 1
                    ORDER BY card_id ASC";

    $stmt = $this->db->prepare($getCardsSql);
    $stmt->bindParam("card_type", $args['type']);

    try {
        $stmt->execute();
        $cards = $stmt->fetchAll();
    } catch (Exception $e) {
        return $this->response->withJson($e);
    }

    $return = array(
        "data" => $cards
    );

    return $this->response->withJson($return);

});

// Get content for skills chips and category headings
$app->get('/chips', function ($request, $response, $args) {
    
    $getChipsSql = "SELECT *
                    FROM chip_content
                    WHERE visible = 1
                    ORDER BY chip_id ASC";

    $stmt = $this->db->prepare($getChipsSql);

    try {
        $stmt->execute();
        $cards = $stmt->fetchAll();
    } catch (Exception $e) {
        return $this->response->withJson($e);
    }

    $return = array(
        "data" => $cards
    );

    return $this->response->withJson($return);

});

// Get content for courses carousel
$app->get('/courses', function ($request, $response, $args) {
    
    $getCoursesSql = "SELECT *
                      FROM course_content
                      WHERE visible = 1
                      ORDER BY course_id ASC";

    $stmt = $this->db->prepare($getCoursesSql);

    try {
        $stmt->execute();
        $courses = $stmt->fetchAll();
    } catch (Exception $e) {
        return $this->response->withJson($e);
    }

    foreach($courses as &$course) {
        $newLineBreaks = array();

        // Create expanded array with length equal to line break quantity
        // for($i = 0; $i < intval($course['line_breaks']); ++$i) {
        //     array_push($newLineBreaks, $i);
        // }

        // Create array with single element for line break quantity
        array_push($newLineBreaks, intval($course['line_breaks']));
        $course['line_breaks'] = $newLineBreaks;
    }
    unset($course); // break the reference with the last element

    // Group array into arrays of 3 courses
    $groupedCourses = array();
    for ($i = 0; $i < count($courses); $i += 3) {
        array_push($groupedCourses, array_slice($courses, $i, 3));
    }

    $return = array(
        "data" => $groupedCourses
    );

    return $this->response->withJson($return);

});

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

// Create a new user in the database and return the new user and a jwt
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

// Test the user's login credentials and return a jwt if valid
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

// Test whether the current jwt of the user's session is valid
$app->post('/urlshortener/authenticate', function ($request, $response, $args) {
    
    try {
        $isAuth = isAuthenticated($request, $this);
    } catch (Exception $e) {
        return $this->response->withJson(array("error" => $e->getMessage()), 403);
    }

    return $this->response->withJson(array("authenticated" => $isAuth));

});

// For use with CSE 5323 Lab 1. Returns image URLs from database
$app->get('/mslc-urls', function ($request, $response, $args) {
    
    $getMSLCUrlsSql = "SELECT url
                       FROM mslc_urls";

    $stmt = $this->db->prepare($getMSLCUrlsSql);

    try {
        $stmt->execute();
        $MSLCUrls = $stmt->fetchAll();
    } catch (Exception $e) {
        return $this->response->withJson($e);
    }

    $return = array(
        "data" => $MSLCUrls
    );

    return $this->response->withJson($return);

});