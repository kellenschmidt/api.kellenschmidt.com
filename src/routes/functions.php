<?php

use \Firebase\JWT\JWT;

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
        "iss" => $_SERVER['HTTP_HOST'], // Domain name that issued the token i.e. kellenschmidt.com
        "iat" => time(),
        "exp" => time() + (3600 * 24 * 60), // Expiration time: 60 days
        "sub" => $userId, // user_id of the user that the token is being created for
        "pwd" => $password,
        "ipa" => $ipAddress,
        "bwr" => $browser,
        "os"  => $operating_system
    );
    
    $claims = array_merge($header, $payload);
    
    // Create JWT
    try {
        $jwt = JWT::encode($claims, getenv("JWT_SECRET"));
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
        $decoded = JWT::decode($jwt, getenv("JWT_SECRET"), array('HS256'));
        $iss = $decoded->iss;
        $sub = $decoded->sub;
        $pwd = $decoded->pwd;
        $exp = $decoded->exp;
        $ipa = $decoded->ipa;
        $bwr = $decoded->bwr;
        $os  = $decoded->os;
    } catch (Exception $e) {
        throw new Exception("Malformed/invalid token, " . $e->getMessage());
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
    $domain = $_SERVER['HTTP_HOST'];
    $ipAddress = $_SERVER['REMOTE_ADDR'];
    $user_agent = $_SERVER['HTTP_USER_AGENT'];
    $start = strrpos($user_agent, ')') + 2;
    $end = strrpos($user_agent, ' ');
    $browser = substr($user_agent, $start, $end-$start);
    preg_match('#\((.*?)\)#', $user_agent, $match);
    $operating_system = $match[1];
    
    // $log_file_name = "/var/log/jwt-auth-errors.log";
    // try {
    //     if (!isset($log_file)) {
    //         $log_file = fopen($log_file_name, "w");
    //     }
    // } catch (Exception $e) {
    //     throw new Exception("Failed to open " . $log_file_name);
    // }
    
    $auth_error_sql = "INSERT INTO auth_errors
    SET error_datetime = :error_datetime,
    failed_property = :failed_property,
    jwt_value = :jwt_value,
    browser_value = :browser_value";
    
    $stmt = $_this->db->prepare($auth_error_sql);
    $currentDateTime = date('Y/m/d H:i:s');
    $stmt->bindParam("error_datetime", $currentDateTime);
    $currentTime = time();

    // Check if jwt claims match current user's session
    if($iss != $domain) {
        // $output = "[". date('Y/m/d H:i:s') ."] " . "Failed domain verification" . $iss . " != " . $domain;
        // fwrite($log_file, $output);
        $failed_property = "domain";
        if(!isset($domain)) {
            $domain = "";
        }
        $stmt->bindParam("failed_property", $failed_property);
        $stmt->bindParam("jwt_value", $iss);
        $stmt->bindParam("browser_value", $domain);
        $stmt->execute();
        throw new Exception("Invalid/expired token");
    } else if($ipa != $ipAddress) {
        // $output = "[". date('Y/m/d H:i:s') ."] " . "Failed ip address verification" . $ipa . " != " . $ipAddress;
        // fwrite($log_file, $output);
        $failed_property = "ip address";
        if(!isset($ipAddress)) {
            $ipAddress = "";
        }
        $stmt->bindParam("failed_property", $failed_property);
        $stmt->bindParam("jwt_value", $ipa);
        $stmt->bindParam("browser_value", $ipAddress);
        $stmt->execute();
        throw new Exception("Invalid/expired token");
    } else if($bwr != $browser) {
        // $output = "[". date('Y/m/d H:i:s') ."] " . "Failed browser verification" . $bwr . " != " . $browser;
        // fwrite($log_file, $output);
        $failed_property = "browser";
        if(!isset($browser)) {
            $browser = "";
        }
        $stmt->bindParam("failed_property", $failed_property);
        $stmt->bindParam("jwt_value", $bwr);
        $stmt->bindParam("browser_value", $browser);
        $stmt->execute();
        throw new Exception("Invalid/expired token");
    } else if($os != $operating_system) {
        // $output = "[". date('Y/m/d H:i:s') ."] " . "Failed operating system verification" . $os . " != " . $operating_system;
        // fwrite($log_file, $output);
        $failed_property = "operating system";
        if(!isset($operating_system)) {
            $operating_system = "";
        }
        $stmt->bindParam("failed_property", $failed_property);
        $stmt->bindParam("jwt_value", $os);
        $stmt->bindParam("browser_value", $operating_system);
        $stmt->execute();
        throw new Exception("Invalid/expired token");
    } else if($pwd != $password) {
        // $output = "[". date('Y/m/d H:i:s') ."] " . "Failed password verification" . $pwd . " != " . $password;
        // fwrite($log_file, $output);
        $failed_property = "password";
        if(!isset($password)) {
            $password = "";
        }
        $stmt->bindParam("failed_property", $failed_property);
        $stmt->bindParam("jwt_value", $pwd);
        $stmt->bindParam("browser_value", $password);
        $stmt->execute();
        throw new Exception("Invalid/expired token");
    } else if($exp < $currentTime) {
        // $output = "[". date('Y/m/d H:i:s') ."] " . "Failed time verification" . $exp . " != " . time();
        // fwrite($log_file, $output);
        $failed_property = "time";
        if(!isset($currentTime)) {
            $currentTime = "";
        }
        $stmt->bindParam("failed_property", $failed_property);
        $stmt->bindParam("jwt_value", $exp);
        $stmt->bindParam("browser_value", $currentTime);
        $stmt->execute();
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
        $decoded = JWT::decode($jwt, getenv("JWT_SECRET"), array('HS256'));
        $userId = $decoded->sub;
    } catch (Exception $e) {
        throw new Exception("Malformed/invalid token");
    }
    
    return $userId;
}
