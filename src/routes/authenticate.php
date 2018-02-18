<?php

// Test whether the current jwt of the user's session is valid
$app->post('/authenticate', function ($request, $response, $args) {
    
    try {
        $isAuth = isAuthenticated($request, $this);
    } catch (Exception $e) {
        return $this->response->withJson(array("error" => $e->getMessage()), 403);
    }

    return $this->response->withJson(array("authenticated" => $isAuth));

});
