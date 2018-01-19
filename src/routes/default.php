<?php

use Slim\Http\Request;
use Slim\Http\Response;

// Home page
$app->get('/', function ($request, $response, $args) {
    $input = array('site' => 'api.kellenschmidt.com', 'referrer' => null);
    
    // Log information about the visitor whenever the homepage is visited
    logPageVisit($this, $input);

    // Render index view
    return $this->renderer->render($response, 'index.phtml', $args);
    
});
