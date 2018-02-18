<?php

// Log information whenever a home page is visited
$app->post('/page-visit', function ($request, $response, $args) {
    $input = $request->getParsedBody();
    
    $return = logPageVisit($this, $input);

    return $this->response->withJson($return);
});
