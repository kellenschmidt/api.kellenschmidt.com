<?php

// Return true if the API is not broken
$app->get('/status', function ($request, $response, $args) {
    
    return $this->response->withJson(array("Does it work?" => true));
});
