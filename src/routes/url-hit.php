<?php

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
