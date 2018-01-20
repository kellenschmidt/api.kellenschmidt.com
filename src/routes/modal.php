<?php

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
