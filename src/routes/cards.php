<?php

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
