<?php

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
