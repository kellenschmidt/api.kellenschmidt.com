<?php

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
