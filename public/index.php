<?php
if (PHP_SAPI == 'cli-server') {
    // To help the built-in PHP dev server, check if the request was actually for
    // something which should probably be served as a static file
    $url  = parse_url($_SERVER['REQUEST_URI']);
    $file = __DIR__ . $url['path'];
    if (is_file($file)) {
        return false;
    }
}

require __DIR__ . '/../vendor/autoload.php';

session_start();

// Instantiate the app
$settings = require __DIR__ . '/../src/settings.php';
$app = new \Slim\App($settings);

// Set up dependencies
require __DIR__ . '/../src/dependencies.php';

// Register middleware
require __DIR__ . '/../src/middleware.php';

// Register routes
// require __DIR__ . '/../src/routes.php';
require __DIR__ . '/../src/routes/functions.php';
require __DIR__ . '/../src/routes/default.php';
require __DIR__ . '/../src/routes/status.php';
require __DIR__ . '/../src/routes/page-visit.php';
require __DIR__ . '/../src/routes/cards.php';
require __DIR__ . '/../src/routes/chips.php';
require __DIR__ . '/../src/routes/courses.php';
require __DIR__ . '/../src/routes/urls.php';
require __DIR__ . '/../src/routes/url-hit.php';
require __DIR__ . '/../src/routes/register.php';
require __DIR__ . '/../src/routes/login.php';
require __DIR__ . '/../src/routes/authenticate.php';

// Run app
$app->run();
