<?php

$app->add(new Tuupola\Middleware\CorsMiddleware([
    "origin" => ['http?://*.kellenschmidt.com','http?://kellenschmidt.com','http://*.kspw','http://kspw'],
    "methods" => ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    "headers.allow" => ["Authorization"],
    "headers.expose" => [],
    "credentials" => false,
    "cache" => 0,
]));
