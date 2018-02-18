<?php

// Define regex for comparison with cross-domain origins
$http_origin = $_SERVER['HTTP_ORIGIN'];
$kellenschmidt = "/^(https?:\/\/(?:.+\.)?kellenschmidt\.com(?::\d{1,5})?)$/";
$kspw = "/^(https?:\/\/(?:.+\.)?kspw(?::\d{1,5})?)$/";
$localhost = "/^(https?:\/\/(?:.+\.)?localhost(?::\d{1,5})?)$/";

// Get name of environment from env var set in shell script
$environment = getenv("ENV");

// Set header to allow CORS for cross-domain requests based on environment
if($environment == "prod" || $environment == "test") {
    if(preg_match($kellenschmidt, $http_origin) || preg_match($localhost, $http_origin)) {
        header("Access-Control-Allow-Origin: $http_origin");
    } else {
        header("Access-Control-Allow-Origin: null");
    }
} else if($environment == "docker") {
    if(preg_match($kspw, $http_origin)) {
        header("Access-Control-Allow-Origin: $http_origin");
    } else {
        header("Access-Control-Allow-Origin: null");
    }
} else {
    echo "Invalid environment variable value for \"ENV\" in .env";
    header("Access-Control-Allow-Origin: null");
}

header('Access-Control-Allow-Methods: GET,PUT,POST,DELETE,PATCH,OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');
