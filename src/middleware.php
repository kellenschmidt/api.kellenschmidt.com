<?php

use Bairwell\MiddlewareCors;

// read the allowed methods for a route
$corsAllowedMethods = function (ServerRequestInterface $request) use ($container) : array {

    // if this closure is called, make sure it has the route available in the container.
    /* @var RouterInterface $router */
    $router = $container->get('router');

    $routeInfo = $router->dispatch($request);
    $methods   = [];
    // was the method called allowed?
    if ($routeInfo[0] === Dispatcher::METHOD_NOT_ALLOWED) {
        $methods = $routeInfo[1];
    } else {
        // if it was, see if we can get the routes and then the methods from it.
        // @var \Slim\Route $route
        $route = $request->getAttribute('route');
        // has the request get a route defined? is so use that
        if (null !== $route) {
            $methods = $route->getMethods();
        }
    }

    // if we have methods, let's list them removing the OPTIONs one.
    if (0 === count($methods)) {
        // find the OPTIONs method
        $key = array_search('OPTIONS', $methods,true);
        // and remove it if set.
        if (false !== $key) {
            unset($methods[$key]);
            $methods = array_values($methods);
        }
    }

    return $methods;
};
$cors = new MiddlewareCors(
        [
            'origin'           => ['*.kellenschmidt.com','kellenschmidt.com','*.kspw','kspw','localhost'],
            'exposeHeaders'    => '',
            'maxAge'           => 120,
            'allowCredentials' => true,
            'allowMethods'     => $corsAllowedMethods,
            'allowHeaders'     => ['Accept', 'Accept-Language', 'Authorization', 'Content-Type','DNT','Keep-Alive','User-Agent','X-Requested-With','If-Modified-Since','Cache-Control','Origin'],
        ]
    );

$app->add($cors);
