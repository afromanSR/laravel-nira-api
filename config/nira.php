<?php

return [
    'username' => env('NIRA_USERNAME'),
    'password' => env('NIRA_PASSWORD'),
    'server' => env('NIRA_SERVER', "154.72.206.138:8080"),
    'server_path' => env('NIRA_SERVER_PATH', "pilatusp2-tpi2-ws/ThirdPartyInterfaceNewWS"),
    'namespace' => env('NIRA_NAMESPACE', "http://facade.server.pilatus.thirdparty.tidis.muehlbauer.de/"),
];