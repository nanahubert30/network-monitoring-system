<?php
// test_backend.php - Simple test to verify PHP setup

header('Content-Type: application/json');

// Basic PHP info
$testResults = [
    'php_version' => PHP_VERSION,
    'php_os' => PHP_OS,
    'timestamp' => date('Y-m-d H:i:s'),
    'functions' => [
        'shell_exec' => function_exists('shell_exec'),
        'exec' => function_exists('exec'),
        'fsockopen' => function_exists('fsockopen'),
        'gethostbyaddr' => function_exists('gethostbyaddr')
    ],
    'disabled_functions' => explode(',', ini_get('disable_functions')),
    'extensions' => [
        'json' => extension_loaded('json'),
        'curl' => extension_loaded('curl'),
        'sockets' => extension_loaded('sockets')
    ]
];

// Test basic network command
if (function_exists('shell_exec')) {
    if (PHP_OS_FAMILY === 'Windows') {
        $pingTest = @shell_exec('ping -n 1 127.0.0.1 2>NUL');
        $testResults['ping_test'] = $pingTest ? 'Success' : 'Failed';
    } else {
        $pingTest = @shell_exec('ping -c 1 127.0.0.1 2>/dev/null');
        $testResults['ping_test'] = $pingTest ? 'Success' : 'Failed';
    }
} else {
    $testResults['ping_test'] = 'shell_exec disabled';
}

echo json_encode($testResults, JSON_PRETTY_PRINT);
?>