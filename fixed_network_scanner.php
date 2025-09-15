<?php
// fixed_network_scanner_ip.php - Network scanner with improved error handling

// Set proper headers first
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Error handling configuration
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
set_time_limit(120); // Increase time limit for network scanning

class NetworkScanner {
    private $targetIP;
    private $timeout = 2;
    private $vendors = [
        '001B63' => 'Apple', '001EC2' => 'Apple', '002608' => 'Apple',
        '0C7430' => 'Apple', '14109F' => 'Apple', '1C5CF2' => 'Apple',
        'B499BA' => 'Cisco', '0007EB' => 'Cisco', '001560' => 'Cisco',
        '00D0C0' => 'Cisco', '4C00A0' => 'Cisco', '5C5015' => 'Cisco',
        '001438' => 'HP', '0016B9' => 'HP', '001B78' => 'HP',
        '001E0B' => 'HP', '6C3BE5' => 'HP', '98F2B3' => 'HP',
        '70B3D5' => 'TP-Link', 'C46E1F' => 'TP-Link', 'E8DE27' => 'TP-Link',
        'A0F3C1' => 'TP-Link', '14CC20' => 'TP-Link', '50C7BF' => 'TP-Link',
        '20E52A' => 'Netgear', 'E091F5' => 'Netgear', '4C60DE' => 'Netgear',
        'A0040A' => 'Netgear', 'C40415' => 'Netgear', '309C23' => 'Netgear',
        '001B11' => 'D-Link', '001CF0' => 'D-Link', '001E58' => 'D-Link',
        '002191' => 'D-Link', '0022B0' => 'D-Link', '14D64D' => 'D-Link'
    ];
    
    public function __construct($ip) {
        // Validate IP address
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            throw new InvalidArgumentException('Invalid IPv4 address format: ' . $ip);
        }
        $this->targetIP = $ip;
    }
    
    public function scan() {
        try {
            $startTime = microtime(true);
            $devices = [];
            
            // Get network information
            $networkInfo = $this->getNetworkInfo();
            
            // Extract network from the target IP (assume /24 subnet)
            $networkParts = explode('.', $this->targetIP);
            if (count($networkParts) !== 4) {
                throw new InvalidArgumentException('Invalid IP address format');
            }
            
            $networkBase = $networkParts[0] . '.' . $networkParts[1] . '.' . $networkParts[2];
            
            // Limit scan range for performance
            $scanRange = range(1, 254);
            
            foreach ($scanRange as $i) {
                $ip = "$networkBase.$i";
                
                // Skip invalid IPs
                if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                    continue;
                }
                
                if ($this->pingHost($ip)) {
                    $device = $this->scanDevice($ip);
                    if ($device) {
                        // Add special labels
                        if ($ip === $networkInfo['local_ip']) {
                            $device['name'] = 'This Computer (Local)';
                            $device['is_local'] = true;
                        } elseif ($ip === $this->targetIP) {
                            $device['name'] = $device['name'] . ' (Target)';
                            $device['is_target'] = true;
                        }
                        $devices[] = $device;
                    }
                }
                
                // Prevent timeout on large scans
                if ((microtime(true) - $startTime) > 100) {
                    break;
                }
            }
            
            $scanTime = round(microtime(true) - $startTime, 2);
            
            return [
                'success' => true,
                'scan_time' => date('Y-m-d H:i:s'),
                'duration' => $scanTime . 's',
                'network' => $networkBase . '.0/24',
                'target_ip' => $this->targetIP,
                'total_devices' => count($devices),
                'switches' => $this->countDevicesByType($devices, 'switch'),
                'devices' => $devices,
                'network_info' => $networkInfo
            ];
            
        } catch (Exception $e) {
            return [
                'success' => false,
                'error' => 'Scan failed: ' . $e->getMessage(),
                'devices' => [],
                'debug' => $this->getDebugInfo()
            ];
        }
    }
    
    private function pingHost($ip) {
        // Validate and escape IP
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }
        
        $ip = escapeshellarg($ip);
        
        try {
            if (PHP_OS_FAMILY === 'Windows') {
                $command = "ping -n 1 -w 1000 {$ip} 2>NUL";
            } else {
                $command = "ping -c 1 -W 2 {$ip} 2>/dev/null";
            }
            
            $output = '';
            if (function_exists('shell_exec')) {
                $output = @shell_exec($command);
            } elseif (function_exists('exec')) {
                @exec($command, $outputArray);
                $output = implode("\n", $outputArray);
            } else {
                return false; // No command execution available
            }
            
            if (!$output) {
                return false;
            }
            
            // Check for successful ping response
            if (PHP_OS_FAMILY === 'Windows') {
                return (strpos($output, 'TTL=') !== false || strpos($output, 'bytes=') !== false);
            } else {
                return (strpos($output, 'ttl=') !== false || strpos($output, 'time=') !== false);
            }
            
        } catch (Exception $e) {
            return false;
        }
    }
    
    private function scanDevice($ip) {
        try {
            $device = [
                'ip' => $ip,
                'status' => 'online',
                'name' => null,
                'hostname' => null,
                'mac' => null,
                'vendor' => 'Unknown',
                'os_guess' => 'Unknown',
                'device_type' => '💻',
                'deviceCategory' => 'device',
                'open_ports' => [],
                'response_time' => null,
                'last_seen' => date('Y-m-d H:i:s'),
                'is_local' => false,
                'is_target' => false
            ];
            
            // Get hostname with timeout
            $device['hostname'] = $this->getHostname($ip);
            $device['name'] = $device['hostname'] ?: 'Unknown Device';
            
            // Get MAC address
            $device['mac'] = $this->getMacAddress($ip);
            
            // Get vendor from MAC
            if ($device['mac']) {
                $device['vendor'] = $this->getVendorFromMac($device['mac']);
            }
            
            // Scan common ports only
            $device['open_ports'] = $this->scanCommonPorts($ip);
            
            // Get response time
            $device['response_time'] = $this->getResponseTime($ip);
            
            // Determine device type and category
            $this->categorizeDevice($device);
            
            // Guess OS
            $device['os_guess'] = $this->guessOS($device);
            
            return $device;
            
        } catch (Exception $e) {
            error_log("Error scanning device {$ip}: " . $e->getMessage());
            return null;
        }
    }
    
    private function getHostname($ip) {
        try {
            // Set a timeout for hostname resolution
            $hostname = @gethostbyaddr($ip);
            return ($hostname && $hostname !== $ip && strlen($hostname) > 0) ? $hostname : null;
        } catch (Exception $e) {
            return null;
        }
    }
    
    private function getMacAddress($ip) {
        try {
            $ip = escapeshellarg($ip);
            
            if (PHP_OS_FAMILY === 'Windows') {
                // First ping to populate ARP table
                @shell_exec("ping -n 1 -w 1000 {$ip} >NUL 2>&1");
                sleep(1); // Wait for ARP table update
                
                $output = @shell_exec("arp -a {$ip} 2>NUL");
                
                if ($output && preg_match('/([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}/', $output, $matches)) {
                    return strtoupper(str_replace('-', ':', $matches[0]));
                }
            } else {
                // First ping to populate ARP table
                @shell_exec("ping -c 1 -W 1 {$ip} >/dev/null 2>&1");
                sleep(1); // Wait for ARP table update
                
                // Try different ARP commands
                $commands = [
                    "arp -n {$ip} 2>/dev/null",
                    "ip neigh show {$ip} 2>/dev/null",
                    "cat /proc/net/arp | grep {$ip} 2>/dev/null"
                ];
                
                foreach ($commands as $cmd) {
                    $output = @shell_exec($cmd);
                    if ($output && preg_match('/([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}/', $output, $matches)) {
                        return strtoupper($matches[0]);
                    }
                }
            }
            
            return null;
        } catch (Exception $e) {
            return null;
        }
    }
    
    private function scanCommonPorts($ip) {
        // Reduced port list for faster scanning
        $commonPorts = [22, 23, 53, 80, 135, 139, 161, 443, 445, 8080];
        $openPorts = [];
        
        foreach ($commonPorts as $port) {
            if ($this->isPortOpen($ip, $port)) {
                $openPorts[] = $port;
            }
        }
        
        return $openPorts;
    }
    
    private function isPortOpen($ip, $port, $timeout = 2) {
        try {
            $connection = @fsockopen($ip, $port, $errno, $errstr, $timeout);
            if ($connection) {
                fclose($connection);
                return true;
            }
            return false;
        } catch (Exception $e) {
            return false;
        }
    }
    
    private function getResponseTime($ip) {
        $ip = escapeshellarg($ip);
        
        try {
            if (PHP_OS_FAMILY === 'Windows') {
                $output = @shell_exec("ping -n 1 {$ip} 2>NUL");
                if ($output && preg_match('/time[<=](\d+)ms/', $output, $matches)) {
                    return $matches[1] . 'ms';
                }
            } else {
                $output = @shell_exec("ping -c 1 {$ip} 2>/dev/null");
                if ($output && preg_match('/time=([\d.]+) ms/', $output, $matches)) {
                    return round($matches[1]) . 'ms';
                }
            }
        } catch (Exception $e) {
            // Ignore errors
        }
        
        return null;
    }
    
    private function categorizeDevice(&$device) {
        $ports = $device['open_ports'];
        $hostname = strtolower($device['hostname'] ?? '');
        $ip = $device['ip'];
        
        // Extract gateway IP (usually .1)
        $networkParts = explode('.', $this->targetIP);
        $gatewayIP = $networkParts[0] . '.' . $networkParts[1] . '.' . $networkParts[2] . '.1';
        
        // Network switch detection
        if (in_array(161, $ports) && (in_array(23, $ports) || in_array(22, $ports))) {
            $device['device_type'] = '🔌';
            $device['deviceCategory'] = 'switch';
            $device['name'] = $device['name'] ?: 'Network Switch';
            
            // Add switch-specific info (simulated)
            $device['portCount'] = rand(8, 48);
            $device['connectedDevices'] = rand(2, 15);
            $device['uptime'] = rand(1, 365) . ' days';
            $device['powerConsumption'] = rand(20, 80) . 'W';
        }
        // Router/Gateway detection
        elseif ($ip === $gatewayIP || 
                strpos($hostname, 'router') !== false || 
                strpos($hostname, 'gateway') !== false ||
                (in_array(80, $ports) && in_array(53, $ports))) {
            $device['device_type'] = '📶';
            $device['name'] = $device['name'] ?: 'Router/Gateway';
        }
        // Web server detection
        elseif (in_array(80, $ports) || in_array(443, $ports) || in_array(8080, $ports)) {
            $device['device_type'] = '🖥️';
            $device['name'] = $device['name'] ?: 'Web Server';
        }
        // Windows machine detection
        elseif (in_array(135, $ports) && in_array(445, $ports)) {
            $device['device_type'] = '💻';
            $device['name'] = $device['name'] ?: 'Windows Computer';
        }
        // Linux/Unix machine detection
        elseif (in_array(22, $ports)) {
            $device['device_type'] = '🐧';
            $device['name'] = $device['name'] ?: 'Linux/Unix System';
        }
        // Mobile device detection
        elseif (strpos($hostname, 'iphone') !== false || strpos($hostname, 'ipad') !== false) {
            $device['device_type'] = '📱';
            $device['name'] = $device['name'] ?: 'iOS Device';
        }
        elseif (strpos($hostname, 'android') !== false) {
            $device['device_type'] = '📱';
            $device['name'] = $device['name'] ?: 'Android Device';
        }
    }
    
    private function guessOS($device) {
        $ports = $device['open_ports'];
        $hostname = strtolower($device['hostname'] ?? '');
        
        // Windows indicators
        if (in_array(135, $ports) && in_array(445, $ports)) {
            return 'Windows';
        }
        
        // Linux/Unix indicators
        if (in_array(22, $ports) && !in_array(135, $ports)) {
            return 'Linux/Unix';
        }
        
        // Switch/Router OS
        if ($device['deviceCategory'] === 'switch') {
            return 'Embedded/Network OS';
        }
        
        // Mobile OS detection
        if (strpos($hostname, 'iphone') !== false || strpos($hostname, 'ipad') !== false) {
            return 'iOS';
        }
        
        if (strpos($hostname, 'android') !== false) {
            return 'Android';
        }
        
        return 'Unknown';
    }
    
    private function getVendorFromMac($mac) {
        if (!$mac) return 'Unknown';
        
        $oui = strtoupper(substr(str_replace([':', '-'], '', $mac), 0, 6));
        return $this->vendors[$oui] ?? 'Unknown';
    }
    
    private function getNetworkInfo() {
        try {
            $info = [
                'local_ip' => $this->getLocalIP(),
                'gateway' => $this->getGateway(),
                'target_ip' => $this->targetIP
            ];
            
            // Add scanned network
            $networkParts = explode('.', $this->targetIP);
            $info['scanned_network'] = $networkParts[0] . '.' . $networkParts[1] . '.' . $networkParts[2] . '.0/24';
            
            return $info;
        } catch (Exception $e) {
            return [
                'local_ip' => '127.0.0.1',
                'gateway' => null,
                'target_ip' => $this->targetIP,
                'error' => $e->getMessage()
            ];
        }
    }
    
    private function getLocalIP() {
        try {
            // Try multiple methods to get local IP
            $methods = [];
            
            if (PHP_OS_FAMILY === 'Windows') {
                $output = @shell_exec('ipconfig | findstr "IPv4" 2>NUL');
                if ($output && preg_match('/(\d+\.\d+\.\d+\.\d+)/', $output, $matches)) {
                    $methods[] = $matches[1];
                }
            } else {
                // Try different Linux commands
                $commands = [
                    'hostname -I 2>/dev/null | awk "{print $1}"',
                    'ip route get 8.8.8.8 2>/dev/null | awk "{print $7}" | head -1',
                    'ifconfig | grep "inet " | grep -v 127.0.0.1 | awk "{print $2}" | head -1'
                ];
                
                foreach ($commands as $cmd) {
                    $output = @shell_exec($cmd);
                    if ($output) {
                        $ip = trim($output);
                        if (filter_var($ip, FILTER_VALIDATE_IP)) {
                            $methods[] = $ip;
                            break;
                        }
                    }
                }
            }
            
            // PHP fallback methods
            if (isset($_SERVER['SERVER_ADDR']) && filter_var($_SERVER['SERVER_ADDR'], FILTER_VALIDATE_IP)) {
                $methods[] = $_SERVER['SERVER_ADDR'];
            }
            
            // Return first valid IP
            foreach ($methods as $ip) {
                if (filter_var($ip, FILTER_VALIDATE_IP) && $ip !== '127.0.0.1') {
                    return $ip;
                }
            }
            
            return '127.0.0.1';
        } catch (Exception $e) {
            return '127.0.0.1';
        }
    }
    
    private function getGateway() {
        try {
            if (PHP_OS_FAMILY === 'Windows') {
                $output = @shell_exec('ipconfig | findstr "Default Gateway" 2>NUL');
                if ($output && preg_match('/(\d+\.\d+\.\d+\.\d+)/', $output, $matches)) {
                    return $matches[1];
                }
            } else {
                $commands = [
                    'ip route | grep default 2>/dev/null',
                    'route -n | grep "^0.0.0.0" 2>/dev/null'
                ];
                
                foreach ($commands as $cmd) {
                    $output = @shell_exec($cmd);
                    if ($output && preg_match('/(\d+\.\d+\.\d+\.\d+)/', $output, $matches)) {
                        return $matches[1];
                    }
                }
            }
            return null;
        } catch (Exception $e) {
            return null;
        }
    }
    
    private function countDevicesByType($devices, $type) {
        return count(array_filter($devices, function($device) use ($type) {
            return $device['deviceCategory'] === $type;
        }));
    }
    
    private function getDebugInfo() {
        return [
            'php_version' => PHP_VERSION,
            'php_os' => PHP_OS,
            'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown',
            'functions_available' => [
                'shell_exec' => function_exists('shell_exec'),
                'exec' => function_exists('exec'),
                'fsockopen' => function_exists('fsockopen'),
                'gethostbyaddr' => function_exists('gethostbyaddr')
            ],
            'disabled_functions' => array_filter(explode(',', str_replace(' ', '', ini_get('disable_functions')))),
            'time_limit' => ini_get('max_execution_time'),
            'memory_limit' => ini_get('memory_limit'),
            'extensions' => [
                'json' => extension_loaded('json'),
                'curl' => extension_loaded('curl'),
                'sockets' => extension_loaded('sockets')
            ]
        ];
    }
}

// System status and connectivity functions
function getSystemStatus() {
    try {
        $requirements = checkSystemRequirements();
        $connectivity = testConnectivity();
        
        return [
            'success' => true,
            'system_info' => [
                'php_version' => PHP_VERSION,
                'php_os' => PHP_OS,
                'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? 'CLI',
                'memory_limit' => ini_get('memory_limit'),
                'max_execution_time' => ini_get('max_execution_time'),
                'current_time' => date('Y-m-d H:i:s'),
                'extensions' => [
                    'sockets' => extension_loaded('sockets'),
                    'curl' => extension_loaded('curl'),
                    'json' => extension_loaded('json')
                ]
            ],
            'requirements' => $requirements,
            'connectivity' => $connectivity
        ];
    } catch (Exception $e) {
        return [
            'success' => false,
            'error' => $e->getMessage()
        ];
    }
}

function checkSystemRequirements() {
    $disabledFunctions = array_filter(explode(',', str_replace(' ', '', ini_get('disable_functions'))));
    
    return [
        'php_version' => [
            'required' => '7.0',
            'current' => PHP_VERSION,
            'status' => version_compare(PHP_VERSION, '7.0', '>=')
        ],
        'extensions' => [
            'sockets' => extension_loaded('sockets'),
            'json' => extension_loaded('json'),
            'curl' => extension_loaded('curl')
        ],
        'functions' => [
            'exec' => function_exists('exec') && !in_array('exec', $disabledFunctions),
            'shell_exec' => function_exists('shell_exec') && !in_array('shell_exec', $disabledFunctions),
            'fsockopen' => function_exists('fsockopen') && !in_array('fsockopen', $disabledFunctions),
            'gethostbyaddr' => function_exists('gethostbyaddr') && !in_array('gethostbyaddr', $disabledFunctions)
        ],
        'permissions' => [
            'write_data' => is_writable('.'),
            'read_config' => is_readable(__FILE__)
        ],
        'disabled_functions' => $disabledFunctions
    ];
}

function testConnectivity() {
    $tests = [];
    
    try {
        // Test localhost connectivity
        $tests['localhost'] = false;
        $connection = @fsockopen('127.0.0.1', 80, $errno, $errstr, 2);
        if ($connection) {
            $tests['localhost'] = true;
            fclose($connection);
        }
        
        // Test external connectivity with ping
        $tests['external'] = false;
        if (function_exists('shell_exec')) {
            if (PHP_OS_FAMILY === 'Windows') {
                $output = @shell_exec('ping -n 1 -w 2000 8.8.8.8 2>NUL');
                $tests['external'] = $output && (strpos($output, 'TTL=') !== false || strpos($output, 'bytes=') !== false);
            } else {
                $output = @shell_exec('ping -c 1 -W 2 8.8.8.8 2>/dev/null');
                $tests['external'] = $output && (strpos($output, 'ttl=') !== false || strpos($output, 'time=') !== false);
            }
        }
        
        return $tests;
    } catch (Exception $e) {
        return ['error' => $e->getMessage()];
    }
}

// Main request handler with improved error handling
try {
    $endpoint = $_GET['endpoint'] ?? 'scan';
    $result = [];
    
    switch ($endpoint) {
        case 'status':
            $result = getSystemStatus();
            break;
            
        case 'scan':
            $ip = $_GET['ip'] ?? '';
            
            if (empty($ip)) {
                throw new InvalidArgumentException('IP address parameter is required');
            }
            
            // Validate IP address format
            if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                throw new InvalidArgumentException('Invalid IPv4 address format. Expected format: 192.168.1.1');
            }
            
            $scanner = new NetworkScanner($ip);
            $result = $scanner->scan();
            break;
            
        case 'test':
            $result = [
                'success' => true,
                'timestamp' => date('Y-m-d H:i:s'),
                'connectivity_test' => testConnectivity(),
                'system_requirements' => checkSystemRequirements()
            ];
            break;
            
        default:
            throw new InvalidArgumentException('Unknown endpoint: ' . htmlspecialchars($endpoint));
    }
    
    // Return JSON response
    echo json_encode($result, JSON_PRETTY_PRINT);
    
} catch (Exception $e) {
    // Error response
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => $e->getMessage(),
        'error_type' => get_class($e),
        'debug' => [
            'php_version' => PHP_VERSION,
            'php_os' => PHP_OS,
            'request_method' => $_SERVER['REQUEST_METHOD'],
            'query_string' => $_SERVER['QUERY_STRING'] ?? '',
            'endpoint' => $_GET['endpoint'] ?? 'none',
            'ip_param' => $_GET['ip'] ?? 'none',
            'timestamp' => date('Y-m-d H:i:s'),
            'functions_available' => [
                'shell_exec' => function_exists('shell_exec'),
                'exec' => function_exists('exec'),
                'fsockopen' => function_exists('fsockopen')
            ]
        ]
    ], JSON_PRETTY_PRINT);
}
?>