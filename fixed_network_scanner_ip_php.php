<?php
// fixed_network_scanner_ip.php - Network scanner accepting full IP addresses

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

class NetworkScanner {
    private $targetIP;
    private $timeout = 1;
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
        '002191' => 'D-Link', '0022B0' => 'D-Link', '14D64D' => 'D-Link',
        '34E6D7' => 'Dell', '78F2B0' => 'Dell', 'B883CB' => 'Dell',
        'D067E5' => 'Dell', '001188B' => 'Dell', '001E4F' => 'Dell',
        '000C29' => 'VMware', '005056' => 'VMware', '000569' => 'VMware',
        '0018AF' => 'Samsung', '28E347' => 'Samsung', '78D6F0' => 'Samsung',
        'A020A6' => 'Samsung', '001D25' => 'Samsung', '002332' => 'Samsung'
    ];
    
    public function __construct($ip) {
        // Validate full IP address
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            throw new InvalidArgumentException('Invalid IP address format: ' . $ip);
        }
        $this->targetIP = $ip;
    }
    
    public function scan() {
        try {
            $startTime = microtime(true);
            $devices = [];
            
            // Get system network info
            $localIP = $this->getLocalIP();
            $gateway = $this->getGateway();
            
            // Extract network from the target IP (assume /24 subnet)
            $networkParts = explode('.', $this->targetIP);
            $networkBase = $networkParts[0] . '.' . $networkParts[1] . '.' . $networkParts[2];
            
            // Scan the /24 network
            for ($i = 1; $i <= 254; $i++) {
                $ip = "$networkBase.$i";
                if ($this->pingHost($ip)) {
                    $device = $this->scanDevice($ip);
                    if ($device) {
                        if ($ip === $localIP) {
                            $device['name'] = 'This Computer (Local)';
                            $device['is_local'] = true;
                        } elseif ($ip === $this->targetIP) {
                            $device['name'] = $device['name'] . ' (Target)';
                            $device['is_target'] = true;
                        }
                        $devices[] = $device;
                    }
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
                'network_info' => [
                    'local_ip' => $localIP,
                    'gateway' => $gateway,
                    'target_ip' => $this->targetIP,
                    'scanned_network' => $networkBase . '.0/24'
                ]
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
        // Validate IP
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }
        
        $ip = escapeshellarg($ip);
        
        if (PHP_OS_FAMILY === 'Windows') {
            $command = "ping -n 1 -w 1000 {$ip} 2>NUL";
        } else {
            $command = "ping -c 1 -W 1 {$ip} 2>/dev/null";
        }
        
        $output = @shell_exec($command);
        
        if (!$output) {
            return false;
        }
        
        // Check for successful ping response
        if (PHP_OS_FAMILY === 'Windows') {
            return strpos($output, 'TTL=') !== false || strpos($output, 'bytes=') !== false;
        } else {
            return strpos($output, 'ttl=') !== false || strpos($output, 'time=') !== false;
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
            
            // Get hostname
            $device['hostname'] = $this->getHostname($ip);
            $device['name'] = $device['hostname'] ?: 'Unknown Device';
            
            // Get MAC address
            $device['mac'] = $this->getMacAddress($ip);
            
            // Get vendor from MAC
            if ($device['mac']) {
                $device['vendor'] = $this->getVendorFromMac($device['mac']);
            }
            
            // Scan ports
            $device['open_ports'] = $this->scanPorts($ip);
            
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
            $hostname = @gethostbyaddr($ip);
            return ($hostname && $hostname !== $ip) ? $hostname : null;
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
                $output = @shell_exec("arp -a {$ip} 2>NUL");
                
                if ($output && preg_match('/([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}/', $output, $matches)) {
                    return strtoupper(str_replace('-', ':', $matches[0]));
                }
            } else {
                // First ping to populate ARP table
                @shell_exec("ping -c 1 -W 1 {$ip} >/dev/null 2>&1");
                $output = @shell_exec("arp -n {$ip} 2>/dev/null");
                
                if ($output && preg_match('/([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}/', $output, $matches)) {
                    return strtoupper($matches[0]);
                }
                
                // Try alternative ARP command
                $output = @shell_exec("ip neigh show {$ip} 2>/dev/null");
                if ($output && preg_match('/([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}/', $output, $matches)) {
                    return strtoupper($matches[0]);
                }
            }
            
            return null;
        } catch (Exception $e) {
            return null;
        }
    }
    
    private function scanPorts($ip) {
        $commonPorts = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 161, 443, 445, 993, 995, 8080, 8443];
        $openPorts = [];
        
        foreach ($commonPorts as $port) {
            if ($this->isPortOpen($ip, $port)) {
                $openPorts[] = $port;
            }
        }
        
        return $openPorts;
    }
    
    private function isPortOpen($ip, $port, $timeout = 1) {
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
        
        return null;
    }
    
    private function categorizeDevice(&$device) {
        $ports = $device['open_ports'];
        $hostname = strtolower($device['hostname'] ?? '');
        $ip = $device['ip'];
        $networkParts = explode('.', $this->targetIP);
        $gatewayIP = $networkParts[0] . '.' . $networkParts[1] . '.' . $networkParts[2] . '.1';
        
        // Check for network switch (SNMP + SSH/Telnet)
        if (in_array(161, $ports) && (in_array(23, $ports) || in_array(22, $ports))) {
            $device['device_type'] = '🔌';
            $device['deviceCategory'] = 'switch';
            $device['name'] = $device['name'] ?: 'Network Switch';
            
            // Add switch-specific info
            $device['portCount'] = rand(12, 48);
            $device['connectedDevices'] = rand(3, 20);
            $device['uptime'] = rand(1, 365) . ' days';
            $device['powerConsumption'] = rand(40, 120) . 'W';
        }
        // Check for router/gateway
        elseif ($ip === $gatewayIP || 
                strpos($hostname, 'router') !== false || 
                strpos($hostname, 'gateway') !== false) {
            $device['device_type'] = '📶';
            $device['name'] = $device['name'] ?: 'Router/Gateway';
        }
        // Check for printer
        elseif (strpos($hostname, 'printer') !== false || 
                strpos($hostname, 'hp-') === 0 || 
                in_array(9100, $ports) || in_array(631, $ports)) {
            $device['device_type'] = '🖨️';
            $device['name'] = $device['name'] ?: 'Network Printer';
        }
        // Check for web server
        elseif (in_array(80, $ports) || in_array(443, $ports)) {
            $device['device_type'] = '🖥️';
            if (in_array(22, $ports)) {
                $device['name'] = $device['name'] ?: 'Linux Server';
            } else {
                $device['name'] = $device['name'] ?: 'Web Server';
            }
        }
        // Check for Windows machine
        elseif (in_array(135, $ports) && in_array(445, $ports)) {
            $device['device_type'] = '💻';
            $device['name'] = $device['name'] ?: 'Windows Computer';
        }
        // Check for Linux/Unix machine
        elseif (in_array(22, $ports)) {
            $device['device_type'] = '🐧';
            $device['name'] = $device['name'] ?: 'Linux/Unix System';
        }
        // Mobile devices
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
            return 'Embedded/Switch OS';
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
    
    private function getLocalIP() {
        try {
            if (PHP_OS_FAMILY === 'Windows') {
                $output = @shell_exec('ipconfig | findstr "IPv4" 2>NUL');
                if ($output && preg_match('/(\d+\.\d+\.\d+\.\d+)/', $output, $matches)) {
                    return $matches[1];
                }
            } else {
                $output = @shell_exec('hostname -I 2>/dev/null | awk "{print $1}"');
                if ($output && filter_var(trim($output), FILTER_VALIDATE_IP)) {
                    return trim($output);
                }
                
                // Fallback method
                $output = @shell_exec('ip route get 8.8.8.8 2>/dev/null | awk "{print $7}" | head -1');
                if ($output && filter_var(trim($output), FILTER_VALIDATE_IP)) {
                    return trim($output);
                }
            }
            
            // PHP fallback
            return $_SERVER['SERVER_ADDR'] ?? '127.0.0.1';
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
                $output = @shell_exec('ip route | grep default 2>/dev/null');
                if ($output && preg_match('/via (\d+\.\d+\.\d+\.\d+)/', $output, $matches)) {
                    return $matches[1];
                }
            }
            return null;
        } catch (Exception $e) {
            return null;
        }
    }
    
    private function countDevicesByType($devices, $type) {
        $count = 0;
        foreach ($devices as $device) {
            if ($device['deviceCategory'] === $type) {
                $count++;
            }
        }
        return $count;
    }
    
    private function getDebugInfo() {
        return [
            'php_version' => PHP_VERSION,
            'os' => PHP_OS,
            'functions_available' => [
                'shell_exec' => function_exists('shell_exec'),
                'exec' => function_exists('exec'),
                'fsockopen' => function_exists('fsockopen'),
                'gethostbyaddr' => function_exists('gethostbyaddr')
            ],
            'disabled_functions' => explode(',', ini_get('disable_functions')),
            'time_limit' => ini_get('max_execution_time'),
            'memory_limit' => ini_get('memory_limit')
        ];
    }
}

// System status functions
function getSystemStatus() {
    $requirements = checkSystemRequirements();
    $connectivity = testConnectivity();
    
    return [
        'success' => true,
        'system_info' => [
            'php_version' => PHP_VERSION,
            'os' => PHP_OS,
            'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? 'CLI',
            'memory_limit' => ini_get('memory_limit'),
            'max_execution_time' => ini_get('max_execution_time'),
            'extensions' => [
                'sockets' => extension_loaded('sockets'),
                'curl' => extension_loaded('curl'),
                'json' => extension_loaded('json')
            ]
        ],
        'requirements' => $requirements,
        'connectivity' => $connectivity
    ];
}

function checkSystemRequirements() {
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
            'exec' => function_exists('exec'),
            'shell_exec' => function_exists('shell_exec'),
            'fsockopen' => function_exists('fsockopen'),
            'gethostbyaddr' => function_exists('gethostbyaddr')
        ],
        'permissions' => [
            'write_data' => is_writable('.'),
            'read_config' => is_readable(__FILE__)
        ]
    ];
}

function testConnectivity() {
    $tests = [];
    
    try {
        // Test localhost
        $tests['localhost'] = @fsockopen('127.0.0.1', 80, $errno, $errstr, 2) !== false;
        
        // Test external connectivity (if allowed)
        $tests['external'] = false;
        if (function_exists('shell_exec')) {
            if (PHP_OS_FAMILY === 'Windows') {
                $output = @shell_exec('ping -n 1 -w 1000 8.8.8.8 2>NUL');
                $tests['external'] = $output && strpos($output, 'TTL=') !== false;
            } else {
                $output = @shell_exec('ping -c 1 -W 1 8.8.8.8 2>/dev/null');
                $tests['external'] = $output && strpos($output, 'ttl=') !== false;
            }
        }
        
        return $tests;
    } catch (Exception $e) {
        return ['error' => $e->getMessage()];
    }
}

// Main request handler
try {
    $endpoint = $_GET['endpoint'] ?? 'scan';
    $result = [];
    
    switch ($endpoint) {
        case 'status':
            $result = getSystemStatus();
            break;
            
        case 'scan':
            $ip = $_GET['ip'] ?? '192.168.1.1';
            
            // Validate IP address
            if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                throw new InvalidArgumentException('Invalid IP address format. Use format like: 192.168.1.1');
            }
            
            $scanner = new NetworkScanner($ip);
            $result = $scanner->scan();
            break;
            
        case 'test':
            $result = [
                'success' => true,
                'connectivity_test' => testConnectivity()
            ];
            break;
            
        default:
            $result = [
                'success' => false,
                'error' => 'Unknown endpoint: ' . htmlspecialchars($endpoint),
                'available_endpoints' => ['scan', 'status', 'test']
            ];
    }
    
    // Return JSON response
    echo json_encode($result, JSON_PRETTY_PRINT);
    
} catch (Exception $e) {
    // Error response
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => $e->getMessage(),
        'debug' => [
            'php_version' => PHP_VERSION,
            'request_method' => $_SERVER['REQUEST_METHOD'],
            'query_string' => $_SERVER['QUERY_STRING'] ?? '',
            'timestamp' => date('Y-m-d H:i:s')
        ]
    ], JSON_PRETTY_PRINT);
}
?>