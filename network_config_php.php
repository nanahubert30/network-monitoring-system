<?php
// config.php - Configuration file for network scanner
return [
    // Network settings
    'default_subnet' => '192.168.1',
    'scan_timeout' => 300, // 5 minutes
    'ping_timeout' => 1000, // 1 second
    
    // Port scanning settings
    'common_ports' => [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 161, 443, 445, 993, 995, 8080, 8443, 9999],
    'port_timeout' => 2, // seconds
    
    // Switch detection ports
    'switch_ports' => [22, 23, 80, 161, 443, 8080, 9999],
    
    // SNMP settings
    'snmp_community' => 'public',
    'snmp_timeout' => 5,
    'snmp_retries' => 2,
    
    // Vendor OUI database (MAC address to vendor mapping)
    'vendor_oui' => [
        // Apple
        '001B63' => 'Apple',
        '001EC2' => 'Apple',
        '002608' => 'Apple',
        '0C7430' => 'Apple',
        '14109F' => 'Apple',
        '1C5CF2' => 'Apple',
        '203CAE' => 'Apple',
        '689C70' => 'Apple',
        'A4C361' => 'Apple',
        'C82A14' => 'Apple',
        'E4CE8F' => 'Apple',
        
        // Cisco
        'B499BA' => 'Cisco',
        '0007EB' => 'Cisco',
        '000F23' => 'Cisco',
        '001560' => 'Cisco',
        '00D0C0' => 'Cisco',
        '4C00A0' => 'Cisco',
        '5C5015' => 'Cisco',
        '7C95F3' => 'Cisco',
        'A0EC80' => 'Cisco',
        'C4711E' => 'Cisco',
        
        // Dell
        '001560' => 'Dell',
        '00188B' => 'Dell',
        '001E4F' => 'Dell',
        '002564' => 'Dell',
        '34E6D7' => 'Dell',
        '78F2B0' => 'Dell',
        'B883CB' => 'Dell',
        'D067E5' => 'Dell',
        
        // HP
        '001438' => 'HP',
        '0016B9' => 'HP',
        '001B78' => 'HP',
        '001E0B' => 'HP',
        '002608' => 'HP',
        '6C3BE5' => 'HP',
        '98F2B3' => 'HP',
        'C0847A' => 'HP',
        
        // TP-Link
        '70B3D5' => 'TP-Link',
        'C46E1F' => 'TP-Link',
        'E8DE27' => 'TP-Link',
        'A0F3C1' => 'TP-Link',
        '14CC20' => 'TP-Link',
        '50C7BF' => 'TP-Link',
        '94103E' => 'TP-Link',
        
        // Netgear
        '20E52A' => 'Netgear',
        'E091F5' => 'Netgear',
        '4C60DE' => 'Netgear',
        'A0040A' => 'Netgear',
        'C40415' => 'Netgear',
        '309C23' => 'Netgear',
        
        // D-Link
        '001B11' => 'D-Link',
        '001CF0' => 'D-Link',
        '001E58' => 'D-Link',
        '002191' => 'D-Link',
        '0022B0' => 'D-Link',
        '14D64D' => 'D-Link',
        '1C7EE5' => 'D-Link',
        
        // Microsoft
        '00D0C9' => 'Microsoft',
        '001DD8' => 'Microsoft',
        '7C1E52' => 'Microsoft',
        'E4A7A0' => 'Microsoft',
        
        // Intel
        '001B21' => 'Intel',
        '7085C2' => 'Intel',
        '8CA982' => 'Intel',
        'A4BADB' => 'Intel',
        
        // VMware
        '000C29' => 'VMware',
        '005056' => 'VMware',
        '000569' => 'VMware',
        
        // Samsung
        '0018AF' => 'Samsung',
        '001D25' => 'Samsung',
        '002332' => 'Samsung',
        '28E347' => 'Samsung',
        '34E2FD' => 'Samsung',
        '78D6F0' => 'Samsung',
        'A020A6' => 'Samsung',
        
        // Sony
        '001A80' => 'Sony',
        '001C13' => 'Sony',
        '001D86' => 'Sony',
        '7C4DDF' => 'Sony',
        '84C0EF' => 'Sony',
        
        // LG
        '001854' => 'LG',
        '001C62' => 'LG',
        '002140' => 'LG',
        '6C2F2C' => 'LG',
        
        // Canon
        '002085' => 'Canon',
        '00239D' => 'Canon',
        '0024A5' => 'Canon',
        '64B310' => 'Canon'
    ]
];

// database.php - Simple JSON file database for storing scan results
class NetworkDatabase {
    private $dataFile;
    
    public function __construct($dataFile = 'network_data.json') {
        $this->dataFile = $dataFile;
        $this->initializeDatabase();
    }
    
    private function initializeDatabase() {
        if (!file_exists($this->dataFile)) {
            file_put_contents($this->dataFile, json_encode([
                'scans' => [],
                'devices' => [],
                'last_scan' => null
            ]));
        }
    }
    
    public function saveScanResult($scanData) {
        $data = $this->getData();
        
        $scan = [
            'timestamp' => time(),
            'scan_time' => $scanData['scan_time'],
            'subnet' => $scanData['subnet'],
            'device_count' => $scanData['total_devices'],
            'switch_count' => $scanData['switches']
        ];
        
        $data['scans'][] = $scan;
        $data['devices'] = $scanData['devices'];
        $data['last_scan'] = $scan;
        
        // Keep only last 50 scans
        if (count($data['scans']) > 50) {
            $data['scans'] = array_slice($data['scans'], -50);
        }
        
        file_put_contents($this->dataFile, json_encode($data, JSON_PRETTY_PRINT));
    }
    
    public function getLastScan() {
        $data = $this->getData();
        return $data['last_scan'];
    }
    
    public function getDeviceHistory($ip) {
        $data = $this->getData();
        $history = [];
        
        foreach ($data['scans'] as $scan) {
            // This would require storing device data per scan
            // Implementation depends on requirements
        }
        
        return $history;
    }
    
    public function getScanHistory($limit = 10) {
        $data = $this->getData();
        return array_slice($data['scans'], -$limit);
    }
    
    private function getData() {
        $content = file_get_contents($this->dataFile);
        return json_decode($content, true) ?: ['scans' => [], 'devices' => [], 'last_scan' => null];
    }
}

// network_utils.php - Utility functions
class NetworkUtils {
    
    /**
     * Validate IP address
     */
    public static function isValidIP($ip) {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
    }
    
    /**
     * Get subnet from IP
     */
    public static function getSubnet($ip, $mask = 24) {
        $parts = explode('.', $ip);
        if ($mask == 24) {
            return $parts[0] . '.' . $parts[1] . '.' . $parts[2];
        }
        // Add other mask calculations if needed
        return false;
    }
    
    /**
     * Check if port is open
     */
    public static function isPortOpen($ip, $port, $timeout = 2) {
        $connection = @fsockopen($ip, $port, $errno, $errstr, $timeout);
        if ($connection) {
            fclose($connection);
            return true;
        }
        return false;
    }
    
    /**
     * Format MAC address consistently
     */
    public static function formatMac($mac) {
        $mac = strtoupper(preg_replace('/[^0-9A-F]/', '', $mac));
        return substr($mac, 0, 2) . ':' . substr($mac, 2, 2) . ':' . 
               substr($mac, 4, 2) . ':' . substr($mac, 6, 2) . ':' . 
               substr($mac, 8, 2) . ':' . substr($mac, 10, 2);
    }
    
    /**
     * Get system information
     */
    public static function getSystemInfo() {
        return [
            'os' => PHP_OS,
            'php_version' => PHP_VERSION,
            'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? 'CLI',
            'memory_limit' => ini_get('memory_limit'),
            'max_execution_time' => ini_get('max_execution_time'),
            'extensions' => [
                'sockets' => extension_loaded('sockets'),
                'snmp' => extension_loaded('snmp'),
                'curl' => extension_loaded('curl')
            ]
        ];
    }
    
    /**
     * Test network connectivity
     */
    public static function testConnectivity() {
        $tests = [];
        
        // Test local connectivity
        $localIP = self::getLocalIP();
        $tests['local_ip'] = $localIP;
        $tests['local_ping'] = self::pingHost($localIP);
        
        // Test gateway connectivity
        $gateway = self::getGateway();
        $tests['gateway'] = $gateway;
        $tests['gateway_ping'] = self::pingHost($gateway);
        
        // Test internet connectivity
        $tests['internet_ping'] = self::pingHost('8.8.8.8');
        
        return $tests;
    }
    
    /**
     * Simple ping function
     */
    public static function pingHost($ip, $timeout = 1) {
        if (PHP_OS_FAMILY === 'Windows') {
            $output = shell_exec("ping -n 1 -w 1000 {$ip} 2>NUL");
            return strpos($output, 'TTL=') !== false;
        } else {
            $output = shell_exec("ping -c 1 -W {$timeout} {$ip} 2>/dev/null");
            return strpos($output, 'ttl=') !== false;
        }
    }
    
    /**
     * Get local IP address
     */
    public static function getLocalIP() {
        if (PHP_OS_FAMILY === 'Windows') {
            $output = shell_exec('ipconfig | findstr "IPv4"');
            if ($output && preg_match('/(\d+\.\d+\.\d+\.\d+)/', $output, $matches)) {
                return $matches[1];
            }
        } else {
            $output = shell_exec("hostname -I | awk '{print $1}'");
            if ($output && self::isValidIP(trim($output))) {
                return trim($output);
            }
        }
        return '127.0.0.1';
    }
    
    /**
     * Get default gateway
     */
    public static function getGateway() {
        if (PHP_OS_FAMILY === 'Windows') {
            $output = shell_exec('ipconfig | findstr "Default Gateway"');
            if ($output && preg_match('/(\d+\.\d+\.\d+\.\d+)/', $output, $matches)) {
                return $matches[1];
            }
        } else {
            $output = shell_exec('ip route | grep default');
            if ($output && preg_match('/via (\d+\.\d+\.\d+\.\d+)/', $output, $matches)) {
                return $matches[1];
            }
        }
        return null;
    }
}

// installation_check.php - Check system requirements
function checkSystemRequirements() {
    $requirements = [
        'php_version' => [
            'required' => '7.4',
            'current' => PHP_VERSION,
            'status' => version_compare(PHP_VERSION, '7.4', '>=')
        ],
        'extensions' => [
            'sockets' => extension_loaded('sockets'),
            'json' => extension_loaded('json'),
            'curl' => extension_loaded('curl'),
            'snmp' => extension_loaded('snmp') // Optional but recommended
        ],
        'functions' => [
            'exec' => function_exists('exec'),
            'shell_exec' => function_exists('shell_exec'),
            'popen' => function_exists('popen'),
            'fsockopen' => function_exists('fsockopen')
        ],
        'permissions' => [
            'write_data' => is_writable('.'),
            'read_config' => is_readable(__FILE__)
        ]
    ];
    
    return $requirements;
}

function displayRequirements() {
    $req = checkSystemRequirements();
    
    echo "=== Network Scanner System Requirements Check ===\n\n";
    
    echo "PHP Version: " . $req['php_version']['current'] . 
         " (Required: " . $req['php_version']['required'] . ")\n";
    echo "Status: " . ($req['php_version']['status'] ? "✓ OK" : "✗ FAIL") . "\n\n";
    
    echo "Required Extensions:\n";
    foreach ($req['extensions'] as $ext => $loaded) {
        $status = $loaded ? "✓ Loaded" : "✗ Missing";
        $note = ($ext === 'snmp') ? " (Optional - for advanced switch detection)" : "";
        echo "  {$ext}: {$status}{$note}\n";
    }
    
    echo "\nRequired Functions:\n";
    foreach ($req['functions'] as $func => $available) {
        $status = $available ? "✓ Available" : "✗ Disabled";
        echo "  {$func}(): {$status}\n";
    }
    
    echo "\nFile Permissions:\n";
    foreach ($req['permissions'] as $perm => $allowed) {
        $status = $allowed ? "✓ OK" : "✗ FAIL";
        echo "  {$perm}: {$status}\n";
    }
    
    echo "\n=== Installation Instructions ===\n";
    echo "1. Ensure PHP 7.4+ is installed\n";
    echo "2. Enable required PHP extensions in php.ini\n";
    echo "3. Allow exec/shell_exec functions (remove from disable_functions)\n";
    echo "4. Set appropriate file permissions for data storage\n";
    echo "5. For Linux: Install nmap for advanced scanning (optional)\n";
    echo "6. For advanced switch detection: Enable SNMP extension\n";
}

// Run requirements check if called directly
if (basename(__FILE__) == basename($_SERVER['SCRIPT_NAME'])) {
    displayRequirements();
}

// advanced_scanner.php - Enhanced scanning with nmap integration
class AdvancedNetworkScanner extends NetworkScanner {
    
    private $useNmap = false;
    
    public function __construct($subnet = '192.168.1') {
        parent::__construct($subnet);
        $this->useNmap = $this->checkNmapAvailability();
    }
    
    private function checkNmapAvailability() {
        if (PHP_OS_FAMILY === 'Windows') {
            $output = shell_exec('nmap --version 2>NUL');
        } else {
            $output = shell_exec('which nmap 2>/dev/null');
        }
        return !empty($output);
    }
    
    /**
     * Advanced host discovery using nmap
     */
    protected function scanActiveHosts() {
        if ($this->useNmap) {
            return $this->nmapHostDiscovery();
        }
        return parent::scanActiveHosts();
    }
    
    private function nmapHostDiscovery() {
        $this->log("Using nmap for host discovery");
        
        $command = "nmap -sn {$this->subnet}.0/24 2>/dev/null | grep -E 'Nmap scan report'";
        
        if (PHP_OS_FAMILY === 'Windows') {
            $command = "nmap -sn {$this->subnet}.0/24 2>NUL | findstr \"Nmap scan report\"";
        }
        
        $output = shell_exec($command);
        $activeHosts = [];
        
        if ($output) {
            preg_match_all('/(\d+\.\d+\.\d+\.\d+)/', $output, $matches);
            $activeHosts = $matches[1];
        }
        
        $this->log("Nmap found " . count($activeHosts) . " active hosts");
        return $activeHosts;
    }
    
    /**
     * Enhanced port scanning with nmap
     */
    protected function scanPorts($ip) {
        if ($this->useNmap) {
            return $this->nmapPortScan($ip);
        }
        return parent::scanPorts($ip);
    }
    
    private function nmapPortScan($ip) {
        $ports = '21,22,23,25,53,80,110,135,139,143,161,443,445,993,995,8080';
        $command = "nmap -p {$ports} --open {$ip} 2>/dev/null | grep -E '^[0-9]+/(tcp|udp)' | cut -d'/' -f1";
        
        if (PHP_OS_FAMILY === 'Windows') {
            $command = "nmap -p {$ports} --open {$ip} 2>NUL";
        }
        
        $output = shell_exec($command);
        $openPorts = [];
        
        if ($output) {
            if (PHP_OS_FAMILY === 'Windows') {
                preg_match_all('/(\d+)\/tcp\s+open/', $output, $matches);
                $openPorts = array_map('intval', $matches[1]);
            } else {
                $lines = explode("\n", trim($output));
                $openPorts = array_map('intval', array_filter($lines));
            }
        }
        
        return $openPorts;
    }
    
    /**
     * OS detection using nmap
     */
    protected function guessOS($ip) {
        if ($this->useNmap) {
            return $this->nmapOSDetection($ip);
        }
        return parent::guessOS($ip);
    }
    
    private function nmapOSDetection($ip) {
        $command = "nmap -O {$ip} 2>/dev/null | grep -E 'OS details|Running'";
        
        if (PHP_OS_FAMILY === 'Windows') {
            $command = "nmap -O {$ip} 2>NUL";
        }
        
        $output = shell_exec($command);
        
        if ($output) {
            if (stripos($output, 'Windows') !== false) {
                return 'Windows';
            } elseif (stripos($output, 'Linux') !== false) {
                return 'Linux';
            } elseif (stripos($output, 'iOS') !== false) {
                return 'iOS';
            } elseif (stripos($output, 'Android') !== false) {
                return 'Android';
            }
        }
        
        return parent::guessOS($ip);
    }
}

// api_endpoints.php - Additional API endpoints
class NetworkAPI {
    
    private $db;
    private $scanner;
    
    public function __construct() {
        $this->db = new NetworkDatabase();
        $this->scanner = new AdvancedNetworkScanner();
    }
    
    public function handleRequest() {
        $endpoint = $_GET['endpoint'] ?? 'scan';
        
        switch ($endpoint) {
            case 'scan':
                return $this->performScan();
            case 'status':
                return $this->getSystemStatus();
            case 'history':
                return $this->getScanHistory();
            case 'device':
                return $this->getDeviceInfo();
            case 'test':
                return $this->testConnectivity();
            default:
                return $this->errorResponse('Unknown endpoint');
        }
    }
    
    private function performScan() {
        try {
            $subnet = $_GET['subnet'] ?? '192.168.1';
            $this->scanner = new AdvancedNetworkScanner($subnet);
            
            $result = $this->scanner->scanNetwork();
            
            // Save scan result
            $this->db->saveScanResult($result);
            
            return $result;
        } catch (Exception $e) {
            return $this->errorResponse('Scan failed: ' . $e->getMessage());
        }
    }
    
    private function getSystemStatus() {
        $requirements = checkSystemRequirements();
        $connectivity = NetworkUtils::testConnectivity();
        
        return [
            'success' => true,
            'system_info' => NetworkUtils::getSystemInfo(),
            'requirements' => $requirements,
            'connectivity' => $connectivity,
            'last_scan' => $this->db->getLastScan()
        ];
    }
    
    private function getScanHistory() {
        $limit = (int)($_GET['limit'] ?? 10);
        return [
            'success' => true,
            'history' => $this->db->getScanHistory($limit)
        ];
    }
    
    private function getDeviceInfo() {
        $ip = $_GET['ip'] ?? null;
        if (!$ip || !NetworkUtils::isValidIP($ip)) {
            return $this->errorResponse('Invalid IP address');
        }
        
        // Get detailed device information
        $device = $this->scanner->getDeviceDetails($ip);
        
        return [
            'success' => true,
            'device' => $device,
            'history' => $this->db->getDeviceHistory($ip)
        ];
    }
    
    private function testConnectivity() {
        return [
            'success' => true,
            'connectivity_test' => NetworkUtils::testConnectivity()
        ];
    }
    
    private function errorResponse($message) {
        return [
            'success' => false,
            'error' => $message
        ];
    }
}