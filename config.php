<?php
/**
 * Configuration loader for Security Utils
 * Loads environment variables and provides application constants
 */

class ConfigLoader {
    private static $config = [];
    private static $loaded = false;
    
    /**
     * Load configuration from .env file
     */
    public static function load($envFile = '.env') {
        if (self::$loaded) {
            return;
        }
        
        $envPath = __DIR__ . '/' . $envFile;
        
        if (!file_exists($envPath)) {
            // Fallback to hardcoded values if .env doesn't exist
            self::$config = [
                'APP_VERSION' => 'v2.0.2',
                'APP_NAME' => 'Security Utils',
                'HASH_GENERATOR_NAME' => 'Password Hash Generator',
                'APP_ENV' => 'production'
            ];
            self::$loaded = true;
            return;
        }
        
        $envContent = file_get_contents($envPath);
        $lines = explode("\n", $envContent);
        
        foreach ($lines as $line) {
            $line = trim($line);
            
            // Skip empty lines and comments
            if (empty($line) || strpos($line, '#') === 0) {
                continue;
            }
            
            // Parse key=value format
            if (strpos($line, '=') !== false) {
                list($key, $value) = explode('=', $line, 2);
                $key = trim($key);
                $value = trim($value);
                
                // Remove quotes if present
                if ((substr($value, 0, 1) === '"' && substr($value, -1) === '"') ||
                    (substr($value, 0, 1) === "'" && substr($value, -1) === "'")) {
                    $value = substr($value, 1, -1);
                }
                
                self::$config[$key] = $value;
            }
        }
        
        self::$loaded = true;
    }
    
    /**
     * Get a configuration value
     */
    public static function get($key, $default = null) {
        self::load();
        return isset(self::$config[$key]) ? self::$config[$key] : $default;
    }
    
    /**
     * Get app version
     */
    public static function getVersion() {
        return self::get('APP_VERSION');
    }
    
    /**
     * Get app name
     */
    public static function getAppName() {
        return self::get('APP_NAME');
    }
    
    /**
     * Get hash generator name
     */
    public static function getHashGeneratorName() {
        return self::get('HASH_GENERATOR_NAME');
    }
}

// Auto-load configuration
ConfigLoader::load();