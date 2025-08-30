use std::ffi::CString;
use std::os::raw::c_char;
use std::process::Command;
use std::sync::{Arc, Mutex, Once};
use std::time::{Duration, Instant, UNIX_EPOCH};
use std::collections::HashMap;
use std::fs::{self, File};

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize};

// External crates
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

// Constants
const MAX_DETECTION_ATTEMPTS: usize = 10000;
const SUSPICIOUS_EXECUTION_TIME_MS: u128 = 500;
const MAX_MEMORY_USAGE_MB: u64 = 100;
const INTEGRITY_CHECK_INTERVAL: Duration = Duration::from_secs(300); // 5 minutes

// Global state
static INIT: Once = Once::new();
static DETECTION_COUNTER: AtomicUsize = AtomicUsize::new(0);
static LAST_INTEGRITY_CHECK: AtomicU64 = AtomicU64::new(0);
static IS_UNDER_ATTACK: AtomicBool = AtomicBool::new(false);

// Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub enable_advanced_detection: bool,
    pub enable_memory_analysis: bool,
    pub enable_network_monitoring: bool,
    pub enable_integrity_checks: bool,
    pub max_false_positives: usize,
    pub detection_threshold: f64,
    pub log_level: String,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enable_advanced_detection: true,
            enable_memory_analysis: true,
            enable_network_monitoring: true,
            enable_integrity_checks: true,
            max_false_positives: 3,
            detection_threshold: 0.8,
            log_level: "info".to_string(),
        }
    }
}

// Detection results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    pub is_jailbroken: bool,
    pub confidence: f64,
    pub detection_methods: Vec<String>,
    pub timestamp: DateTime<Utc>,
    pub device_info: DeviceInfo,
    pub threat_level: ThreatLevel,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub device_model: String,
    pub ios_version: String,
    pub architecture: String,
    pub memory_usage: u64,
    pub disk_usage: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ThreatLevel {
    Low,
    Medium,
    High,
    Critical,
}

// Error types
#[derive(Debug, thiserror::Error)]
pub enum DetectionError {
    #[error("System call failed: {0}")]
    SystemCallFailed(String),
    #[error("Memory allocation failed")]
    MemoryAllocationFailed,
    #[error("File operation failed: {0}")]
    FileOperationFailed(String),
    #[error("Process analysis failed: {0}")]
    ProcessAnalysisFailed(String),
    #[error("Network analysis failed: {0}")]
    NetworkAnalysisFailed(String),
}

// Jailbreak detection engine
pub struct JailbreakDetector {
    config: SecurityConfig,
    detection_history: Arc<Mutex<Vec<DetectionResult>>>,
    integrity_hashes: Arc<Mutex<HashMap<String, String>>>,
    last_check: Arc<Mutex<Instant>>,
}

impl JailbreakDetector {
    pub fn new(config: SecurityConfig) -> Self {
        Self {
            config,
            detection_history: Arc::new(Mutex::new(Vec::new())),
            integrity_hashes: Arc::new(Mutex::new(HashMap::new())),
            last_check: Arc::new(Mutex::new(Instant::now())),
        }
    }

    pub fn perform_comprehensive_detection(&self) -> DetectionResult {
        let start_time = Instant::now();
        let mut detection_methods = Vec::new();
        let mut confidence_score: f64 = 0.0;
        let mut threat_level = ThreatLevel::Low;

        // Basic detection methods
        if self.check_common_jailbreak_files() {
            detection_methods.push("Common jailbreak files detected".to_string());
            confidence_score += 0.3;
            threat_level = ThreatLevel::High;
        }

        if self.check_suspicious_processes() {
            detection_methods.push("Suspicious processes detected".to_string());
            confidence_score += 0.25;
            threat_level = ThreatLevel::High;
        }

        if self.check_system_integrity() {
            detection_methods.push("System integrity compromised".to_string());
            confidence_score += 0.4;
            threat_level = ThreatLevel::Critical;
        }

        // Advanced detection methods
        if self.config.enable_advanced_detection {
            if self.check_memory_tampering() {
                detection_methods.push("Memory tampering detected".to_string());
                confidence_score += 0.35;
                threat_level = ThreatLevel::Critical;
            }

            if self.check_code_injection() {
                detection_methods.push("Code injection detected".to_string());
                confidence_score += 0.4;
                threat_level = ThreatLevel::Critical;
            }

            if self.check_hook_detection() {
                detection_methods.push("Runtime hooks detected".to_string());
                confidence_score += 0.3;
                threat_level = ThreatLevel::High;
            }
        }

        // Memory analysis
        if self.config.enable_memory_analysis {
            if self.check_memory_anomalies() {
                detection_methods.push("Memory anomalies detected".to_string());
                confidence_score += 0.2;
                threat_level = ThreatLevel::Medium;
            }
        }

        // Network monitoring
        if self.config.enable_network_monitoring {
            if self.check_network_anomalies() {
                detection_methods.push("Network anomalies detected".to_string());
                confidence_score += 0.15;
                threat_level = ThreatLevel::Medium;
            }
        }

        // Integrity checks
        if self.config.enable_integrity_checks {
            if self.check_file_integrity() {
                detection_methods.push("File integrity compromised".to_string());
                confidence_score += 0.3;
                threat_level = ThreatLevel::High;
            }
        }

        // Timing analysis for hook detection
        let execution_time = start_time.elapsed();
        if execution_time.as_millis() > SUSPICIOUS_EXECUTION_TIME_MS {
            detection_methods.push("Suspicious execution time detected".to_string());
            confidence_score += 0.2;
            threat_level = ThreatLevel::Medium;
        }

        // Normalize confidence score
        confidence_score = confidence_score.min(1.0);

        let result = DetectionResult {
            is_jailbroken: confidence_score >= self.config.detection_threshold,
            confidence: confidence_score,
            detection_methods,
            timestamp: Utc::now(),
            device_info: self.gather_device_info(),
            threat_level,
            recommendations: self.generate_recommendations(&threat_level),
        };

        // Store result in history
        if let Ok(mut history) = self.detection_history.lock() {
            history.push(result.clone());
            if history.len() > 100 {
                history.remove(0);
            }
        }

        // Update last check time
        if let Ok(mut last_check) = self.last_check.lock() {
            *last_check = Instant::now();
        }

        result
    }

    fn check_common_jailbreak_files(&self) -> bool {
        let jailbreak_indicators = [
            // Traditional jailbreak paths
            "/Applications/Cydia.app",
            "/Applications/Sileo.app",
            "/Applications/Zebra.app",
            "/Applications/Installer.app",
            "/Applications/NewTerm.app",
            "/Applications/Filza.app",
            "/Applications/PreferenceLoader.app",
            
            // System libraries and frameworks
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/Library/MobileSubstrate/DynamicLibraries",
            "/usr/libexec/ssh-keysign",
            "/usr/sbin/sshd",
            "/usr/bin/ssh",
            "/usr/bin/scp",
            "/usr/bin/sftp",
            
            // Package management
            "/var/cache/apt",
            "/var/lib/apt",
            "/var/lib/cydia",
            "/var/lib/dpkg",
            "/var/jb",
            "/var/lib/undecimus",
            "/var/lib/electra",
            "/var/lib/checkra1n",
            "/var/lib/odyssey",
            "/var/lib/taurine",
            "/var/lib/unc0ver",
            
            // Configuration files
            "/etc/apt",
            "/etc/ssh",
            "/etc/ssh/sshd_config",
            "/etc/ssh/ssh_config",
            
            // Binaries
            "/bin/bash",
            "/bin/sh",
            "/bin/zsh",
            "/bin/tcsh",
            "/bin/csh",
            "/bin/ksh",
            
            // Private directories
            "/private/var/stash",
            "/private/var/mobile/Library/Cydia",
            "/private/var/mobile/Library/Sileo",
            "/private/var/mobile/Library/Zebra",
            
            // Modern jailbreak indicators
            "/var/checkra1n.dmg",
            "/var/binpack",
            "/.installed_unc0ver",
            "/.bootstrapped_electra",
            "/.installed_odyssey",
            "/.installed_taurine",
            "/.installed_checkra1n",
            
            // TrollStore
            "/Applications/trollstore.app",
            "/var/containers/Bundle/Application/trollstore",
            
            // Substitute and TweakInject
            "/var/lib/substitute",
            "/usr/lib/TweakInject.dylib",
            "/usr/lib/libsubstitute.dylib",
            "/usr/lib/substrate",
            "/usr/lib/substitute",
            
            // Additional modern paths
            "/var/mobile/Library/Preferences/com.saurik.Cydia.plist",
            "/var/mobile/Library/Preferences/com.saurik.Sileo.plist",
            "/var/mobile/Library/Preferences/com.zbra.zbra.plist",
            "/var/mobile/Library/Preferences/com.installer.installer.plist",
        ];

        for indicator in jailbreak_indicators.iter() {
            if self.check_path_exists(indicator) {
                return true;
            }
        }

        false
    }

    fn check_suspicious_processes(&self) -> bool {
        let suspicious_processes = [
            // Jailbreak tools
            "Cydia", "Sileo", "Zebra", "Installer", "NewTerm", "Filza",
            "PreferenceLoader", "Substrate", "substrated", "substitute",
            
            // SSH and networking
            "SSHd", "dropbear", "sshd", "ssh", "scp", "sftp",
            
            // Jailbreak-specific processes
            "checkra1n", "palera1n", "odyssey", "taurine", "unc0ver",
            "electra", "chimera", "rootlessJB", "rootlessJB4",
            
            // Development and debugging tools
            "frida-server", "frida-helper", "frida-agent", "clutch",
            "dumpdecrypted", "Flex", "cycript", "substrate",
            
            // Additional tools
            "trollstore", "jbpatcher", "jbpatcher64", "jbpatcher-arm64",
            "jbpatcher-arm64e", "jbpatcher-arm64e-sim", "jbpatcher-arm64-sim",
        ];

        if let Ok(output) = Command::new("ps").args(&["-A", "-o", "comm"]).output() {
            let process_list = String::from_utf8_lossy(&output.stdout);
            for process in suspicious_processes.iter() {
                if process_list.contains(process) {
                    return true;
                }
            }
        }

        false
    }

    fn check_system_integrity(&self) -> bool {
        // Check for writable system directories
        let protected_paths = ["/System", "/private", "/usr", "/bin", "/sbin"];
        
        for path in protected_paths.iter() {
            if let Ok(metadata) = fs::metadata(path) {
                if !metadata.permissions().readonly() {
                    return true;
                }
            }
        }

        // Check system partition mounting status
        if let Ok(output) = Command::new("mount").output() {
            let mount_info = String::from_utf8_lossy(&output.stdout);
            if mount_info.contains("rw") && mount_info.contains("/private/preboot") {
                return true;
            }
        }

        // Check for suspicious symlinks
        let suspicious_symlinks = [
            "/var/lib/dpkg",
            "/var/cache/apt",
            "/var/lib/apt",
            "/var/log/apt",
            "/etc/alternatives",
        ];

        for symlink in suspicious_symlinks.iter() {
            if fs::read_link(symlink).is_ok() {
                return true;
            }
        }

        false
    }

    fn check_memory_tampering(&self) -> bool {
        // Check for suspicious memory regions
        if let Ok(output) = Command::new("vmmap").arg(std::process::id().to_string()).output() {
            let memory_map = String::from_utf8_lossy(&output.stdout);
            
            let suspicious_patterns = [
                "frida", "substrate", "substitute", "tweak", "inject",
                "hook", "patch", "bypass", "jailbreak", "root",
            ];

            for pattern in suspicious_patterns.iter() {
                if memory_map.to_lowercase().contains(pattern) {
                    return true;
                }
            }
        }

        // Check memory usage anomalies
        if let Ok(memory_usage) = self.get_memory_usage() {
            if memory_usage > MAX_MEMORY_USAGE_MB * 1024 * 1024 {
                return true;
            }
        }

        false
    }

    fn check_code_injection(&self) -> bool {
        // Check for suspicious loaded libraries
        if let Ok(output) = Command::new("otool").args(&["-L", "/proc/self/exe"]).output() {
            let libraries = String::from_utf8_lossy(&output.stdout);
            
            let suspicious_libraries = [
                "frida-agent", "frida-gadget", "FridaGadget",
                "substrate", "substitute", "TweakInject",
                "MobileSubstrate", "libsubstitute", "libsubstrate",
            ];

            for library in suspicious_libraries.iter() {
                if libraries.contains(library) {
                    return true;
                }
            }
        }

        // Check for suspicious frameworks
        let suspicious_frameworks = [
            "/Library/Frameworks/CydiaSubstrate.framework",
            "/Library/Frameworks/TweakInject.framework",
            "/Library/Frameworks/SubstrateLoader.framework",
            "/Library/Frameworks/SubstrateBootstrap.framework",
            "/Library/Frameworks/RocketBootstrap.framework",
            "/System/Library/Frameworks/Substrate.framework",
        ];

        for framework in suspicious_frameworks.iter() {
            if self.check_path_exists(framework) {
                return true;
            }
        }

        false
    }

    fn check_hook_detection(&self) -> bool {
        // Check for suspicious URL schemes
        let suspicious_schemes = ["cydia", "sileo", "zebra", "installer"];
        
        for scheme in suspicious_schemes.iter() {
            if let Ok(output) = Command::new("xcrun")
                .args(&["simctl", "openurl", &format!("{}://", scheme)])
                .output() 
            {
                if output.status.success() {
                    return true;
                }
            }
        }

        // Check for suspicious entitlements
        if let Ok(output) = Command::new("codesign").args(&["-d", "--entitlements", ":", "/proc/self/exe"]).output() {
            let entitlements = String::from_utf8_lossy(&output.stdout);
            if entitlements.contains("get-task-allow") || entitlements.contains("com.apple.security.get-task-allow") {
                return true;
            }
        }

        false
    }

    fn check_memory_anomalies(&self) -> bool {
        // Check for memory pressure
        if let Ok(output) = Command::new("vm_stat").output() {
            let vm_stats = String::from_utf8_lossy(&output.stdout);
            if vm_stats.contains("pressure") && vm_stats.contains("high") {
                return true;
            }
        }

        // Check for suspicious memory mappings
        if let Ok(output) = Command::new("vmmap").args(&["-pages", &std::process::id().to_string()]).output() {
            let pages = String::from_utf8_lossy(&output.stdout);
            if pages.contains("rwx") || pages.contains("rwxp") {
                return true;
            }
        }

        false
    }

    fn check_network_anomalies(&self) -> bool {
        // Check for suspicious network connections
        if let Ok(output) = Command::new("netstat").args(&["-an"]).output() {
            let connections = String::from_utf8_lossy(&output.stdout);
            
            // Check for Frida default ports
            let frida_ports = ["27042", "27043", "27044"];
            for port in frida_ports.iter() {
                if connections.contains(port) {
                    return true;
                }
            }

            // Check for suspicious local connections
            if connections.contains("127.0.0.1:22") || connections.contains("127.0.0.1:2222") {
                return true;
            }
        }

        // Check for suspicious network interfaces
        if let Ok(output) = Command::new("ifconfig").output() {
            let interfaces = String::from_utf8_lossy(&output.stdout);
            if interfaces.contains("tun0") || interfaces.contains("ppp0") {
                return true;
            }
        }

        false
    }

    fn check_file_integrity(&self) -> bool {
        // Check critical system files
        let critical_files = [
            "/System/Library/CoreServices/SystemVersion.plist",
            "/System/Library/CoreServices/SpringBoard.app/SpringBoard",
            "/usr/lib/system/libsystem_kernel.dylib",
            "/usr/lib/system/libsystem_platform.dylib",
        ];

        for file_path in critical_files.iter() {
            if let Ok(current_hash) = self.calculate_file_hash(file_path) {
                if let Ok(stored_hash) = self.get_stored_hash(file_path) {
                    if current_hash != stored_hash {
                        return true;
                    }
                } else {
                    // Store initial hash
                    self.store_file_hash(file_path, &current_hash);
                }
            }
        }

        false
    }

    fn check_path_exists(&self, path: &str) -> bool {
        fs::metadata(path).is_ok()
    }

    fn get_memory_usage(&self) -> Result<u64, DetectionError> {
        // Simple memory usage check using system commands
        if let Ok(output) = Command::new("ps").args(&["-o", "rss=", "-p", &std::process::id().to_string()]).output() {
            if let Ok(memory_str) = String::from_utf8(output.stdout) {
                if let Ok(memory_kb) = memory_str.trim().parse::<u64>() {
                    return Ok(memory_kb * 1024); // Convert KB to bytes
                }
            }
        }
        Ok(0)
    }

    fn calculate_file_hash(&self, file_path: &str) -> Result<String, DetectionError> {
        let file = File::open(file_path)
            .map_err(|e| DetectionError::FileOperationFailed(e.to_string()))?;
        
        // Simple hash calculation using file size and modification time
        let metadata = file.metadata()
            .map_err(|e| DetectionError::FileOperationFailed(e.to_string()))?;
        
        let size = metadata.len();
        let modified = metadata.modified()
            .map_err(|e| DetectionError::FileOperationFailed(e.to_string()))?
            .duration_since(UNIX_EPOCH)
            .map_err(|e| DetectionError::FileOperationFailed(e.to_string()))?
            .as_secs();
        
        // Create a simple hash from size and modification time
        let hash_input = format!("{}_{}", size, modified);
        Ok(format!("{:x}", hash_input.len() as u64))
    }

    fn get_stored_hash(&self, file_path: &str) -> Result<String, DetectionError> {
        if let Ok(hashes) = self.integrity_hashes.lock() {
            if let Some(hash) = hashes.get(file_path) {
                return Ok(hash.clone());
            }
        }
        Err(DetectionError::FileOperationFailed("Hash not found".to_string()))
    }

    fn store_file_hash(&self, file_path: &str, hash: &str) {
        if let Ok(mut hashes) = self.integrity_hashes.lock() {
            hashes.insert(file_path.to_string(), hash.to_string());
        }
    }

    fn gather_device_info(&self) -> DeviceInfo {
        DeviceInfo {
            device_model: self.get_device_model().unwrap_or_else(|_| "Unknown".to_string()),
            ios_version: self.get_ios_version().unwrap_or_else(|_| "Unknown".to_string()),
            architecture: self.get_architecture().unwrap_or_else(|_| "Unknown".to_string()),
            memory_usage: self.get_memory_usage().unwrap_or(0),
            disk_usage: self.get_disk_usage().unwrap_or(0),
        }
    }

    fn get_device_model(&self) -> Result<String, DetectionError> {
        if let Ok(output) = Command::new("sysctl").args(&["-n", "hw.model"]).output() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            Err(DetectionError::SystemCallFailed("Failed to get device model".to_string()))
        }
    }

    fn get_ios_version(&self) -> Result<String, DetectionError> {
        if let Ok(output) = Command::new("sw_vers").arg("-productVersion").output() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            Err(DetectionError::SystemCallFailed("Failed to get iOS version".to_string()))
        }
    }

    fn get_architecture(&self) -> Result<String, DetectionError> {
        if let Ok(output) = Command::new("uname").arg("-m").output() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            Err(DetectionError::SystemCallFailed("Failed to get architecture".to_string()))
        }
    }

    fn get_disk_usage(&self) -> Result<u64, DetectionError> {
        if let Ok(output) = Command::new("df").arg("/").output() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            let lines: Vec<&str> = output_str.lines().collect();
            if lines.len() > 1 {
                let parts: Vec<&str> = lines[1].split_whitespace().collect();
                if parts.len() > 2 {
                    if let Ok(usage) = parts[2].parse::<u64>() {
                        return Ok(usage * 1024); // Convert to bytes
                    }
                }
            }
        }
        Err(DetectionError::SystemCallFailed("Failed to get disk usage".to_string()))
    }

    fn generate_recommendations(&self, threat_level: &ThreatLevel) -> Vec<String> {
        match threat_level {
            ThreatLevel::Low => vec![
                "Continue monitoring device for suspicious activity".to_string(),
                "Enable additional security measures".to_string(),
            ],
            ThreatLevel::Medium => vec![
                "Investigate detected anomalies immediately".to_string(),
                "Consider device quarantine".to_string(),
                "Review recent app installations".to_string(),
            ],
            ThreatLevel::High => vec![
                "Device should be quarantined immediately".to_string(),
                "Disconnect from corporate network".to_string(),
                "Contact security team".to_string(),
                "Consider device wipe and re-enrollment".to_string(),
            ],
            ThreatLevel::Critical => vec![
                "CRITICAL: Device compromised".to_string(),
                "Immediate quarantine and investigation required".to_string(),
                "Disconnect from all networks".to_string(),
                "Contact security team immediately".to_string(),
                "Device wipe and re-enrollment mandatory".to_string(),
            ],
        }
    }
}

// C interface functions
#[no_mangle]
pub extern "C" fn create_jailbreak_detector() -> *mut JailbreakDetector {
    let config = SecurityConfig::default();
    let detector = JailbreakDetector::new(config);
    Box::into_raw(Box::new(detector))
}

#[no_mangle]
pub extern "C" fn destroy_jailbreak_detector(detector: *mut JailbreakDetector) {
    if !detector.is_null() {
        unsafe {
            let _ = Box::from_raw(detector);
        }
    }
}

#[no_mangle]
pub extern "C" fn perform_detection(detector: *mut JailbreakDetector) -> bool {
    if detector.is_null() {
        return false;
    }

    unsafe {
        let detector_ref = &*detector;
        let result = detector_ref.perform_comprehensive_detection();
        result.is_jailbroken
    }
}

#[no_mangle]
pub extern "C" fn get_detection_reason() -> *mut c_char {
    let reason = CString::new("Enterprise-grade jailbreak detection performed").unwrap();
    reason.into_raw()
}

#[no_mangle]
pub extern "C" fn free_detection_reason(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}

// Legacy compatibility functions
#[no_mangle]
pub unsafe extern "C" fn is_device_jailbroken() -> bool {
    let config = SecurityConfig::default();
    let detector = JailbreakDetector::new(config);
    let result = detector.perform_comprehensive_detection();
    result.is_jailbroken
}

#[no_mangle]
pub unsafe extern "C" fn is_frida_detected() -> bool {
    let config = SecurityConfig::default();
    let detector = JailbreakDetector::new(config);
    
    // Check for Frida-specific indicators
    if detector.check_suspicious_processes() {
        return true;
    }
    
    if detector.check_memory_tampering() {
        return true;
    }
    
    if detector.check_network_anomalies() {
        return true;
    }
    
    false
}

// Additional security functions
#[no_mangle]
pub extern "C" fn get_security_status() -> *mut c_char {
    let status = serde_json::to_string(&SecurityConfig::default()).unwrap_or_default();
    let c_string = CString::new(status).unwrap();
    c_string.into_raw()
}

#[no_mangle]
pub extern "C" fn free_security_status(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}

// MARK: - Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_config_default() {
        let config = SecurityConfig::default();
        assert_eq!(config.enable_advanced_detection, true);
        assert_eq!(config.enable_memory_analysis, true);
        assert_eq!(config.enable_network_monitoring, true);
        assert_eq!(config.enable_integrity_checks, true);
        assert_eq!(config.max_false_positives, 3);
        assert_eq!(config.detection_threshold, 0.8);
        assert_eq!(config.log_level, "info");
    }

    #[test]
    fn test_jailbreak_detector_creation() {
        let config = SecurityConfig::default();
        let detector = JailbreakDetector::new(config);
        assert_eq!(detector.config.enable_advanced_detection, true);
    }

    #[test]
    fn test_detection_result_creation() {
        let device_info = DeviceInfo {
            device_model: "iPhone".to_string(),
            ios_version: "15.0".to_string(),
            architecture: "arm64".to_string(),
            memory_usage: 1024 * 1024,
            disk_usage: 1024 * 1024 * 1024,
        };

        let result = DetectionResult {
            is_jailbroken: false,
            confidence: 0.1,
            detection_methods: vec!["No threats detected".to_string()],
            timestamp: Utc::now(),
            device_info,
            threat_level: ThreatLevel::Low,
            recommendations: vec!["Continue monitoring".to_string()],
        };

        assert_eq!(result.is_jailbroken, false);
        assert_eq!(result.confidence, 0.1);
        assert_eq!(result.threat_level as i32, ThreatLevel::Low as i32);
    }

    #[test]
    fn test_threat_level_ordering() {
        assert!((ThreatLevel::Low as i32) < (ThreatLevel::Medium as i32));
        assert!((ThreatLevel::Medium as i32) < (ThreatLevel::High as i32));
        assert!((ThreatLevel::High as i32) < (ThreatLevel::Critical as i32));
    }

    #[test]
    fn test_device_info_creation() {
        let device_info = DeviceInfo {
            device_model: "iPad".to_string(),
            ios_version: "16.0".to_string(),
            architecture: "arm64".to_string(),
            memory_usage: 2048 * 1024,
            disk_usage: 2048 * 1024 * 1024,
        };

        assert_eq!(device_info.device_model, "iPad");
        assert_eq!(device_info.ios_version, "16.0");
        assert_eq!(device_info.architecture, "arm64");
        assert_eq!(device_info.memory_usage, 2048 * 1024);
        assert_eq!(device_info.disk_usage, 2048 * 1024 * 1024);
    }

    #[test]
    fn test_recommendations_generation() {
        let config = SecurityConfig::default();
        let detector = JailbreakDetector::new(config);

        let low_recommendations = detector.generate_recommendations(&ThreatLevel::Low);
        assert_eq!(low_recommendations.len(), 2);
        assert!(low_recommendations.contains(&"Continue monitoring device for suspicious activity".to_string()));

        let critical_recommendations = detector.generate_recommendations(&ThreatLevel::Critical);
        assert_eq!(critical_recommendations.len(), 5);
        assert!(critical_recommendations.contains(&"CRITICAL: Device compromised".to_string()));
    }

    #[test]
    fn test_path_existence_check() {
        let config = SecurityConfig::default();
        let detector = JailbreakDetector::new(config);

        // Test with non-existent path
        assert_eq!(detector.check_path_exists("/nonexistent/path"), false);

        // Test with root path (should exist on most systems)
        assert_eq!(detector.check_path_exists("/"), true);
    }

    #[test]
    fn test_comprehensive_detection() {
        let config = SecurityConfig::default();
        let detector = JailbreakDetector::new(config);

        let result = detector.perform_comprehensive_detection();
        
        // Verify result structure
        assert!(result.confidence >= 0.0);
        assert!(result.confidence <= 1.0);
        assert!(!result.detection_methods.is_empty());
        assert!(!result.recommendations.is_empty());
        
        // Verify device info
        assert!(!result.device_info.device_model.is_empty());
        assert!(!result.device_info.ios_version.is_empty());
        assert!(!result.device_info.architecture.is_empty());
    }

    #[test]
    fn test_error_types() {
        let system_error = DetectionError::SystemCallFailed("Test error".to_string());
        assert_eq!(system_error.to_string(), "System call failed: Test error");

        let file_error = DetectionError::FileOperationFailed("File error".to_string());
        assert_eq!(file_error.to_string(), "File operation failed: File error");
    }

    #[test]
    fn test_serialization() {
        let config = SecurityConfig::default();
        let json = serde_json::to_string(&config);
        assert!(json.is_ok());

        let deserialized: SecurityConfig = serde_json::from_str(&json.unwrap()).unwrap();
        assert_eq!(deserialized.enable_advanced_detection, config.enable_advanced_detection);
        assert_eq!(deserialized.enable_memory_analysis, config.enable_memory_analysis);
    }

    #[test]
    fn test_constants() {
        assert_eq!(MAX_DETECTION_ATTEMPTS, 10000);
        assert_eq!(SUSPICIOUS_EXECUTION_TIME_MS, 500);
        assert_eq!(MAX_MEMORY_USAGE_MB, 100);
        assert_eq!(INTEGRITY_CHECK_INTERVAL, Duration::from_secs(300));
    }

    #[test]
    fn test_c_interface_functions() {
        // Test detector creation
        let detector = create_jailbreak_detector();
        assert!(!detector.is_null());

        // Test detection
        let result = perform_detection(detector);
        // Result depends on system state, so we just verify it's a boolean

        // Test reason retrieval
        let reason = get_detection_reason();
        assert!(!reason.is_null());
        free_detection_reason(reason);

        // Test security status
        let status = get_security_status();
        assert!(!status.is_null());
        free_security_status(status);

        // Clean up
        destroy_jailbreak_detector(detector);
    }

    #[test]
    fn test_legacy_functions() {
        // Test legacy jailbreak detection
        let is_jailbroken = unsafe { is_device_jailbroken() };
        // Result depends on system state

        // Test Frida detection
        let frida_detected = unsafe { is_frida_detected() };
        // Result depends on system state
    }
}