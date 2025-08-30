#ifndef JAILBREAK_DETECTION_H
#define JAILBREAK_DETECTION_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>

// Forward declaration of the JailbreakDetector struct
typedef struct JailbreakDetector JailbreakDetector;

// Threat level enumeration
typedef enum {
    THREAT_LEVEL_LOW = 0,
    THREAT_LEVEL_MEDIUM = 1,
    THREAT_LEVEL_HIGH = 2,
    THREAT_LEVEL_CRITICAL = 3
} ThreatLevel;

// Device information structure
typedef struct {
    char device_model[256];
    char ios_version[64];
    char architecture[32];
    uint64_t memory_usage;
    uint64_t disk_usage;
} DeviceInfo;

// Detection result structure
typedef struct {
    bool is_jailbroken;
    double confidence;
    char detection_methods[1024];
    uint64_t timestamp;
    DeviceInfo device_info;
    ThreatLevel threat_level;
    char recommendations[1024];
} DetectionResult;

// Security configuration structure
typedef struct {
    bool enable_advanced_detection;
    bool enable_memory_analysis;
    bool enable_network_monitoring;
    bool enable_integrity_checks;
    size_t max_false_positives;
    double detection_threshold;
    char log_level[32];
} SecurityConfig;

// Core detection functions
JailbreakDetector* create_jailbreak_detector(void);
void destroy_jailbreak_detector(JailbreakDetector* detector);
bool perform_detection(JailbreakDetector* detector);

// Legacy compatibility functions
bool is_device_jailbroken(void);
bool is_frida_detected(void);

// Utility functions
char* get_detection_reason(void);
void free_detection_reason(char* ptr);
char* get_security_status(void);
void free_security_status(char* ptr);

// Advanced detection functions
DetectionResult* perform_comprehensive_detection(JailbreakDetector* detector);
void free_detection_result(DetectionResult* result);

// Configuration functions
SecurityConfig* get_default_security_config(void);
void set_security_config(JailbreakDetector* detector, SecurityConfig* config);
void free_security_config(SecurityConfig* config);

// Threat analysis functions
ThreatLevel analyze_threat_level(JailbreakDetector* detector);
double get_confidence_score(JailbreakDetector* detector);
char* get_detection_methods(JailbreakDetector* detector);
char* get_recommendations(JailbreakDetector* detector);

// Device information functions
DeviceInfo* get_device_info(JailbreakDetector* detector);
void free_device_info(DeviceInfo* info);

// Memory and integrity functions
bool check_memory_integrity(JailbreakDetector* detector);
bool check_file_integrity(JailbreakDetector* detector);
bool check_network_integrity(JailbreakDetector* detector);

// Logging and monitoring functions
void enable_detailed_logging(JailbreakDetector* detector, bool enable);
void set_log_level(JailbreakDetector* detector, const char* level);
char* get_detection_history(JailbreakDetector* detector);
void clear_detection_history(JailbreakDetector* detector);

// Anti-tampering functions
bool is_under_attack(JailbreakDetector* detector);
void enable_anti_tampering(JailbreakDetector* detector, bool enable);
bool check_environment_integrity(JailbreakDetector* detector);

// Performance and optimization functions
void set_detection_interval(JailbreakDetector* detector, uint32_t interval_ms);
uint32_t get_detection_interval(JailbreakDetector* detector);
void enable_background_monitoring(JailbreakDetector* detector, bool enable);

// Error handling functions
int get_last_error_code(JailbreakDetector* detector);
char* get_last_error_message(JailbreakDetector* detector);
void clear_last_error(JailbreakDetector* detector);

// Constants
#define JAILBREAK_DETECTION_VERSION "2.0.0"
#define MAX_DETECTION_METHODS 50
#define MAX_RECOMMENDATIONS 20
#define MAX_LOG_ENTRIES 1000

// Error codes
#define JAILBREAK_DETECTION_SUCCESS 0
#define JAILBREAK_DETECTION_ERROR_INVALID_DETECTOR -1
#define JAILBREAK_DETECTION_ERROR_SYSTEM_CALL_FAILED -2
#define JAILBREAK_DETECTION_ERROR_MEMORY_ALLOCATION_FAILED -3
#define JAILBREAK_DETECTION_ERROR_FILE_OPERATION_FAILED -4
#define JAILBREAK_DETECTION_ERROR_PROCESS_ANALYSIS_FAILED -5
#define JAILBREAK_DETECTION_ERROR_NETWORK_ANALYSIS_FAILED -6

#ifdef __cplusplus
}
#endif

#endif // JAILBREAK_DETECTION_H
