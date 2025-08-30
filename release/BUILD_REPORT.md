# Build Report - jailbreak_detection v2.0.0

**Build Date:** Sat Aug 30 00:26:27 WIB 2025
**Build Host:** Robbys-Mac-mini.local
**Rust Version:** rustc 1.89.0 (29483883e 2025-08-04)

## Build Configuration

### Targets Built
- aarch64-apple-ios
- aarch64-apple-ios-sim
- x86_64-apple-ios

### Build Configurations
- debug
- release

## Build Results

### iOS Device (ARM64)
- **Status:** ✅ Success
- **File:** libjailbreak_detection_ios.a
- **Size:** 16M

### iOS Simulator (Universal)
- **Status:** ✅ Success
- **File:** libjailbreak_detection_simulator.a
- **Size:** 32M

## Dependencies

```toml
name = "jailbreak_detection"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["staticlib"]

[dependencies]
# Core system dependencies
libc = "0.2"

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

# Error handling
thiserror = "1.0"

# Time utilities
chrono = { version = "0.4", features = ["serde"] }

# File system utilities
walkdir = "2.4"
```

## Usage Instructions

1. Add the appropriate `.a` file to your Xcode project
2. Include the `jailbreak_detection.h` header file
3. Link against the library in your build settings

## Security Notes

- This library contains enterprise-grade security features
- All unsafe code blocks have been reviewed for security
- Memory management follows Rust safety guidelines
- Comprehensive error handling implemented

## Support

For issues and questions, please refer to the README.md file or create an issue in the repository.
