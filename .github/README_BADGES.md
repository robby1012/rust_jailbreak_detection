# GitHub Workflow Status Badges

Add these badges to your main README.md to show the build status:

## For the main README.md

Add these badges after the title:

```markdown
# Enterprise-Grade iOS Jailbreak Detection Library

[![Release Build](https://github.com/robby1012/rust_jailbreak_detection/actions/workflows/release.yml/badge.svg)](https://github.com/robby1012/rust_jailbreak_detection/actions/workflows/release.yml)
[![Development Build](https://github.com/robby1012/rust_jailbreak_detection/actions/workflows/development.yml/badge.svg)](https://github.com/robby1012/rust_jailbreak_detection/actions/workflows/development.yml)
[![Latest Release](https://img.shields.io/github/v/release/robby1012/rust_jailbreak_detection)](https://github.com/robby1012/rust_jailbreak_detection/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/robby1012/rust_jailbreak_detection/total)](https://github.com/robby1012/rust_jailbreak_detection/releases)
```

## Download Section

Add this section to your README.md:

```markdown
## 📦 Downloads

### Pre-built Binaries

Get the latest pre-built binaries from the [Releases](https://github.com/robby1012/rust_jailbreak_detection/releases) page:

- **Release Build** - Optimized for production use
- **Debug Build** - Includes debug symbols for development
- **Combined Package** - Contains both release and debug builds

Each package includes:
- iOS device library (`libjailbreak_detection_ios.a`)
- iOS simulator universal library (`libjailbreak_detection_simulator.a`) 
- C header file (`jailbreak_detection.h`)
- Integration examples and documentation

### Quick Download Links

| Build Type | Download | Description |
|------------|----------|-------------|
| 🚀 Release | [Download](https://github.com/robby1012/rust_jailbreak_detection/releases/latest/download/jailbreak_detection-release.zip) | Optimized production build |
| 🔧 Debug | [Download](https://github.com/robby1012/rust_jailbreak_detection/releases/latest/download/jailbreak_detection-debug.zip) | Debug build with symbols |
| 📦 Combined | [Download](https://github.com/robby1012/rust_jailbreak_detection/releases/latest/download/jailbreak_detection-combined.zip) | Both release and debug |

## 🔨 Building from Source

### Prerequisites
- Rust 1.70.0 or higher
- Xcode Command Line Tools
- iOS development environment

### Quick Build
```bash
# Clone the repository
git clone https://github.com/robby1012/rust_jailbreak_detection.git
cd rust_jailbreak_detection

# Build all targets (uses the included build script)
./build.sh

# Or build manually with cargo
cargo build --target aarch64-apple-ios --release
cargo build --target aarch64-apple-ios-sim --release
cargo build --target x86_64-apple-ios --release
```

### Using the Build Script
The included `build.sh` script provides comprehensive building options:

```bash
./build.sh                    # Build all targets
./build.sh -c                 # Clean and build
./build.sh -a                 # Build and run all checks
./build.sh --help             # Show all options
```
```
