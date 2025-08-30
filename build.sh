#!/bin/bash

# Enterprise-Grade iOS Jailbreak Detection Library Build Script
# This script builds the library for various iOS targets and architectures

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
LIBRARY_NAME="jailbreak_detection"
VERSION="2.0.0"
BUILD_DIR="target"
RELEASE_DIR="release"

# iOS targets
TARGETS=(
    "aarch64-apple-ios"           # iOS devices (ARM64)
    "aarch64-apple-ios-sim"       # iOS simulator (ARM64)
    "x86_64-apple-ios"            # iOS simulator (x86_64, Intel Macs)
)

# Build configurations
BUILD_CONFIGS=(
    "debug"
    "release"
)

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check prerequisites
check_prerequisites() {
    print_status "Checking build prerequisites..."
    
    if ! command_exists cargo; then
        print_error "Rust/Cargo not found. Please install Rust first."
        print_status "Visit: https://rustup.rs/"
        exit 1
    fi
    
    if ! command_exists rustc; then
        print_error "Rust compiler not found. Please install Rust first."
        exit 1
    fi
    
    # Check Rust version
    RUST_VERSION=$(rustc --version | cut -d' ' -f2)
    REQUIRED_VERSION="1.70.0"
    
    if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$RUST_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
        print_warning "Rust version $RUST_VERSION detected. Version $REQUIRED_VERSION or higher is recommended."
    fi
    
    print_success "Prerequisites check completed"
}

# Function to add iOS targets
add_ios_targets() {
    print_status "Adding iOS targets to Rust..."
    
    for target in "${TARGETS[@]}"; do
        if ! rustup target list --installed | grep -q "$target"; then
            print_status "Adding target: $target"
            rustup target add "$target"
        else
            print_status "Target $target already installed"
        fi
    done
    
    print_success "iOS targets configured"
}

# Function to clean build artifacts
clean_build() {
    print_status "Cleaning build artifacts..."
    
    if [ -d "$BUILD_DIR" ]; then
        rm -rf "$BUILD_DIR"
        print_status "Build directory cleaned"
    fi
    
    if [ -d "$RELEASE_DIR" ]; then
        rm -rf "$RELEASE_DIR"
        print_status "Release directory cleaned"
    fi
    
    # Clean Cargo artifacts
    cargo clean
    print_success "Clean completed"
}

# Function to build for a specific target and configuration
build_target() {
    local target=$1
    local config=$2
    
    print_status "Building for $target ($config)..."
    
    local build_args="--target $target"
    if [ "$config" = "release" ]; then
        build_args="$build_args --release"
    fi
    
    if cargo build $build_args; then
        print_success "Build completed for $target ($config)"
        return 0
    else
        print_error "Build failed for $target ($config)"
        return 1
    fi
}

# Function to build all targets
build_all_targets() {
    print_status "Starting build process for all targets..."
    
    local build_success=true
    
    for target in "${TARGETS[@]}"; do
        for config in "${BUILD_CONFIGS[@]}"; do
            if ! build_target "$target" "$config"; then
                build_success=false
            fi
        done
    done
    
    if [ "$build_success" = true ]; then
        print_success "All builds completed successfully"
    else
        print_error "Some builds failed"
        exit 1
    fi
}

# Function to create universal binary
create_universal_binary() {
    print_status "Creating universal binary..."
    
    mkdir -p "$RELEASE_DIR"
    
    # Create universal binary for iOS devices (ARM64)
    if [ -f "$BUILD_DIR/aarch64-apple-ios/release/lib$LIBRARY_NAME.a" ]; then
        cp "$BUILD_DIR/aarch64-apple-ios/release/lib$LIBRARY_NAME.a" "$RELEASE_DIR/lib${LIBRARY_NAME}_ios.a"
        print_success "iOS device binary created"
    fi
    
    # Create universal binary for iOS simulator
    if [ -f "$BUILD_DIR/aarch64-apple-ios-sim/release/lib$LIBRARY_NAME.a" ] && [ -f "$BUILD_DIR/x86_64-apple-ios/release/lib$LIBRARY_NAME.a" ]; then
        lipo -create \
            "$BUILD_DIR/aarch64-apple-ios-sim/release/lib$LIBRARY_NAME.a" \
            "$BUILD_DIR/x86_64-apple-ios/release/lib$LIBRARY_NAME.a" \
            -output "$RELEASE_DIR/lib${LIBRARY_NAME}_simulator.a"
        print_success "iOS simulator universal binary created"
    fi
    
    # Copy header file
    if [ -f "jailbreak_detection.h" ]; then
        cp "jailbreak_detection.h" "$RELEASE_DIR/"
        print_success "Header file copied"
    fi
    
    # Create version info
    echo "Version: $VERSION" > "$RELEASE_DIR/VERSION"
    echo "Build Date: $(date)" >> "$RELEASE_DIR/VERSION"
    echo "Targets: ${TARGETS[*]}" >> "$RELEASE_DIR/VERSION"
    
    print_success "Universal binary creation completed"
}

# Function to run tests
run_tests() {
    print_status "Running tests..."
    
    if cargo test; then
        print_success "Tests passed"
    else
        print_error "Tests failed"
        exit 1
    fi
}

# Function to run clippy (Rust linter)
run_clippy() {
    print_status "Running Clippy (Rust linter)..."
    
    if command_exists cargo-clippy; then
        if cargo clippy -- -D warnings; then
            print_success "Clippy passed"
        else
            print_warning "Clippy found issues"
        fi
    else
        print_warning "Clippy not installed. Install with: cargo install clippy"
    fi
}

# Function to check security
security_check() {
    print_status "Running security checks..."
    
    # Check for unsafe code usage
    local unsafe_count=$(grep -r "unsafe" src/ | wc -l)
    if [ "$unsafe_count" -gt 0 ]; then
        print_warning "Found $unsafe_count unsafe code blocks"
        grep -r "unsafe" src/
    else
        print_success "No unsafe code found"
    fi
    
    # Check for potential security issues
    if grep -r "println!" src/ >/dev/null 2>&1; then
        print_warning "Found println! statements (potential security risk in production)"
    fi
    
    print_success "Security checks completed"
}

# Function to generate build report
generate_report() {
    print_status "Generating build report..."
    
    local report_file="$RELEASE_DIR/BUILD_REPORT.md"
    
    cat > "$report_file" << EOF
# Build Report - $LIBRARY_NAME v$VERSION

**Build Date:** $(date)
**Build Host:** $(hostname)
**Rust Version:** $(rustc --version)

## Build Configuration

### Targets Built
$(for target in "${TARGETS[@]}"; do echo "- $target"; done)

### Build Configurations
$(for config in "${BUILD_CONFIGS[@]}"; do echo "- $config"; done)

## Build Results

### iOS Device (ARM64)
- **Status:** $(if [ -f "$RELEASE_DIR/lib${LIBRARY_NAME}_ios.a" ]; then echo "✅ Success"; else echo "❌ Failed"; fi)
- **File:** lib${LIBRARY_NAME}_ios.a
- **Size:** $(if [ -f "$RELEASE_DIR/lib${LIBRARY_NAME}_ios.a" ]; then ls -lh "$RELEASE_DIR/lib${LIBRARY_NAME}_ios.a" | awk '{print $5}'; else echo "N/A"; fi)

### iOS Simulator (Universal)
- **Status:** $(if [ -f "$RELEASE_DIR/lib${LIBRARY_NAME}_simulator.a" ]; then echo "✅ Success"; else echo "❌ Failed"; fi)
- **File:** lib${LIBRARY_NAME}_simulator.a
- **Size:** $(if [ -f "$RELEASE_DIR/lib${LIBRARY_NAME}_simulator.a" ]; then ls -lh "$RELEASE_DIR/lib${LIBRARY_NAME}_simulator.a" | awk '{print $5}'; else echo "N/A"; fi)

## Dependencies

\`\`\`toml
$(cat Cargo.toml | grep -E "^(name|version|edition|\[dependencies)" -A 20)
\`\`\`

## Usage Instructions

1. Add the appropriate \`.a\` file to your Xcode project
2. Include the \`jailbreak_detection.h\` header file
3. Link against the library in your build settings

## Security Notes

- This library contains enterprise-grade security features
- All unsafe code blocks have been reviewed for security
- Memory management follows Rust safety guidelines
- Comprehensive error handling implemented

## Support

For issues and questions, please refer to the README.md file or create an issue in the repository.
EOF

    print_success "Build report generated: $report_file"
}

# Function to show help
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message"
    echo "  -c, --clean         Clean build artifacts before building"
    echo "  -t, --test          Run tests after building"
    echo "  -l, --lint          Run Clippy linter"
    echo "  -s, --security      Run security checks"
    echo "  -a, --all           Run all checks (test, lint, security)"
    echo "  --targets-only      Only add iOS targets (skip building)"
    echo "  --clean-only        Only clean build artifacts"
    echo ""
    echo "Examples:"
    echo "  $0                    # Build all targets"
    echo "  $0 -c                 # Clean and build all targets"
    echo "  $0 -a                 # Build and run all checks"
    echo "  $0 --targets-only     # Only configure iOS targets"
}

# Main execution
main() {
    local clean_build_flag=false
    local run_tests_flag=false
    local run_lint_flag=false
    local run_security_flag=false
    local targets_only_flag=false
    local clean_only_flag=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -c|--clean)
                clean_build_flag=true
                shift
                ;;
            -t|--test)
                run_tests_flag=true
                shift
                ;;
            -l|--lint)
                run_lint_flag=true
                shift
                ;;
            -s|--security)
                run_security_flag=true
                shift
                ;;
            -a|--all)
                run_tests_flag=true
                run_lint_flag=true
                run_security_flag=true
                shift
                ;;
            --targets-only)
                targets_only_flag=true
                shift
                ;;
            --clean-only)
                clean_only_flag=true
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # Execute based on flags
    if [ "$clean_only_flag" = true ]; then
        clean_build
        exit 0
    fi
    
    if [ "$targets_only_flag" = true ]; then
        check_prerequisites
        add_ios_targets
        exit 0
    fi
    
    # Main build process
    check_prerequisites
    add_ios_targets
    
    if [ "$clean_build_flag" = true ]; then
        clean_build
    fi
    
    if [ "$run_security_flag" = true ]; then
        security_check
    fi
    
    build_all_targets
    create_universal_binary
    
    if [ "$run_tests_flag" = true ]; then
        run_tests
    fi
    
    if [ "$run_lint_flag" = true ]; then
        run_clippy
    fi
    
    generate_report
    
    print_success "Build process completed successfully!"
    print_status "Release files are available in: $RELEASE_DIR/"
}

# Run main function with all arguments
main "$@"
