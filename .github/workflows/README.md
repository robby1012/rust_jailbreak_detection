# GitHub Workflows

This directory contains GitHub Actions workflows for automated building and releasing of the iOS jailbreak detection library.

## Workflows

### 1. Release Build (`release.yml`)

**Triggered by:**
- Creating a tag that starts with `v` (e.g., `v1.0.0`, `v2.1.0`)
- Manual workflow dispatch with version input

**What it does:**
- Builds the library for all iOS targets (device and simulator)
- Creates both debug and release versions
- Generates universal binaries for iOS simulator
- Creates downloadable zip packages
- Automatically creates a GitHub release with artifacts
- Runs tests and linting

**Artifacts created:**
- `jailbreak_detection-release.zip` - Optimized release binaries
- `jailbreak_detection-debug.zip` - Debug binaries with symbols
- `jailbreak_detection-combined.zip` - Both release and debug binaries

### 2. Development Build (`development.yml`)

**Triggered by:**
- Push to `main` or `development` branches
- Pull requests to `main` or `development` branches

**What it does:**
- Runs tests and code quality checks on every PR
- Builds development packages when code is pushed to `development` branch
- Creates development artifacts for testing

**Artifacts created (on development branch only):**
- `jailbreak_detection-dev-release.zip` - Development release build
- `jailbreak_detection-dev-debug.zip` - Development debug build

## Usage

### Creating a Release

1. **Tag-based Release** (Recommended):
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```

2. **Manual Release**:
   - Go to Actions → Release Build → Run workflow
   - Enter the version (e.g., `v1.0.0`)
   - Click "Run workflow"

### Downloading Binaries

#### For Users:
1. Go to the [Releases](../../releases) page
2. Download the appropriate zip file:
   - **Release zip**: For production use (optimized)
   - **Debug zip**: For development/debugging
   - **Combined zip**: Contains both versions

#### For Developers:
1. Go to the [Actions](../../actions) tab
2. Click on a completed workflow run
3. Download artifacts from the "Artifacts" section

## Package Contents

Each zip file contains:

```
├── libjailbreak_detection_ios.a          # iOS device library
├── libjailbreak_detection_simulator.a    # iOS simulator universal library
├── jailbreak_detection.h                 # C header file
├── Examples/                             # Integration examples
│   ├── SwiftIntegration.swift
│   ├── App-Bridging-Header.h
│   └── Xcode Settings *.png
├── VERSION                               # Build information
└── BUILD_REPORT.md                       # Detailed build report
```

## Integration Guide

1. **Extract the downloaded zip file**

2. **Add libraries to your Xcode project:**
   - For iOS devices: `libjailbreak_detection_ios.a`
   - For iOS simulator: `libjailbreak_detection_simulator.a`

3. **Include the header file:**
   ```c
   #include "jailbreak_detection.h"
   ```

4. **Configure Xcode settings:**
   - See example screenshots in `Examples/` directory
   - Add library search paths
   - Configure build settings as shown

5. **Swift Integration:**
   - Check `Examples/SwiftIntegration.swift` for usage examples
   - Add bridging header as shown in `Examples/App-Bridging-Header.h`

## Build Targets

The workflows build for the following iOS targets:

- **aarch64-apple-ios** - iOS devices (iPhone/iPad with ARM64)
- **aarch64-apple-ios-sim** - iOS simulator on Apple Silicon Macs
- **x86_64-apple-ios** - iOS simulator on Intel Macs

The simulator libraries are automatically combined into universal binaries supporting both Intel and Apple Silicon Macs.

## Requirements

- **Rust**: Latest stable version
- **iOS targets**: Automatically installed by the workflow
- **macOS runner**: Required for iOS compilation

## Troubleshooting

### Common Issues:

1. **Build failures:**
   - Check the Actions tab for detailed logs
   - Ensure all dependencies are properly specified in `Cargo.toml`

2. **Missing artifacts:**
   - Artifacts are automatically cleaned up after the retention period
   - For releases, artifacts are permanently available in the Releases section

3. **Integration issues:**
   - Check the `Examples/` directory for proper integration
   - Ensure correct Xcode build settings

### Getting Help:

1. Check the build logs in the Actions tab
2. Review the `BUILD_REPORT.md` included in each package
3. Create an issue if you encounter problems

## Workflow Customization

To modify the workflows:

1. **Change build targets**: Edit the `matrix.target` section
2. **Add new build types**: Modify the `strategy.matrix` configuration
3. **Change retention periods**: Update `retention-days` values
4. **Modify package contents**: Edit the packaging steps

## Security Notes

- Workflows only run on the main repository (not forks)
- Release creation requires push access to the repository
- Artifacts are available to repository collaborators
- No secrets are exposed in the build process
