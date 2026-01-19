#!/bin/bash
# Build script for creating various distribution packages
set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$PROJECT_DIR/build"
VERSION="1.0.0"

echo "🔨 Security Utilities Build Script"
echo "   📂 Project: $PROJECT_DIR"
echo "   📦 Version: $VERSION"
echo ""

# Create build directory
mkdir -p "$BUILD_DIR"

show_help() {
    echo "Usage: $0 [OPTIONS] [TARGETS]"
    echo ""
    echo "Available targets:"
    echo "  docker     - Build Docker image and create launcher script"
    echo "  native     - Create native installation script"
    echo "  flatpak    - Prepare Flatpak manifest and files"
    echo "  snap       - Prepare Snap package files"
    echo "  appimage   - Create AppImage (requires appimage-builder)"
    echo "  all        - Build all targets"
    echo ""
    echo "Options:"
    echo "  -h, --help     Show this help message"
    echo "  -c, --clean    Clean build directory before building"
    echo "  -v, --version  Show version and exit"
    echo ""
}

clean_build() {
    echo "🧹 Cleaning build directory..."
    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR"
}

build_docker() {
    echo "🐳 Building Docker image..."
    docker build -t security-utils:$VERSION .
    docker tag security-utils:$VERSION security-utils:latest
    
    echo "📋 Creating Docker launcher script..."
    cp run-security-utils.sh "$BUILD_DIR/"
    chmod +x "$BUILD_DIR/run-security-utils.sh"
    
    echo "✅ Docker build complete"
    echo "   🚀 Run with: ./build/run-security-utils.sh"
}

build_native() {
    echo "💻 Preparing native installation..."
    cp install-native.sh "$BUILD_DIR/"
    chmod +x "$BUILD_DIR/install-native.sh"
    
    echo "✅ Native installer ready"
    echo "   🚀 Install with: ./build/install-native.sh"
}

build_flatpak() {
    echo "📦 Preparing Flatpak package..."
    FLATPAK_DIR="$BUILD_DIR/flatpak"
    mkdir -p "$FLATPAK_DIR"
    
    # Copy manifest and support files
    cp dev.secutils.SecurityUtils.json "$FLATPAK_DIR/"
    cp flatpak-wrapper.sh "$FLATPAK_DIR/"
    cp dev.secutils.SecurityUtils.desktop "$FLATPAK_DIR/"
    cp dev.secutils.SecurityUtils.svg "$FLATPAK_DIR/"
    cp dev.secutils.SecurityUtils.appdata.xml "$FLATPAK_DIR/"
    
    # Copy application files
    cp -r *.php css js password_hash_gen_doc.html README.md "$FLATPAK_DIR/"
    
    # Make wrapper executable
    chmod +x "$FLATPAK_DIR/flatpak-wrapper.sh"
    
    # Create build instructions
    cat > "$FLATPAK_DIR/BUILD.md" << 'EOF'
# Building Flatpak Package

## Prerequisites
```bash
# Install flatpak-builder
sudo apt install flatpak-builder

# Add Flathub repository
flatpak remote-add --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo
```

## Build
```bash
# Build the application
flatpak-builder build-dir dev.secutils.SecurityUtils.json --force-clean

# Install locally
flatpak-builder --user --install --force-clean build-dir dev.secutils.SecurityUtils.json

# Run the application
flatpak run dev.secutils.SecurityUtils
```

## Create Bundle
```bash
# Create a .flatpak bundle
flatpak build-bundle ~/.local/share/flatpak/repo security-utils.flatpak dev.secutils.SecurityUtils
```
EOF
    
    echo "✅ Flatpak package ready"
    echo "   📁 Files: ./build/flatpak/"
    echo "   📖 Instructions: ./build/flatpak/BUILD.md"
}

build_snap() {
    echo "📦 Preparing Snap package..."
    SNAP_DIR="$BUILD_DIR/snap"
    mkdir -p "$SNAP_DIR"
    
    # Copy snap configuration
    cp -r snap "$SNAP_DIR/"
    
    # Copy application files to snap directory
    cp -r *.php css js password_hash_gen_doc.html README.md "$SNAP_DIR/"
    
    # Create build instructions
    cat > "$SNAP_DIR/BUILD.md" << 'EOF'
# Building Snap Package

## Prerequisites
```bash
# Install snapcraft
sudo apt install snapcraft

# Or via snap
sudo snap install snapcraft --classic
```

## Build
```bash
# Build the snap
snapcraft

# Install locally
sudo snap install --dangerous security-utils_1.0.0_amd64.snap

# Run the application
snap run security-utils
```

## Publish
```bash
# Upload to Snap Store (requires account)
snapcraft upload security-utils_1.0.0_amd64.snap
snapcraft release security-utils 1 stable
```
EOF
    
    echo "✅ Snap package ready"
    echo "   📁 Files: ./build/snap/"
    echo "   📖 Instructions: ./build/snap/BUILD.md"
}

build_appimage() {
    echo "📦 Creating AppImage..."
    
    if ! command -v appimage-builder &> /dev/null; then
        echo "❌ appimage-builder not found. Install with:"
        echo "   pip3 install appimage-builder"
        echo "   Or see: https://appimage-builder.readthedocs.io/"
        return 1
    fi
    
    APPIMAGE_DIR="$BUILD_DIR/appimage"
    mkdir -p "$APPIMAGE_DIR"
    
    # Create AppDir structure
    mkdir -p "$APPIMAGE_DIR/AppDir/usr/bin"
    mkdir -p "$APPIMAGE_DIR/AppDir/usr/share/security-utils"
    mkdir -p "$APPIMAGE_DIR/AppDir/usr/share/applications"
    mkdir -p "$APPIMAGE_DIR/AppDir/usr/share/icons/hicolor/scalable/apps"
    
    # Copy application files
    cp -r *.php css js password_hash_gen_doc.html README.md "$APPIMAGE_DIR/AppDir/usr/share/security-utils/"
    cp dev.secutils.SecurityUtils.desktop "$APPIMAGE_DIR/AppDir/usr/share/applications/"
    cp dev.secutils.SecurityUtils.svg "$APPIMAGE_DIR/AppDir/usr/share/icons/hicolor/scalable/apps/"
    
    # Create launcher script
    cat > "$APPIMAGE_DIR/AppDir/usr/bin/security-utils" << 'EOF'
#!/bin/bash
APPDIR="$(dirname "$(dirname "$(readlink -f "$0")")")"
cd "$APPDIR/usr/share/security-utils"
php -S localhost:8070 &
sleep 2
xdg-open "http://localhost:8070" 2>/dev/null &
wait
EOF
    chmod +x "$APPIMAGE_DIR/AppDir/usr/bin/security-utils"
    
    # Create AppImage recipe
    cat > "$APPIMAGE_DIR/AppImageBuilder.yml" << 'EOF'
version: 1
script:
  - rm -rf AppDir || true
  - mkdir -p AppDir/usr/share/security-utils
  - cp -r *.php css js password_hash_gen_doc.html README.md AppDir/usr/share/security-utils/

AppDir:
  path: ./AppDir
  
  app_info:
    id: dev.secutils.SecurityUtils
    name: Security Utilities
    icon: dev.secutils.SecurityUtils
    version: 1.0.0
    exec: usr/bin/security-utils
    exec_args: $@

  apt:
    arch: amd64
    sources:
      - sourceline: 'deb [arch=amd64] http://archive.ubuntu.com/ubuntu/ focal main restricted universe multiverse'
        key_url: 'http://keyserver.ubuntu.com/pks/lookup?op=get&search=0x3B4FE6ACC0B21F32'
    
    include:
      - php
      - php-gd
      - php-cli

  files:
    exclude:
      - usr/share/man
      - usr/share/doc/*/README.*
      - usr/share/doc/*/changelog.*
      - usr/share/doc/*/NEWS.*
      - usr/share/doc/*/TODO.*

AppImage:
  update-information: null
  sign-key: null
  arch: x86_64
EOF
    
    cd "$APPIMAGE_DIR"
    appimage-builder --skip-tests
    
    if [ -f "Security Utilities-1.0.0-x86_64.AppImage" ]; then
        mv "Security Utilities-1.0.0-x86_64.AppImage" "../security-utils-1.0.0-x86_64.AppImage"
        echo "✅ AppImage created: ./build/security-utils-1.0.0-x86_64.AppImage"
    else
        echo "❌ AppImage build failed"
        return 1
    fi
    
    cd "$PROJECT_DIR"
}

# Parse command line arguments
TARGETS=()
CLEAN=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -v|--version)
            echo "Security Utilities Build Script v$VERSION"
            exit 0
            ;;
        -c|--clean)
            CLEAN=true
            shift
            ;;
        docker|native|flatpak|snap|appimage|all)
            TARGETS+=("$1")
            shift
            ;;
        *)
            echo "❌ Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Default to all if no targets specified
if [ ${#TARGETS[@]} -eq 0 ]; then
    TARGETS=("all")
fi

# Clean if requested
if [ "$CLEAN" = true ]; then
    clean_build
fi

# Build targets
for target in "${TARGETS[@]}"; do
    echo "🎯 Building target: $target"
    
    case $target in
        docker)
            build_docker
            ;;
        native)
            build_native
            ;;
        flatpak)
            build_flatpak
            ;;
        snap)
            build_snap
            ;;
        appimage)
            build_appimage
            ;;
        all)
            build_docker
            build_native
            build_flatpak
            build_snap
            echo ""
            echo "ℹ️  AppImage requires appimage-builder. Run './build.sh appimage' if available."
            ;;
        *)
            echo "❌ Unknown target: $target"
            exit 1
            ;;
    esac
    
    echo ""
done

echo "🎉 Build completed successfully!"
echo ""
echo "📋 Available distributions:"
echo "   🐳 Docker: ./build/run-security-utils.sh"
echo "   💻 Native: ./build/install-native.sh" 
echo "   📦 Flatpak: ./build/flatpak/"
echo "   📦 Snap: ./build/snap/"
if [ -f "$BUILD_DIR/security-utils-1.0.0-x86_64.AppImage" ]; then
    echo "   📱 AppImage: ./build/security-utils-1.0.0-x86_64.AppImage"
fi
echo ""