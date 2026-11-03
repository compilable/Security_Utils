#!/bin/bash
# Build script for creating various distribution packages
set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$PROJECT_DIR/build"
VERSION="3.0.0"

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
    echo "  release    - Create reproducible source archive and SHA-256 checksum"
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
    cp -r *.php css js password_hash_gen_doc.html README.md THIRD_PARTY_ASSETS.md THIRD_PARTY_ASSETS.sha256 RECOVERY_RELEASE_CHECKLIST.md "$FLATPAK_DIR/"
    
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
    cp -r *.php css js password_hash_gen_doc.html README.md THIRD_PARTY_ASSETS.md THIRD_PARTY_ASSETS.sha256 RECOVERY_RELEASE_CHECKLIST.md "$SNAP_DIR/"
    
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
sudo snap install --dangerous security-utils_3.0.0_amd64.snap

# Run the application
snap run security-utils
```

## Publish
```bash
# Upload to Snap Store (requires account)
snapcraft upload security-utils_3.0.0_amd64.snap
snapcraft release security-utils 1 stable
```
EOF
    
    echo "✅ Snap package ready"
    echo "   📁 Files: ./build/snap/"
    echo "   📖 Instructions: ./build/snap/BUILD.md"
}

build_release() {
    local release_dir="$BUILD_DIR/release"
    local archive="$release_dir/security-utils-$VERSION.tar.gz"
    mkdir -p "$release_dir"
    tar --sort=name --mtime="@${SOURCE_DATE_EPOCH:-0}" --owner=0 --group=0 --numeric-owner \
        --exclude='./.git' --exclude='./build' --exclude='./security_utils_developer_recommendations.md' \
        -cf - . | gzip -n > "$archive"
    (cd "$release_dir" && sha256sum "$(basename "$archive")" > "$(basename "$archive").sha256")
    echo "✅ Release archive: $archive"
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
        docker|native|flatpak|snap|release|all)
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
        release)
            build_release
            ;;
        all)
            build_docker
            build_native
            build_flatpak
            build_snap
            build_release
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
echo ""
