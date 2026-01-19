#!/bin/bash
# Native Installation Script for Security Utilities
set -e

INSTALL_DIR="$HOME/.local/share/security-utils"
DESKTOP_DIR="$HOME/.local/share/applications"
BIN_DIR="$HOME/.local/bin"

echo "🔧 Installing Security Utilities natively..."

# Detect package manager and install PHP if needed
install_php() {
    if command -v apt-get &> /dev/null; then
        echo "📦 Installing PHP via apt..."
        sudo apt-get update && sudo apt-get install -y php php-gd php-cli php-finfo
    elif command -v dnf &> /dev/null; then
        echo "📦 Installing PHP via dnf..."
        sudo dnf install -y php php-gd php-cli
    elif command -v pacman &> /dev/null; then
        echo "📦 Installing PHP via pacman..."
        sudo pacman -S php php-gd
    elif command -v zypper &> /dev/null; then
        echo "📦 Installing PHP via zypper..."
        sudo zypper install php php-gd
    else
        echo "❌ Unable to detect package manager. Please install PHP manually:"
        echo "   php, php-gd, php-cli packages are required"
        exit 1
    fi
}

# Check PHP installation
if ! command -v php &> /dev/null; then
    echo "⚠️  PHP not found. Installing..."
    install_php
else
    echo "✅ PHP found: $(php --version | head -n1)"
fi

# Check required PHP extensions
check_extension() {
    if ! php -m | grep -q "$1"; then
        echo "❌ PHP extension '$1' is missing"
        return 1
    fi
    return 0
}

echo "🔍 Checking PHP extensions..."
MISSING_EXTENSIONS=0

for ext in gd fileinfo; do
    if ! check_extension "$ext"; then
        MISSING_EXTENSIONS=1
    fi
done

if [ $MISSING_EXTENSIONS -eq 1 ]; then
    echo "⚠️  Some extensions are missing. Attempting to install..."
    install_php
fi

# Create installation directories
echo "📁 Creating directories..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$DESKTOP_DIR"
mkdir -p "$BIN_DIR"

# Copy application files
echo "📋 Copying application files..."
cp -r ./*.php "$INSTALL_DIR/"
cp -r ./css "$INSTALL_DIR/" 2>/dev/null || true
cp -r ./js "$INSTALL_DIR/" 2>/dev/null || true
cp ./README.md "$INSTALL_DIR/" 2>/dev/null || true
cp ./docker-compose.yml "$INSTALL_DIR/" 2>/dev/null || true
cp ./Dockerfile "$INSTALL_DIR/" 2>/dev/null || true

# Create launcher script
echo "🚀 Creating launcher script..."
cat > "$INSTALL_DIR/launch.sh" << 'EOF'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PORT=${1:-8070}

# Check if already running
if lsof -Pi :$PORT -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo "⚠️  Port $PORT is already in use"
    echo "   Try a different port: $0 8080"
    exit 1
fi

echo "🚀 Starting Security Utilities on port $PORT..."
echo "   🌐 Dashboard: http://localhost:$PORT"
echo "   🔐 Password Hash Generator: http://localhost:$PORT/password_hash_gen.php"
echo "   🖼️  Image Randomizer: http://localhost:$PORT/image-randomizer.php"
echo ""
echo "Press Ctrl+C to stop the server..."

# Create temp directory for image processing
mkdir -p temp

# Start PHP built-in server
php -S localhost:$PORT &
PHP_PID=$!

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "🛑 Stopping Security Utilities..."
    kill $PHP_PID 2>/dev/null || true
    exit 0
}

# Set up signal handlers
trap cleanup SIGINT SIGTERM

# Try to open browser
sleep 2
if command -v xdg-open &> /dev/null; then
    xdg-open "http://localhost:$PORT" 2>/dev/null &
elif command -v open &> /dev/null; then
    open "http://localhost:$PORT" 2>/dev/null &
fi

# Wait for PHP server to exit
wait $PHP_PID
EOF

chmod +x "$INSTALL_DIR/launch.sh"

# Create command-line launcher
cat > "$BIN_DIR/security-utils" << EOF
#!/bin/bash
exec "$INSTALL_DIR/launch.sh" "\$@"
EOF

chmod +x "$BIN_DIR/security-utils"

# Create desktop entry
echo "🖥️  Creating desktop entry..."
cat > "$DESKTOP_DIR/security-utils.desktop" << EOF
[Desktop Entry]
Name=Security Utilities
Comment=Web-based security tools for developers and security professionals
Exec=$INSTALL_DIR/launch.sh
Icon=applications-security
Terminal=false
Type=Application
Categories=Development;Security;Network;
StartupNotify=true
Keywords=security;password;hash;encryption;image;randomizer;
EOF

# Update desktop database if available
if command -v update-desktop-database &> /dev/null; then
    update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true
fi

# Create uninstaller
cat > "$INSTALL_DIR/uninstall.sh" << EOF
#!/bin/bash
echo "🗑️  Uninstalling Security Utilities..."
rm -rf "$INSTALL_DIR"
rm -f "$DESKTOP_DIR/security-utils.desktop"
rm -f "$BIN_DIR/security-utils"
if command -v update-desktop-database &> /dev/null; then
    update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true
fi
echo "✅ Security Utilities uninstalled successfully!"
EOF

chmod +x "$INSTALL_DIR/uninstall.sh"

echo ""
echo "✅ Installation completed successfully!"
echo ""
echo "📋 How to use:"
echo "   • From applications menu: Look for 'Security Utilities'"
echo "   • From terminal: security-utils"
echo "   • Directly: $INSTALL_DIR/launch.sh"
echo ""
echo "🔧 Management:"
echo "   • Uninstall: $INSTALL_DIR/uninstall.sh"
echo "   • Location: $INSTALL_DIR"
echo ""

# Ask if user wants to launch now
read -p "🚀 Launch Security Utilities now? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    exec "$INSTALL_DIR/launch.sh"
fi