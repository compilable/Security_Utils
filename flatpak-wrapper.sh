#!/bin/bash
# Flatpak wrapper script for Security Utilities
set -e

APP_DIR="/app/share/security-utils"
RUNTIME_DIR="$XDG_RUNTIME_DIR/security-utils"

# Create runtime directory
mkdir -p "$RUNTIME_DIR"

# Set working directory
cd "$APP_DIR"

# Find available port
PORT=8070
while lsof -Pi :$PORT -sTCP:LISTEN -t >/dev/null 2>&1; do
    PORT=$((PORT + 1))
done

echo "🚀 Starting Security Utilities on port $PORT..."
echo "   🌐 Dashboard: http://localhost:$PORT"
echo "   🔐 Password Hash Generator: http://localhost:$PORT/password_hash_gen.php"
echo "   🖼️  Image Randomizer: http://localhost:$PORT/image-randomizer.php"
echo ""
echo "Press Ctrl+C to stop the server..."

# Create temp directory for image processing
mkdir -p "$RUNTIME_DIR/temp"

# Start PHP built-in server
php -S localhost:$PORT -t "$APP_DIR" &
PHP_PID=$!

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "🛑 Stopping Security Utilities..."
    kill $PHP_PID 2>/dev/null || true
    rm -rf "$RUNTIME_DIR"
    exit 0
}

# Set up signal handlers
trap cleanup SIGINT SIGTERM

# Try to open browser after delay
sleep 2
if command -v xdg-open &> /dev/null; then
    xdg-open "http://localhost:$PORT" 2>/dev/null &
fi

# Wait for PHP server to exit
wait $PHP_PID