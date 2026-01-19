#!/bin/bash
# Security Utilities Launcher
CONTAINER_NAME="sec-utils-app"
PORT=${1:-8070}

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    echo "   Ubuntu/Debian: sudo apt install docker.io"
    echo "   Fedora/RHEL: sudo dnf install docker"
    echo "   Arch: sudo pacman -S docker"
    exit 1
fi

# Check if Docker daemon is running
if ! docker info >/dev/null 2>&1; then
    echo "❌ Docker daemon is not running."
    echo "   Start it with: sudo systemctl start docker"
    echo "   Enable at boot: sudo systemctl enable docker"
    exit 1
fi

# Check if container is running
if docker ps --format "table {{.Names}}" | grep -q "$CONTAINER_NAME"; then
    echo "✅ Security Utilities is already running at http://localhost:$PORT"
    echo "   To restart: docker restart $CONTAINER_NAME"
    echo "   To stop: docker stop $CONTAINER_NAME && docker rm $CONTAINER_NAME"
    
    # Try to open browser
    if command -v xdg-open &> /dev/null; then
        xdg-open "http://localhost:$PORT" 2>/dev/null &
    fi
    exit 0
fi

# Stop and remove existing stopped container if it exists
if docker ps -a --format "table {{.Names}}" | grep -q "$CONTAINER_NAME"; then
    echo "🔄 Removing existing container..."
    docker rm "$CONTAINER_NAME" >/dev/null 2>&1
fi

echo "🚀 Starting Security Utilities..."

# Build the Docker image
if ! docker build -t sec-utils . >/dev/null 2>&1; then
    echo "❌ Failed to build Docker image. Make sure you're in the correct directory."
    exit 1
fi

# Run the container
if docker run -d --name "$CONTAINER_NAME" -p "$PORT:80" -v "$(pwd):/var/www/html" sec-utils >/dev/null 2>&1; then
    echo "✅ Security Utilities started successfully!"
    echo "   🌐 Dashboard: http://localhost:$PORT"
    echo "   🔐 Password Hash Generator: http://localhost:$PORT/password_hash_gen.php"
    echo "   🖼️  Image Randomizer: http://localhost:$PORT/image-randomizer.php"
    echo ""
    echo "📋 Management Commands:"
    echo "   Stop: docker stop $CONTAINER_NAME"
    echo "   Restart: docker restart $CONTAINER_NAME"
    echo "   View logs: docker logs $CONTAINER_NAME"
    echo "   Remove: docker stop $CONTAINER_NAME && docker rm $CONTAINER_NAME"
    
    # Try to open browser automatically
    sleep 2
    if command -v xdg-open &> /dev/null; then
        xdg-open "http://localhost:$PORT" 2>/dev/null &
    elif command -v open &> /dev/null; then
        open "http://localhost:$PORT" 2>/dev/null &
    fi
else
    echo "❌ Failed to start container. Port $PORT might be in use."
    echo "   Try a different port: $0 8080"
    exit 1
fi