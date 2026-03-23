# Security Utilities

A collection of web-based security tools designed for developers and everyday users.

## 🛠️ Tools Included

### 1. Password Hash Generator v2.0.1
- **URL**: `http://localhost:8070/password_hash_gen.php`
- **Features**:
  - Generate secure password hashes using various algorithms
  - Verify passwords against existing hashes
  - Support for multiple hashing algorithms (bcrypt, SHA, MD5, etc.)
  - Dark/Light theme support
  - Secure headers and CSP implementation

### 2. Image Randomizer
- **URL**: `http://localhost:8070/image-randomizer.php`
- **Features**:
  - Randomize image file data to avoid forensic detection
  - Support for JPEG, PNG, GIF, and WebP formats
  - Configurable randomization cycles
  - Multiple hash algorithms (MD5, SHA256, SHA512)
  - File integrity verification
  - Secure file upload handling

## � Deployment Options

Security Utilities supports multiple deployment methods to suit different environments and preferences:

| Method | Best For | Requirements | Installation Time |
|--------|----------|--------------|------------------|
| **Docker Launcher** | Quick testing, development | Docker | ~30 seconds |
| **Native Install** | Daily use, performance | PHP 8.2+ | ~2 minutes |
| **Flatpak** | Sandboxed, universal | Flatpak runtime | ~5 minutes |
| **Snap** | Ubuntu/derivatives | snapd | ~3 minutes |
| **AppImage** | Portable, no install | None | ~10 minutes |

## �🐳 Getting Started with Docker

### Prerequisites
- Docker
- Docker Compose (optional - included in Docker Desktop)

### Quick Start Options

#### Option 1: Docker Launcher Script (Recommended)

The easiest way to get started is using our automated launcher script:

1. **Clone or download the project**
   ```bash
   git clone https://github.com/compilable/Security_Utils.git
   cd Security_Utils
   ```

2. **Run the launcher script**
   ```bash
   ./run-security-utils.sh
   ```

The launcher script will:
- ✅ Check Docker installation and guide you if missing
- 🔄 Automatically build/pull the Docker image
- 🚀 Start the container with proper port management
- 🌐 Open your browser automatically to the dashboard
- 🛡️ Handle port conflicts and container cleanup
- ⏹️ Provide easy stop/restart options

#### Option 2: Manual Docker Compose

If you prefer manual control:

1. **Clone or download the project**
   ```bash
   git clone https://github.com/compilable/Security_Utils.git
   cd Security_Utils
   ```

2. **Start the application**
   ```bash
   docker-compose up -d
   ```

3. **Access the tools**
   - Dashboard: http://localhost:8070/
   - Password Hash Generator: http://localhost:8070/password_hash_gen.php
   - Image Randomizer: http://localhost:8070/image-randomizer.php

4. **Stop the application**
   ```bash
   docker-compose down
   ```

## 💻 Native Installation

### Prerequisites
- PHP 8.4.18 or higher
- PHP GD extension
- Web browser

### Quick Install

```bash
# Run the installation script
./install-native.sh

# Launch from applications menu or command line
security-utils
```

### Features
- **Auto-dependency detection**: Installs PHP on Ubuntu, Fedora, Arch, openSUSE
- **Desktop integration**: Adds application menu entry and launcher
- **System integration**: Creates command-line utility
- **Clean uninstall**: Includes removal script
- **Multiple distributions**: Supports major Linux package managers

### Manual Installation

If you prefer manual setup:

```bash
# Install PHP (Ubuntu/Debian)
sudo apt install php php-gd php-cli

# Install PHP (Fedora/RHEL)
sudo dnf install php php-gd php-cli

# Install PHP (Arch Linux)
sudo pacman -S php php-gd

# Run the application
php -S localhost:8070
```

### Docker Configuration

The application runs on **port 8070** by default. You can modify this in the `docker-compose.yml` file:

```yaml
ports:
  - "8070:80"  # Change 8070 to your desired port
```

### Container Details

- **Base Image**: PHP 8.2 with Apache
- **Container Name**: password-hash-generator
- **Features**:
  - GD extension for image processing
  - Apache mod_rewrite enabled
  - Secure file permissions
  - Volume mounting for development

### Docker Launcher Script Features

The `run-security-utils.sh` script provides advanced container management:

- **Smart Dependency Checking**: Automatically detects and guides Docker installation
- **Port Management**: Finds available ports if 8070 is busy
- **Container Lifecycle**: Handles building, starting, stopping, and cleanup
- **Browser Integration**: Automatically opens the dashboard in your default browser
- **Error Handling**: Provides clear error messages and troubleshooting guidance
- **Cross-Platform**: Works on Linux, macOS, and Windows (with WSL/Git Bash)

**Script Usage:**
```bash
# Basic start
./run-security-utils.sh

# Use custom port  
./run-security-utils.sh --port 8080

# Stop all containers
./run-security-utils.sh --stop

# Clean restart
./run-security-utils.sh --restart

# Show help
./run-security-utils.sh --help
```

## 🏗️ Build System

### Universal Build Script

The `build.sh` script creates packages for all supported formats:

```bash
# Build all formats
./build.sh all

# Build specific formats
./build.sh docker native flatpak

# Clean build and rebuild
./build.sh --clean all

# Show available options
./build.sh --help
```

### Supported Package Formats

#### Flatpak Package
```bash
# Build Flatpak package
./build.sh flatpak

# Manual build (requires flatpak-builder)
cd build/flatpak
flatpak-builder build-dir dev.secutils.SecurityUtils.json --force-clean
flatpak-builder --user --install --force-clean build-dir dev.secutils.SecurityUtils.json
```

#### Snap Package
```bash
# Build Snap package
./build.sh snap

# Manual build (requires snapcraft)
cd build/snap
snapcraft
sudo snap install --dangerous security-utils_1.0.0_amd64.snap
```

#### AppImage (Portable)
```bash
# Build AppImage (requires appimage-builder)
./build.sh appimage

# Run the portable application
./build/security-utils-1.0.0-x86_64.AppImage
```

### Distribution Files

After building, you'll find:

```
build/
├── run-security-utils.sh           # Docker launcher
├── install-native.sh               # Native installer
├── security-utils-1.0.0-x86_64.AppImage  # Portable app
├── flatpak/                        # Flatpak package files
│   ├── dev.secutils.SecurityUtils.json
│   └── BUILD.md                    # Build instructions
└── snap/                           # Snap package files
    ├── snapcraft.yaml
    └── BUILD.md                    # Build instructions
```

## 🔧 Development

### Local Development Setup

The application uses volume mounting, so changes to your local files will be reflected immediately in the container.

### File Structure
```
sec_utils/
├── index.php                              # Dashboard/Landing page
├── password_hash_gen.php                  # Password Hash Generator
├── image-randomizer.php                   # Image Randomizer tool
├── css/                                   # Stylesheet files
│   └── dashboard.css                     # Dashboard styles
├── js/                                    # JavaScript files  
│   └── dashboard.js                      # Dashboard interactions
├── password_hash_gen_doc.html             # Documentation
├── docker-compose.yml                     # Docker Compose configuration
├── Dockerfile                            # Docker image configuration
├── run-security-utils.sh                 # Docker launcher script
├── install-native.sh                     # Native installation script
├── build.sh                              # Multi-format build script
├── dev.secutils.SecurityUtils.json       # Flatpak manifest
├── flatpak-wrapper.sh                    # Flatpak execution wrapper
├── dev.secutils.SecurityUtils.desktop    # Desktop entry file
├── dev.secutils.SecurityUtils.svg        # Application icon
├── dev.secutils.SecurityUtils.appdata.xml # App metadata
├── snap/                                  # Snap package files
│   ├── snapcraft.yaml                   # Snap configuration
│   └── security-utils-wrapper           # Snap execution wrapper
├── build/                                 # Generated packages (after build)
│   ├── run-security-utils.sh            # Docker launcher copy
│   ├── install-native.sh                # Native installer copy
│   ├── security-utils-1.0.0-x86_64.AppImage # Portable application
│   ├── flatpak/                         # Flatpak build files
│   └── snap/                            # Snap build files
└── README.md                             # This file
```

### Building the Image

To build the Docker image locally:

```bash
docker build -t sec-utils .
```

### Customization

- **Upload Directory**: Images are processed in the system temp directory
- **File Size Limits**: Maximum 10MB per file, up to 10 files
- **Security Headers**: Comprehensive CSP and security headers implemented
- **Supported Formats**: JPEG, PNG, GIF, WebP

## 🔒 Security Features

- Content Security Policy (CSP) headers
- X-Frame-Options: DENY
- X-XSS-Protection enabled
- No-sniff content type protection
- Strict referrer policy
- Secure file upload validation
- Input sanitization and validation

## 📋 Requirements

- Docker Engine 20.0+
- Docker Compose 2.0+
- Web browser with JavaScript enabled

## 🚀 Production Deployment

### Deployment Method Selection

**For Production Servers:**
- **Docker**: Best for containerized environments, easy scaling
- **Native**: Best performance, direct system integration
- **Snap**: Good for Ubuntu-based production systems

**For End-User Distribution:**
- **Flatpak**: Universal Linux distribution, sandboxed security
- **Snap**: Ubuntu Store distribution, automatic updates
- **AppImage**: Portable, no installation required

### Production Checklist

For any production deployment:

1. **Update security headers** for your domain
2. **Configure HTTPS** with proper SSL certificates
3. **Set up proper logging** and monitoring
4. **Review file upload limits** based on your needs
5. **Consider firewall rules** for the exposed port
6. **Test all deployment formats** in your target environment
7. **Set up backup procedures** for user data and configurations

### Environment Variables

You can customize the deployment using environment variables:

```yaml
environment:
  - APACHE_DOCUMENT_ROOT=/var/www/html
  - PHP_MEMORY_LIMIT=256M
  - PHP_MAX_UPLOAD_SIZE=10M
```

## 📝 License

This project is released under an open-source license. See individual tool headers for specific licensing information.

## 🙏 Third-Party Acknowledgments

This project makes use of several excellent third-party libraries and frameworks:

### Frontend Libraries & Frameworks
- **[Bootstrap 5.3.0](https://getbootstrap.com/)** - Modern CSS framework for responsive design
  - License: MIT
  - Used for: UI components, responsive layout, and styling
  
- **[Bootstrap Icons 1.7.2](https://icons.getbootstrap.com/)** - Official icon library for Bootstrap
  - License: MIT  
  - Used for: UI icons throughout the application

### Cryptographic Libraries (Password Hash Generator)
- **[CryptoJS 4.1.1](https://cryptojs.gitbook.io/docs/)** - JavaScript cryptographic library
  - License: MIT
  - Used for: MD5, SHA-1, SHA-256, SHA-512, and other hash implementations
  
- **[bcryptjs 2.4.3](https://github.com/dcodeIO/bcrypt.js)** - JavaScript bcrypt implementation
  - License: MIT
  - Used for: bcrypt password hashing and verification
  
- **[scrypt-js 3.0.1](https://github.com/ricmoo/scrypt-js)** - Pure JavaScript scrypt implementation  
  - License: MIT
  - Used for: scrypt key derivation function
  
- **[argon2-browser 1.18.0](https://github.com/antelle/argon2-browser)** - WebAssembly Argon2 implementation
  - License: MIT
  - Used for: Argon2 password hashing (latest security standard)

### Content Delivery Networks
- **[jsDelivr](https://www.jsdelivr.com/)** - Free CDN for open source projects
  - Used for: Serving Bootstrap, Bootstrap Icons, bcryptjs, and scrypt-js
  
- **[Cloudflare CDN (cdnjs)](https://cdnjs.com/)** - Free CDN service
  - Used for: Serving CryptoJS library
  
- **[unpkg](https://unpkg.com/)** - Fast, global CDN for npm packages  
  - Used for: Serving argon2-browser library

### Server Environment
- **[PHP 8.2](https://www.php.net/)** - Server-side scripting language
  - License: PHP License v3.01
  - Used for: Backend processing and server-side operations
  
- **[Apache HTTP Server](https://httpd.apache.org/)** - Web server software
  - License: Apache License 2.0
  - Used for: Web server functionality
  
- **[Docker](https://www.docker.com/)** - Containerization platform
  - Used for: Application deployment and development environment

We extend our sincere gratitude to all the developers and maintainers of these projects for making their excellent work available to the open-source community.

## 📥 Installation Summary

### Quick Start (Choose One)

```bash
# Docker (Recommended for testing)
./run-security-utils.sh

# Native Installation (Recommended for daily use) 
./install-native.sh

# Build all packages
./build.sh all
```

### Platform-Specific Instructions

**Ubuntu/Debian:**
```bash
# Native install with auto-dependencies
./install-native.sh

# Or build Snap package
./build.sh snap
```

**Fedora/RHEL/CentOS:**
```bash
# Native install with auto-dependencies
./install-native.sh

# Or use Flatpak
./build.sh flatpak
```

**Arch Linux/Manjaro:**
```bash
# Native install with auto-dependencies
./install-native.sh

# Or portable AppImage
./build.sh appimage
```

**Any Linux Distribution:**
```bash
# Docker (universal)
./run-security-utils.sh

# Or portable AppImage
./build.sh appimage && ./build/security-utils-1.0.0-x86_64.AppImage
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test with Docker
5. Submit a pull request

## 📞 Support

- Check the `password_hash_gen_doc.html` file for additional documentation
- Review the source code for detailed implementation  
- Test all deployment methods in a safe environment before production use
- Use the build system to create packages for your target platform

## ⚠️ Security Notice

These tools are designed for legitimate security testing and development purposes. Always ensure you have proper authorization before using these tools on systems you do not own.
