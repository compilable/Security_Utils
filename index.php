<?php
// Security headers with enhanced CSP and additional security headers
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; font-src 'self' https://cdn.jsdelivr.net; img-src 'self' data:; connect-src 'self' https://cdn.jsdelivr.net; frame-src 'none'; object-src 'none'; base-uri 'self';");
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Permissions-Policy: geolocation=(), microphone=(), camera=()");
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Utilities Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-9ndCyUaIbzAi2FUVXJi0CjmCapSmO7SnpJef0486qhLnuZ2cdeRhO02iuK6FUUVM" crossorigin="anonymous">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet" crossorigin="anonymous">
    <link href="css/dashboard.css" rel="stylesheet">
</head>
<body>
    <!-- Theme Toggle Button -->
    <div class="theme-toggle" id="theme-toggle" title="Toggle Dark/Light Theme">
        <i class="bi bi-moon-stars" id="theme-icon"></i>
    </div>

    <!-- Hero Section -->
    <section class="hero-section">
        <div class="container">
            <div class="row align-items-center">
                <div class="col-lg-8">
                    <h1 class="display-4 fw-bold mb-3">
                        <i class="bi bi-shield-check"></i> Security Utilities
                    </h1>
                    <p class="lead mb-4">
                        Professional-grade security tools for developers and security professionals. 
                        Generate secure password hashes and randomize image files with enterprise-level security.
                    </p>
                    <div class="d-flex flex-wrap gap-3">
                        <span class="badge bg-light text-dark px-3 py-2">
                            <i class="bi bi-check-circle"></i> Enterprise Security
                        </span>
                        <span class="badge bg-light text-dark px-3 py-2">
                            <i class="bi bi-check-circle"></i> Open Source
                        </span>
                        <span class="badge bg-light text-dark px-3 py-2">
                            <i class="bi bi-check-circle"></i> Docker Ready
                        </span>
                    </div>
                </div>
                <div class="col-lg-4 text-center">
                    <div class="hero-stats mt-4 mt-lg-0">
                        <div class="row">
                            <div class="col-6">
                                <div class="stat-number text-white">2</div>
                                <div class="text-white-50">Tools</div>
                            </div>
                            <div class="col-6">
                                <div class="stat-number text-white">10+</div>
                                <div class="text-white-50">Algorithms</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- Tools Section -->
    <section class="container">
        <div class="row g-4">
            <!-- Password Hash Generator Card -->
            <div class="col-lg-6">
                <div class="tool-card p-4 text-center">
                    <div class="tool-icon text-primary">
                        <i class="bi bi-shield-lock"></i>
                    </div>
                    <h3 class="h4 mb-3">Password Hash Generator</h3>
                    <p class="text-muted mb-4">
                        Generate and verify secure password hashes using industry-standard algorithms 
                        including bcrypt, Argon2, scrypt, and various SHA implementations.
                    </p>
                    
                    <div class="mb-4">
                        <h6 class="mb-3">Key Features:</h6>
                        <ul class="feature-list">
                            <li>Multiple hashing algorithms (bcrypt, Argon2, scrypt)</li>
                            <li>Password verification and comparison</li>
                            <li>Secure client-side processing</li>
                            <li>Dark/Light theme support</li>
                            <li>Real-time strength analysis</li>
                            <li>Export hash results</li>
                        </ul>
                    </div>
                    
                    <div class="mb-3">
                        <span class="badge bg-success me-2">v2.0.1</span>
                        <span class="badge bg-outline-primary me-2">
                            <i class="bi bi-cpu"></i> Client-side
                        </span>
                        <span class="badge bg-outline-success">
                            <i class="bi bi-shield-check"></i> Secure
                        </span>
                    </div>
                    
                    <a href="password_hash_gen.php" class="btn btn-launch">
                        <i class="bi bi-play-circle"></i> Launch Tool
                    </a>
                </div>
            </div>

            <!-- Image Randomizer Card -->
            <div class="col-lg-6">
                <div class="tool-card p-4 text-center">
                    <div class="tool-icon text-success">
                        <i class="bi bi-image"></i>
                    </div>
                    <h3 class="h4 mb-3">Image Randomizer</h3>
                    <p class="text-muted mb-4">
                        Randomize image file data to avoid forensic detection while maintaining 
                        visual integrity. Perfect for privacy and security applications.
                    </p>
                    
                    <div class="mb-4">
                        <h6 class="mb-3">Key Features:</h6>
                        <ul class="feature-list">
                            <li>Support for JPEG, PNG, GIF, WebP formats</li>
                            <li>Configurable randomization cycles</li>
                            <li>File integrity verification</li>
                            <li>Multiple hash algorithms (MD5, SHA256, SHA512)</li>
                            <li>Secure file upload handling</li>
                            <li>Batch processing support</li>
                        </ul>
                    </div>
                    
                    <div class="mb-3">
                        <span class="badge bg-info me-2">Latest</span>
                        <span class="badge bg-outline-warning me-2">
                            <i class="bi bi-upload"></i> File Upload
                        </span>
                        <span class="badge bg-outline-success">
                            <i class="bi bi-shield-check"></i> Secure
                        </span>
                    </div>
                    
                    <a href="image-randomizer.php" class="btn btn-launch">
                        <i class="bi bi-play-circle"></i> Launch Tool
                    </a>
                </div>
            </div>
        </div>

        <!-- Additional Info Section -->
        <div class="stats-section">
            <div class="row text-center g-4">
                <div class="col-md-3">
                    <div class="stat-item">
                        <div class="stat-number">10+</div>
                        <div class="text-muted">Hash Algorithms</div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-item">
                        <div class="stat-number">4</div>
                        <div class="text-muted">Image Formats</div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-item">
                        <div class="stat-number">256-bit</div>
                        <div class="text-muted">Encryption</div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-item">
                        <div class="stat-number">100%</div>
                        <div class="text-muted">Open Source</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Quick Start Guide -->
        <div class="row mt-5">
            <div class="col-12">
                <div class="tool-card p-4">
                    <h4 class="mb-4">
                        <i class="bi bi-rocket-takeoff"></i> Quick Start Guide
                    </h4>
                    <div class="row g-4">
                        <div class="col-md-4">
                            <div class="d-flex align-items-start">
                                <div class="flex-shrink-0">
                                    <div class="btn btn-primary btn-sm rounded-circle step-circle">
                                        1
                                    </div>
                                </div>
                                <div class="flex-grow-1 ms-3">
                                    <h6>Choose Your Tool</h6>
                                    <p class="text-muted mb-0">Select either Password Hash Generator for secure hashing or Image Randomizer for file obfuscation.</p>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="d-flex align-items-start">
                                <div class="flex-shrink-0">
                                    <div class="btn btn-success btn-sm rounded-circle step-circle">
                                        2
                                    </div>
                                </div>
                                <div class="flex-grow-1 ms-3">
                                    <h6>Configure Settings</h6>
                                    <p class="text-muted mb-0">Adjust algorithm settings, security parameters, and processing options according to your needs.</p>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="d-flex align-items-start">
                                <div class="flex-shrink-0">
                                    <div class="btn btn-warning btn-sm rounded-circle step-circle">
                                        3
                                    </div>
                                </div>
                                <div class="flex-grow-1 ms-3">
                                    <h6>Process & Export</h6>
                                    <p class="text-muted mb-0">Execute your security operations and export results for use in your applications.</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- Footer -->
    <footer class="footer">
        <div class="container">
            <div class="row align-items-center">
                <div class="col-md-6">
                    <p class="mb-0">
                        <strong>Security Utilities</strong> &copy; <?php echo date('Y'); ?> - 
                        <a href="https://opensource.org/licenses/MIT" target="_blank" class="text-decoration-none">MIT License</a>
                    </p>
                </div>
                <div class="col-md-6 text-md-end">
                    <p class="mb-0">
                        <i class="bi bi-github"></i> 
                        <a href="https://github.com/compilable/Security_Utils" target="_blank" class="text-decoration-none">
                            GitHub Repository
                        </a>
                    </p>
                </div>
            </div>
        </div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js" integrity="sha384-geWF76RCwLtnZ8qwWowPQNguL3RmwHVBC9FhGdlKrxdiJJigb/j/68SIy3Te4Bkz" crossorigin="anonymous"></script>
    <script src="js/dashboard.js"></script>
</body>
</html>