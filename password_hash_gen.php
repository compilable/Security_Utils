<?php
// Security headers with improved CSP and additional security headers
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://unpkg.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; font-src 'self' https://cdn.jsdelivr.net; img-src 'self' data:; connect-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://unpkg.com; frame-src 'none'; object-src 'none'; base-uri 'self';");
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
    <title>Password Hash Generator v2.0.0</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-9ndCyUaIbzAi2FUVXJi0CjmCapSmO7SnpJef0486qhLnuZ2cdeRhO02iuK6FUUVM" crossorigin="anonymous">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet" crossorigin="anonymous">
    <style>
        :root {
            --bg-color: #f8f9fa;
            --card-bg: #ffffff;
            --text-color: #212529;
            --border-color: #dee2e6;
            --input-bg: #ffffff;
            --input-border: #ced4da;
            --muted-text: #6c757d;
            --hover-bg: #e9ecef;
        }
        
        [data-theme="dark"] {
            --bg-color: #121212;
            --card-bg: #1e1e1e;
            --text-color: #ffffff;
            --border-color: #404040;
            --input-bg: #2d2d2d;
            --input-border: #555555;
            --muted-text: #aaaaaa;
            --hover-bg: #333333;
        }
        
        body {
            background-color: var(--bg-color) !important;
            color: var(--text-color) !important;
            transition: background-color 0.3s ease, color 0.3s ease;
        }
        
        .card {
            background-color: var(--card-bg) !important;
            border-color: var(--border-color) !important;
            color: var(--text-color) !important;
        }
        
        .form-control {
            background-color: var(--input-bg) !important;
            border-color: var(--input-border) !important;
            color: var(--text-color) !important;
        }
        
        .form-control:focus {
            background-color: var(--input-bg) !important;
            border-color: #0d6efd !important;
            color: var(--text-color) !important;
            box-shadow: 0 0 0 0.25rem rgba(13, 110, 253, 0.25) !important;
        }
        
        .form-select {
            background-color: var(--input-bg) !important;
            border-color: var(--input-border) !important;
            color: var(--text-color) !important;
        }
        
        .text-muted {
            color: var(--muted-text) !important;
        }
        
        .theme-toggle {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 1050;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 0.375rem;
            padding: 0.5rem;
            box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075);
        }
        
        .file-list {
            max-height: 200px;
            overflow-y: auto;
            border: 1px solid var(--border-color);
            border-radius: 0.375rem;
            padding: 0.5rem;
            background-color: var(--input-bg);
        }
        .file-item {
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 0.25rem;
            padding: 0.5rem;
            margin-bottom: 0.5rem;
            display: flex;
            justify-content: between;
            align-items: center;
            color: var(--text-color);
        }
        .file-item:hover {
            background-color: var(--hover-bg);
            cursor: pointer;
        }
        .password-field {
            position: relative;
        }
        .password-toggle {
            position: absolute;
            right: 10px;
            top: 50%;
            transform: translateY(-50%);
            cursor: pointer;
            z-index: 10;
            color: var(--muted-text);
        }
        .generated-password {
            font-family: monospace;
            word-break: break-all;
        }
        .card {
            box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075);
        }
    </style>
</head>
<body class="bg-light">
    <!-- Theme Toggle -->
    <div class="theme-toggle">
        <div class="form-check form-switch">
            <input class="form-check-input" type="checkbox" id="themeToggle">
            <label class="form-check-label" for="themeToggle" id="themeLabel">
                <i class="bi bi-sun-fill"></i> Light
            </label>
        </div>
    </div>
    
    <!-- Back Button -->
    <div class="container mt-3">
        <a href="index.php" class="btn btn-secondary btn-sm">
            <i class="bi bi-arrow-left"></i> Back to Dashboard
        </a>
    </div>
    
    <div class="container py-5">
        <div class="row justify-content-center">
            <div class="col-lg-8">
                <div class="card">
                    <div class="card-header bg-primary text-white d-flex justify-content-between align-items-center">
                        <h4 class="mb-0"><i class="bi bi-shield-lock"></i> Password Hash Generator v2.0.0</h4>
                        <a href="password_hash_gen_doc.html" class="btn btn-outline-light btn-sm" target="_blank" title="Open User Documentation">
                            <i class="bi bi-question-circle"></i> Help
                        </a>
                    </div>
                    <div class="card-body">
                        <form id="hashForm" enctype="multipart/form-data">
                            <!-- File Selection -->
                            <div class="mb-4">
                                <label class="form-label fw-bold">Key files:</label>
                                <div class="input-group mb-3">
                                    <input type="file" class="form-control" id="fileInput" multiple accept="*/*" maxlength="255">
                                    <button type="button" class="btn btn-outline-secondary" id="addFilesBtn">
                                        <i class="bi bi-plus-circle"></i> Add Files
                                    </button>
                                </div>
                                <div id="fileList" class="file-list">
                                    <div class="text-muted text-center py-3">
                                        <i class="bi bi-file-earmark"></i> No files selected. Double-click items to remove.
                                    </div>
                                </div>
                                <small class="text-muted">Maximum 10 files, 5MB each</small>
                            </div>

                            <!-- Password Input -->
                            <div class="mb-4">
                                <label for="password" class="form-label fw-bold">Password:</label>
                                <div class="password-field">
                                    <input type="password" class="form-control" id="password" name="password" maxlength="100" autocomplete="new-password">
                                    <i class="bi bi-eye password-toggle" data-target="password"></i>
                                </div>
                            </div>

                            <hr>

                            <!-- Security Questions -->
                            <div class="mb-4">
                                <label for="q1" class="form-label fw-bold">Answer to Q1:</label>
                                <div class="password-field">
                                    <input type="password" class="form-control" id="q1" name="q1" maxlength="100" autocomplete="off">
                                    <i class="bi bi-eye password-toggle" data-target="q1"></i>
                                </div>
                            </div>

                            <div class="mb-4">
                                <label for="q2" class="form-label fw-bold">Answer to Q2:</label>
                                <div class="password-field">
                                    <input type="password" class="form-control" id="q2" name="q2" maxlength="100" autocomplete="off">
                                    <i class="bi bi-eye password-toggle" data-target="q2"></i>
                                </div>
                            </div>

                            <div class="mb-4">
                                <label for="q3" class="form-label fw-bold">Answer to Q3:</label>
                                <div class="password-field">
                                    <input type="password" class="form-control" id="q3" name="q3" maxlength="100" autocomplete="off">
                                    <i class="bi bi-eye password-toggle" data-target="q3"></i>
                                </div>
                            </div>

                            <!-- Show Password Checkbox -->
                            <div class="form-check mb-4 text-center">
                                <input class="form-check-input" type="checkbox" id="showPasswordCheck">
                                <label class="form-check-label" for="showPasswordCheck">
                                    Show Password
                                </label>
                            </div>

                            <!-- Iterations -->
                            <div class="mb-4">
                                <label for="iterations" class="form-label fw-bold">Number of iterations:</label>
                                <select class="form-select" id="iterations" name="iterations">
                                    <?php for($i = 1; $i <= 10; $i++): ?>
                                        <option value="<?php echo $i; ?>" <?php echo $i === 1 ? 'selected' : ''; ?>><?php echo $i; ?></option>
                                    <?php endfor; ?>
                                </select>
                            </div>

                            <!-- Hash Algorithm -->
                            <div class="mb-4">
                                <label class="form-label fw-bold">Hashing Algorithm:</label>
                                <div class="form-check">
                                    <input class="form-check-input" type="radio" name="hashAlgorithm" id="md5" value="md5" checked>
                                    <label class="form-check-label" for="md5">MD5SUM</label>
                                </div>
                                <div class="form-check">
                                    <input class="form-check-input" type="radio" name="hashAlgorithm" id="sha256" value="sha256">
                                    <label class="form-check-label" for="sha256">SHA 256</label>
                                </div>
                                <div class="form-check">
                                    <input class="form-check-input" type="radio" name="hashAlgorithm" id="sha512" value="sha512">
                                    <label class="form-check-label" for="sha512">SHA 512</label>
                                </div>
                                <div class="form-check">
                                    <input class="form-check-input" type="radio" name="hashAlgorithm" id="bcrypt" value="bcrypt">
                                    <label class="form-check-label" for="bcrypt">BCrypt</label>
                                </div>
                                <div class="form-check">
                                    <input class="form-check-input" type="radio" name="hashAlgorithm" id="scrypt" value="scrypt">
                                    <label class="form-check-label" for="scrypt">SCrypt</label>
                                </div>
                                <div class="form-check">
                                    <input class="form-check-input" type="radio" name="hashAlgorithm" id="argon2" value="argon2">
                                    <label class="form-check-label" for="argon2">Argon2</label>
                                </div>
                            </div>

                            <!-- Generate Button -->
                            <div class="mb-4 text-center">
                                <button type="button" class="btn btn-primary btn-lg" id="generateBtn">
                                    <i class="bi bi-gear"></i> Generate
                                </button>
                            </div>

                            <hr>

                            <!-- Generated Password -->
                            <div class="mb-4">
                                <label for="generatedPassword" class="form-label fw-bold">Generated password:</label>
                                <div class="input-group">
                                    <input type="password" class="form-control generated-password" id="generatedPassword" readonly>
                                    <button type="button" class="btn btn-outline-secondary" id="copyBtn" disabled>
                                        <i class="bi bi-clipboard"></i> Copy to Clipboard
                                    </button>
                                </div>
                            </div>

                            <!-- Clear Button -->
                            <div class="text-center">
                                <button type="button" class="btn btn-secondary" id="clearBtn">
                                    <i class="bi bi-arrow-clockwise"></i> Clear
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Footer -->
    <footer class="mt-5 py-4 border-top">
        <div class="container">
            <div class="row">
                <div class="col-12 text-center">
                    <p class="text-muted mb-2">
                        <small>
                            &copy; <?php echo date('Y'); ?> Password Hash Generator - Released under the 
                            <a href="https://opensource.org/licenses/MIT" target="_blank" class="text-decoration-none">MIT License</a>
                        </small>
                    </p>
                    <p class="text-muted mb-0">
                        <small>
                            <i class="bi bi-github"></i> 
                            <a href="https://github.com/compilable/Security_Utils" target="_blank" class="text-decoration-none">
                                GitHub Repository
                            </a>
                        </small>
                    </p>
                </div>
            </div>
        </div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js" integrity="sha384-geWF76RCwLtnZ8qwWowPQNguL3RmwHVBC9FhGdlKrxdiJJigb/j/68SIy3Te4Bkz" crossorigin="anonymous"></script>
    <!-- Include crypto-js for secure MD5 implementation -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js" integrity="sha512-E8QSvWZ0eCLGk4km3hxSsNmGWbLtSCSUcewDQPQWZF6pEU8GlT8a5fF32wOl1i8ftdMhssTrF/OhyGWwonTcXA==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
    <!-- Include bcryptjs for bcrypt support -->
    <script src="https://cdn.jsdelivr.net/npm/bcryptjs@2.4.3/dist/bcrypt.min.js" crossorigin="anonymous"></script>
    <!-- Include scrypt-js for scrypt support -->
    <script src="https://cdn.jsdelivr.net/npm/scrypt-js@3.0.1/scrypt.min.js" crossorigin="anonymous"></script>
    <!-- Include argon2-browser for Argon2 support -->
    <script src="https://unpkg.com/argon2-browser@1.18.0/dist/argon2-bundled.min.js" crossorigin="anonymous"></script>
    <script>
        // Security constants
        const MAX_FILES = 10;
        const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB
        const MAX_INPUT_LENGTH = 100;
        const MAX_QUESTION_LENGTH = 100;
        
        // Rate limiting
        let lastGenerateTime = 0;
        const RATE_LIMIT_MS = 1000; // 1 second between generations

        // Detect bcrypt library with delayed loading support
        let bcryptLib = null;
        let scryptLib = null;
        
        function detectBcryptLibrary() {
            // Debug: Log available global objects
            console.log('Available globals:', {
                'typeof dcodeIO': typeof dcodeIO,
                'typeof bcrypt': typeof bcrypt,
                'typeof window.bcrypt': typeof window.bcrypt,
                'typeof window.dcodeIO': typeof window.dcodeIO,
                'window.dcodeIO': window.dcodeIO,
                'window.bcryptjs': typeof window.bcryptjs,
                'typeof scrypt': typeof scrypt,
                'window.scrypt': typeof window.scrypt,
                'All window keys': Object.keys(window).filter(key => key.toLowerCase().includes('crypt'))
            });
            
            // Try multiple detection methods for bcrypt
            if (typeof dcodeIO !== 'undefined' && dcodeIO && dcodeIO.bcrypt) {
                bcryptLib = dcodeIO.bcrypt;
                console.log('BCrypt detected via dcodeIO.bcrypt');
            } else if (typeof bcrypt !== 'undefined' && bcrypt && bcrypt.genSaltSync) {
                bcryptLib = bcrypt;
                console.log('BCrypt detected via global bcrypt');
            } else if (typeof window !== 'undefined' && window.dcodeIO && window.dcodeIO.bcrypt) {
                bcryptLib = window.dcodeIO.bcrypt;
                console.log('BCrypt detected via window.dcodeIO.bcrypt');
            } else if (typeof window !== 'undefined' && window.bcrypt && window.bcrypt.genSaltSync) {
                bcryptLib = window.bcrypt;
                console.log('BCrypt detected via window.bcrypt');
            } else if (typeof window !== 'undefined' && window.bcryptjs) {
                bcryptLib = window.bcryptjs;
                console.log('BCrypt detected via window.bcryptjs');
            }
            
            // Try detection methods for scrypt
            if (typeof scrypt !== 'undefined' && scrypt && scrypt.scrypt) {
                scryptLib = scrypt;
                console.log('SCrypt detected via global scrypt');
            } else if (typeof window !== 'undefined' && window.scrypt && window.scrypt.scrypt) {
                scryptLib = window.scrypt;
                console.log('SCrypt detected via window.scrypt');
            }
            
            console.log('BCrypt library detected:', bcryptLib ? 'Yes' : 'No');
            if (bcryptLib) {
                console.log('BCrypt methods available:', {
                    'genSaltSync': typeof bcryptLib.genSaltSync,
                    'hashSync': typeof bcryptLib.hashSync,
                    'available methods': Object.keys(bcryptLib)
                });
            }
            
            console.log('SCrypt library detected:', scryptLib ? 'Yes' : 'No');
            if (scryptLib) {
                console.log('SCrypt methods available:', {
                    'scrypt': typeof scryptLib.scrypt,
                    'available methods': Object.keys(scryptLib)
                });
            }
            
            return (bcryptLib !== null) || (scryptLib !== null);
        }
        
        // Initial detection
        detectBcryptLibrary();
        
        // Retry detection after a delay to handle async loading
        setTimeout(() => {
            if (!bcryptLib || !scryptLib) {
                console.log('Retrying crypto libraries detection after delay...');
                detectBcryptLibrary();
            }
        }, 1000);

        // Check Web Crypto API availability
        function isWebCryptoAvailable() {
            return window.isSecureContext && 
                   typeof window.crypto !== 'undefined' && 
                   typeof window.crypto.subtle !== 'undefined';
        }

        // Fallback for crypto.getRandomValues when Web Crypto API is not available
        function getRandomBytes(length) {
            if (isWebCryptoAvailable()) {
                return crypto.getRandomValues(new Uint8Array(length));
            } else {
                // Fallback using Math.random (less secure but functional)
                console.warn('Using fallback random generation (less secure). Consider using HTTPS for better security.');
                const bytes = new Uint8Array(length);
                for (let i = 0; i < length; i++) {
                    bytes[i] = Math.floor(Math.random() * 256);
                }
                return bytes;
            }
        }
        
        // Show warning about insecure context
        function showSecurityWarning() {
            if (!isWebCryptoAvailable() && !window.securityWarningShown) {
                window.securityWarningShown = true;
                console.warn('Web Crypto API not available. Using fallback implementations. For better security, access the application over HTTPS or localhost.');
                
                // Show user-visible warning
                const warning = document.createElement('div');
                warning.className = 'alert alert-warning alert-dismissible fade show';
                warning.style.position = 'fixed';
                warning.style.top = '80px';
                warning.style.right = '20px';
                warning.style.zIndex = '9999';
                warning.style.maxWidth = '350px';
                warning.innerHTML = `
                    <strong>Security Notice:</strong> Using fallback encryption. For enhanced security, access this page over HTTPS or localhost.
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                `;
                document.body.appendChild(warning);
                
                // Auto-remove after 10 seconds
                setTimeout(() => {
                    if (warning.parentNode) {
                        warning.parentNode.removeChild(warning);
                    }
                }, 10000);
            }
        }

        class SecureHashUtils {
            static async genStringHash(algorithm, text) {
                if (!text || typeof text !== 'string') {
                    throw new Error('Invalid input text');
                }
                
                // Only apply length restrictions to non-hash algorithms (WebCrypto algorithms)
                // Hash algorithms like bcrypt, scrypt, argon2 can handle longer inputs including pre-hashed data
                if (text.length > MAX_INPUT_LENGTH && !['md5', 'bcrypt', 'scrypt', 'argon2', 'sha256', 'sha384', 'sha512', 'sha1'].includes(algorithm)) {
                    throw new Error('Input too long');
                }
                
                switch(algorithm) {
                    case 'md5':
                        // Use crypto-js for secure MD5
                        return CryptoJS.MD5(text).toString();
                    case 'sha256':
                        if (isWebCryptoAvailable()) {
                            const encoder = new TextEncoder();
                            const data = encoder.encode(text);
                            const sha256Hash = await crypto.subtle.digest('SHA-256', data);
                            return this.bufferToHex(sha256Hash);
                        } else {
                            // Fallback to crypto-js
                            return CryptoJS.SHA256(text).toString();
                        }
                    case 'sha512':
                        if (isWebCryptoAvailable()) {
                            const encoder = new TextEncoder();
                            const data = encoder.encode(text);
                            const sha512Hash = await crypto.subtle.digest('SHA-512', data);
                            return this.bufferToHex(sha512Hash);
                        } else {
                            // Fallback to crypto-js
                            return CryptoJS.SHA512(text).toString();
                        }
                    case 'bcrypt':
                        // BCrypt with cost factor of 12
                        if (!bcryptLib) {
                            throw new Error('BCrypt library not available');
                        }
                        const bcryptSalt = bcryptLib.genSaltSync(12);
                        return bcryptLib.hashSync(text, bcryptSalt);
                    case 'scrypt':
                        // SCrypt with N=16384, r=8, p=1, dkLen=64
                        if (!scryptLib) {
                            throw new Error('SCrypt library not available');
                        }
                        const textBuffer = new TextEncoder().encode(text);
                        const scryptSalt = crypto.getRandomValues(new Uint8Array(16));
                        const scryptResult = await scryptLib.scrypt(textBuffer, scryptSalt, 16384, 8, 1, 64);
                        // Convert to hex and prepend salt
                        const saltHex = Array.from(scryptSalt).map(b => b.toString(16).padStart(2, '0')).join('');
                        const hashHex = Array.from(scryptResult).map(b => b.toString(16).padStart(2, '0')).join('');
                        return saltHex + hashHex;
                    case 'argon2':
                        // Argon2id with default parameters
                        const argon2Result = await argon2.hash({
                            pass: text,
                            salt: crypto.getRandomValues(new Uint8Array(16)),
                            type: argon2.ArgonType.Argon2id,
                            mem: 65536, // 64 MB
                            time: 3,    // 3 iterations
                            parallelism: 4
                        });
                        return argon2Result.encoded;
                    default:
                        throw new Error('Unsupported hash algorithm');
                }
            }

            static bufferToHex(buffer) {
                return Array.from(new Uint8Array(buffer))
                    .map(b => b.toString(16).padStart(2, '0'))
                    .join('');
            }

            static async genFileHash(fileList, algorithm, cycles = 1) {
                if (!Array.isArray(fileList) || fileList.length === 0) return "";
                if (cycles < 1 || cycles > 10) throw new Error('Invalid cycle count');

                const fileHashes = [];
                
                // Sort files by name for consistent results
                const sortedFiles = Array.from(fileList).sort((a, b) => a.name.localeCompare(b.name));
                
                for (const file of sortedFiles) {
                    this.validateFile(file);
                    let fileHash = await this.calculateFileHash(file, algorithm);
                    
                    for (let cycle = 1; cycle < cycles; cycle++) {
                        fileHash = await this.genStringHash(algorithm, fileHash);
                    }
                    fileHashes.push(fileHash);
                }

                if (fileList.length === 1) {
                    return fileHashes[0];
                } else {
                    return await this.genStringHash(algorithm, fileHashes.join(''));
                }
            }

            static validateFile(file) {
                if (!file || !file.name) {
                    throw new Error('Invalid file object');
                }
                
                if (file.size > MAX_FILE_SIZE) {
                    throw new Error(`File too large: ${file.name}. Maximum size is ${MAX_FILE_SIZE / (1024*1024)}MB`);
                }
                
                // Check for potentially dangerous file types
                const dangerousExtensions = ['.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.js', '.jar'];
                const extension = file.name.toLowerCase().substring(file.name.lastIndexOf('.'));
                if (dangerousExtensions.includes(extension)) {
                    console.warn(`Warning: Processing potentially dangerous file type: ${file.name}`);
                }
            }

            static async calculateFileHash(file, algorithm) {
                return new Promise((resolve, reject) => {
                    const reader = new FileReader();
                    reader.onload = async function(e) {
                        try {
                            // Use ArrayBuffer for binary files
                            const arrayBuffer = e.target.result;
                            let hash;
                            
                            switch(algorithm) {
                                case 'md5':
                                    // Convert ArrayBuffer to WordArray for crypto-js
                                    const wordArray = CryptoJS.lib.WordArray.create(arrayBuffer);
                                    hash = CryptoJS.MD5(wordArray).toString();
                                    break;
                                case 'sha256':
                                    if (isWebCryptoAvailable()) {
                                        const sha256Hash = await crypto.subtle.digest('SHA-256', arrayBuffer);
                                        hash = SecureHashUtils.bufferToHex(sha256Hash);
                                    } else {
                                        // Fallback to crypto-js
                                        const wordArray = CryptoJS.lib.WordArray.create(arrayBuffer);
                                        hash = CryptoJS.SHA256(wordArray).toString();
                                    }
                                    break;
                                case 'sha512':
                                    if (isWebCryptoAvailable()) {
                                        const sha512Hash = await crypto.subtle.digest('SHA-512', arrayBuffer);
                                        hash = SecureHashUtils.bufferToHex(sha512Hash);
                                    } else {
                                        // Fallback to crypto-js
                                        const wordArray = CryptoJS.lib.WordArray.create(arrayBuffer);
                                        hash = CryptoJS.SHA512(wordArray).toString();
                                    }
                                    break;
                                case 'bcrypt':
                                    // For files with bcrypt, convert to base64 first then hash
                                    if (!bcryptLib) {
                                        throw new Error('BCrypt library not available');
                                    }
                                    const base64 = btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)));
                                    const bcryptFileSalt = bcryptLib.genSaltSync(12);
                                    hash = bcryptLib.hashSync(base64, bcryptFileSalt);
                                    break;
                                case 'scrypt':
                                    // For files with scrypt
                                    if (!scryptLib) {
                                        throw new Error('SCrypt library not available');
                                    }
                                    const fileBuffer = new Uint8Array(arrayBuffer);
                                    const scryptFileSalt = getRandomBytes(16);
                                    const fileScryptResult = await scryptLib.scrypt(fileBuffer, scryptFileSalt, 16384, 8, 1, 64);
                                    const fileSaltHex = Array.from(scryptFileSalt).map(b => b.toString(16).padStart(2, '0')).join('');
                                    const fileHashHex = Array.from(fileScryptResult).map(b => b.toString(16).padStart(2, '0')).join('');
                                    hash = fileSaltHex + fileHashHex;
                                    break;
                                case 'argon2':
                                    // For files with Argon2, convert to base64 first
                                    const fileBase64 = btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)));
                                    const argon2Result = await argon2.hash({
                                        pass: fileBase64,
                                        salt: getRandomBytes(16),
                                        type: argon2.ArgonType.Argon2id,
                                        mem: 65536,
                                        time: 3,
                                        parallelism: 4
                                    });
                                    hash = argon2Result.encoded;
                                    break;
                                default:
                                    throw new Error('Unsupported hash algorithm');
                            }
                            resolve(hash);
                        } catch (error) {
                            reject(new Error(`Failed to hash file ${file.name}: ${error.message}`));
                        }
                    };
                    reader.onerror = () => reject(new Error(`Failed to read file: ${file.name}`));
                    reader.readAsArrayBuffer(file); // Use ArrayBuffer instead of text
                });
            }

            static async genQuestionHash(questionList, algorithm, cycles = 1) {
                if (!Array.isArray(questionList) || questionList.length === 0) return "";
                if (cycles < 1 || cycles > 10) throw new Error('Invalid cycle count');

                const qHashes = [];

                for (const question of questionList) {
                    if (typeof question !== 'string' || question.length > MAX_QUESTION_LENGTH) {
                        throw new Error('Invalid question format or too long');
                    }
                    
                    let questionHash = await this.genStringHash(algorithm, question);
                    
                    for (let cycle = 1; cycle < cycles; cycle++) {
                        questionHash = await this.genStringHash(algorithm, questionHash);
                    }
                    qHashes.push(questionHash);
                }

                if (questionList.length === 1) {
                    return qHashes[0];
                } else {
                    // Join all question hashes first, then hash the result (matches Python implementation)
                    return await this.genStringHash(algorithm, qHashes.join(''));
                }
            }

            static async getHmacDigest(algorithm, passwordList, key) {
                if (!Array.isArray(passwordList) || passwordList.length === 0) {
                    return "";
                }
                
                if (!key || typeof key !== 'string' || key.length > MAX_INPUT_LENGTH) {
                    throw new Error('Invalid HMAC key');
                }

                const password = passwordList.join('');
                
                if (password.length === 0) {
                    return "";
                }

                try {
                    switch(algorithm) {
                        case 'md5':
                            // Proper HMAC-MD5 implementation using CryptoJS (matches Python implementation)
                            return CryptoJS.HmacMD5(password, key).toString();
                        case 'sha256':
                            if (isWebCryptoAvailable()) {
                                // Use Web Crypto API for proper HMAC implementation
                                const encoder = new TextEncoder();
                                const keyData = encoder.encode(key);
                                const messageData = encoder.encode(password);
                                const cryptoKey = await crypto.subtle.importKey(
                                    'raw',
                                    keyData,
                                    { name: 'HMAC', hash: 'SHA-256' },
                                    false,
                                    ['sign']
                                );
                                const signature = await crypto.subtle.sign('HMAC', cryptoKey, messageData);
                                return this.bufferToHex(signature);
                            } else {
                                // Fallback to crypto-js
                                return CryptoJS.HmacSHA256(password, key).toString();
                            }
                        case 'sha512':
                            if (isWebCryptoAvailable()) {
                                // Use Web Crypto API for proper HMAC implementation
                                const encoder = new TextEncoder();
                                const keyData = encoder.encode(key);
                                const messageData = encoder.encode(password);
                                const cryptoKey = await crypto.subtle.importKey(
                                    'raw',
                                    keyData,
                                    { name: 'HMAC', hash: 'SHA-512' },
                                    false,
                                    ['sign']
                                );
                                const signature = await crypto.subtle.sign('HMAC', cryptoKey, messageData);
                                return this.bufferToHex(signature);
                            } else {
                                // Fallback to crypto-js
                                return CryptoJS.HmacSHA512(password, key).toString();
                            }
                        case 'bcrypt':
                            // BCrypt doesn't support HMAC, use key-stretching approach
                            if (!bcryptLib) {
                                throw new Error('BCrypt library not available');
                            }
                            const combinedBcrypt = key + password;
                            const hmacBcryptSalt = bcryptLib.genSaltSync(12);
                            return bcryptLib.hashSync(combinedBcrypt, hmacBcryptSalt);
                        case 'scrypt':
                            // SCrypt with key as salt
                            if (!scryptLib) {
                                throw new Error('SCrypt library not available');
                            }
                            const combinedScrypt = new TextEncoder().encode(password);
                            const hmacKeySalt = new TextEncoder().encode(key.substring(0, 16).padEnd(16, '0'));
                            const hmacScryptResult = await scryptLib.scrypt(combinedScrypt, hmacKeySalt, 16384, 8, 1, 64);
                            return Array.from(hmacScryptResult).map(b => b.toString(16).padStart(2, '0')).join('');
                        case 'argon2':
                            // Argon2 with password and key
                            const combinedArgon2 = password + key;
                            const argon2Result = await argon2.hash({
                                pass: combinedArgon2,
                                salt: getRandomBytes(16),
                                type: argon2.ArgonType.Argon2id,
                                mem: 65536,
                                time: 3,
                                parallelism: 4
                            });
                            return argon2Result.encoded;
                        default:
                            throw new Error('Unsupported hash algorithm');
                    }
                } catch (error) {
                    throw new Error(`HMAC generation failed: ${error.message}`);
                }
            }

            // Secure memory cleanup
            static clearSensitiveData(element) {
                if (element && element.value) {
                    // Overwrite with random data before clearing
                    const length = element.value.length;
                    element.value = Array(length).fill(0).map(() => Math.random().toString(36)).join('').substring(0, length);
                    setTimeout(() => {
                        element.value = '';
                    }, 100);
                }
            }
        }

        class PasswordHashGenerator {
            constructor() {
                this.selectedFiles = new Set();
                this.selectedHash = 'md5';
                this.maxFiles = MAX_FILES;
                this.autoClearTimer = null;
                this.autoClearInterval = 60000; // 1 minute in milliseconds
                this.initializeTheme();
                this.initializeEventListeners();
                this.startAutoClearTimer();
            }

            initializeTheme() {
                // Load saved theme or default to light
                const savedTheme = localStorage.getItem('theme') || 'light';
                this.setTheme(savedTheme);
                
                // Set up theme toggle
                const themeToggle = document.getElementById('themeToggle');
                const themeLabel = document.getElementById('themeLabel');
                
                themeToggle.checked = savedTheme === 'dark';
                this.updateThemeLabel(savedTheme);
                
                themeToggle.addEventListener('change', (e) => {
                    const theme = e.target.checked ? 'dark' : 'light';
                    this.setTheme(theme);
                    localStorage.setItem('theme', theme);
                });
            }
            
            setTheme(theme) {
                document.documentElement.setAttribute('data-theme', theme);
                this.updateThemeLabel(theme);
            }
            
            updateThemeLabel(theme) {
                const themeLabel = document.getElementById('themeLabel');
                if (theme === 'dark') {
                    themeLabel.innerHTML = '<i class="bi bi-moon-fill"></i> Dark';
                } else {
                    themeLabel.innerHTML = '<i class="bi bi-sun-fill"></i> Light';
                }
            }

            initializeEventListeners() {
                // File selection with validation
                document.getElementById('addFilesBtn').addEventListener('click', () => {
                    document.getElementById('fileInput').click();
                });

                document.getElementById('fileInput').addEventListener('change', (e) => {
                    this.addFiles(e.target.files);
                });

                // Input validation for text fields
                ['password', 'q1', 'q2', 'q3'].forEach(id => {
                    const input = document.getElementById(id);
                    input.addEventListener('input', (e) => {
                        const maxLen = id === 'password' ? MAX_INPUT_LENGTH : MAX_QUESTION_LENGTH;
                        if (e.target.value.length > maxLen) {
                            e.target.value = e.target.value.substring(0, maxLen);
                            this.showWarning(`Input truncated to ${maxLen} characters`);
                        }
                    });
                });

                // Password visibility toggles
                document.querySelectorAll('.password-toggle').forEach(toggle => {
                    toggle.addEventListener('click', (e) => {
                        this.togglePasswordVisibility(e.target.dataset.target);
                    });
                });

                // Show password checkbox
                document.getElementById('showPasswordCheck').addEventListener('change', (e) => {
                    this.toggleAllPasswordVisibility(e.target.checked);
                });

                // Hash algorithm change
                document.querySelectorAll('input[name="hashAlgorithm"]').forEach(radio => {
                    radio.addEventListener('change', (e) => {
                        this.selectedHash = e.target.value;
                        // Clear generated password when algorithm changes
                        SecureHashUtils.clearSensitiveData(document.getElementById('generatedPassword'));
                    });
                });

                // Generate button
                document.getElementById('generateBtn').addEventListener('click', () => {
                    this.generatePassword();
                });

                // Copy button
                document.getElementById('copyBtn').addEventListener('click', () => {
                    this.copyToClipboard();
                });

                // Clear button
                document.getElementById('clearBtn').addEventListener('click', () => {
                    this.clearForm();
                });

                // Generated password change
                document.getElementById('generatedPassword').addEventListener('input', (e) => {
                    document.getElementById('copyBtn').disabled = e.target.value.length === 0;
                });

                // Prevent form submission
                document.getElementById('hashForm').addEventListener('submit', (e) => {
                    e.preventDefault();
                });
                
                // Add activity listeners to reset auto-clear timer
                this.addActivityListeners();
            }

            startAutoClearTimer() {
                // Clear existing timer
                if (this.autoClearTimer) {
                    clearTimeout(this.autoClearTimer);
                }
                
                // Start new timer
                this.autoClearTimer = setTimeout(() => {
                    this.showWarning('Form will be cleared in 10 seconds for security...', 'warning', 10000);
                    
                    // Final warning and clear
                    setTimeout(() => {
                        this.clearForm();
                        this.showWarning('Form cleared automatically for security', 'info', 3000);
                        this.startAutoClearTimer(); // Restart timer
                    }, 10000);
                }, this.autoClearInterval - 10000); // Show warning 10 seconds before clearing
            }

            resetAutoClearTimer() {
                this.startAutoClearTimer();
            }

            addActivityListeners() {
                // List of events that indicate user activity
                const activityEvents = ['click', 'keydown', 'mousemove', 'input', 'change'];
                
                activityEvents.forEach(eventType => {
                    document.addEventListener(eventType, () => {
                        this.resetAutoClearTimer();
                    }, { passive: true });
                });
            }

            showWarning(message, type = 'warning', duration = 5000) {
                // Create a temporary warning message
                const warning = document.createElement('div');
                const alertType = type === 'info' ? 'alert-info' : type === 'warning' ? 'alert-warning' : 'alert-danger';
                warning.className = `alert ${alertType} alert-dismissible fade show position-fixed`;
                warning.style.top = '20px';
                warning.style.right = '20px';
                warning.style.zIndex = '9999';
                warning.innerHTML = `
                    ${this.escapeHtml(message)}
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                `;
                document.body.appendChild(warning);
                
                setTimeout(() => {
                    if (warning.parentNode) {
                        warning.parentNode.removeChild(warning);
                    }
                }, duration);
            }

            escapeHtml(text) {
                const map = {
                    '&': '&amp;',
                    '<': '&lt;',
                    '>': '&gt;',
                    '"': '&quot;',
                    "'": '&#039;'
                };
                return text.replace(/[&<>"']/g, function(m) { return map[m]; });
            }

            addFiles(files) {
                const newFiles = Array.from(files);
                
                // Validate file count
                if (this.selectedFiles.size + newFiles.length > this.maxFiles) {
                    this.showWarning(`Maximum ${this.maxFiles} files allowed`);
                    return;
                }
                
                // Validate and add files
                for (const file of newFiles) {
                    try {
                        SecureHashUtils.validateFile(file);
                        this.selectedFiles.add(file);
                    } catch (error) {
                        this.showWarning(`File rejected: ${error.message}`);
                    }
                }
                
                this.updateFileList();
                // Clear the file input to allow re-selecting the same file
                document.getElementById('fileInput').value = '';
            }

            updateFileList() {
                const fileListDiv = document.getElementById('fileList');
                
                if (this.selectedFiles.size === 0) {
                    fileListDiv.innerHTML = `
                        <div class="text-muted text-center py-3">
                            <i class="bi bi-file-earmark"></i> No files selected. Double-click items to remove.
                        </div>
                    `;
                    return;
                }

                fileListDiv.innerHTML = '';
                this.selectedFiles.forEach(file => {
                    const fileItem = document.createElement('div');
                    fileItem.className = 'file-item';
                    
                    // Escape file name and size to prevent XSS
                    const fileName = this.escapeHtml(file.name);
                    const fileSize = (file.size / 1024).toFixed(2);
                    
                    fileItem.innerHTML = `
                        <span><i class="bi bi-file-earmark"></i> ${fileName}</span>
                        <small class="text-muted">(${fileSize} KB)</small>
                    `;
                    
                    fileItem.addEventListener('dblclick', () => {
                        this.removeFile(file);
                    });
                    
                    fileListDiv.appendChild(fileItem);
                });
            }

            removeFile(file) {
                this.selectedFiles.delete(file);
                this.updateFileList();
            }

            togglePasswordVisibility(targetId) {
                const input = document.getElementById(targetId);
                const toggle = document.querySelector(`[data-target="${targetId}"]`);
                
                if (input.type === 'password') {
                    input.type = 'text';
                    toggle.className = 'bi bi-eye-slash password-toggle';
                } else {
                    input.type = 'password';
                    toggle.className = 'bi bi-eye password-toggle';
                }
            }

            toggleAllPasswordVisibility(show) {
                const inputs = ['password', 'q1', 'q2', 'q3'];
                inputs.forEach(inputId => {
                    const input = document.getElementById(inputId);
                    const toggle = document.querySelector(`[data-target="${inputId}"]`);
                    
                    if (show) {
                        input.type = 'text';
                        toggle.className = 'bi bi-eye-slash password-toggle';
                    } else {
                        input.type = 'password';
                        toggle.className = 'bi bi-eye password-toggle';
                    }
                });
            }

            getQuestions() {
                const questions = [];
                ['q1', 'q2', 'q3'].forEach(id => {
                    const value = document.getElementById(id).value.trim();
                    if (value) questions.push(value);
                });
                return questions;
            }

            async generatePassword() {
                // Rate limiting
                const now = Date.now();
                if (now - lastGenerateTime < RATE_LIMIT_MS) {
                    this.showWarning('Please wait before generating another password');
                    return;
                }
                lastGenerateTime = now;

                const generateBtn = document.getElementById('generateBtn');
                const originalText = generateBtn.innerHTML;
                
                generateBtn.innerHTML = '<i class="bi bi-hourglass-split"></i> Generating...';
                generateBtn.disabled = true;

                try {
                    // Get inputs
                    const password = document.getElementById('password').value.trim();
                    const finalPassword = [];
                    const selectedHash = this.selectedHash;
                    const iterations = parseInt(document.getElementById('iterations').value);

                    if (iterations < 1 || iterations > 10) {
                        throw new Error('Invalid iteration count');
                    }

                    // Generate hash of files with validation
                    const fileHash = await SecureHashUtils.genFileHash(
                        Array.from(this.selectedFiles), 
                        selectedHash, 
                        iterations
                    );
                    if (fileHash) {
                        finalPassword.push(fileHash);
                    }

                    // Generate hash of questions with validation
                    const questions = this.getQuestions();
                    const questionHash = await SecureHashUtils.genQuestionHash(
                        questions, 
                        selectedHash, 
                        iterations
                    );
                    if (questionHash) {
                        finalPassword.push(questionHash);
                    }

                    // Check if we have any input to work with
                    if (finalPassword.length === 0 && !password) {
                        throw new Error('At least one input is required: password, files, or security questions');
                    }

                    // If no files or questions provided but password exists, use the password itself as input
                    if (finalPassword.length === 0 && password) {
                        finalPassword.push(password);
                    }

                    let finalHash;
                    
                    // Use password as HMAC key if provided, otherwise just combine the hashes
                    if (password) {
                        finalHash = await SecureHashUtils.getHmacDigest(
                            selectedHash, 
                            finalPassword, 
                            password
                        );
                    } else {
                        // If no password provided, just hash the combined inputs
                        const combinedInput = finalPassword.join('');
                        finalHash = await SecureHashUtils.genStringHash(selectedHash, combinedInput);
                    }

                    document.getElementById('generatedPassword').value = finalHash;
                    document.getElementById('copyBtn').disabled = false;

                } catch (error) {
                    console.error('Error generating password:', error);
                    this.showWarning(`Generation failed: ${error.message}`);
                    // Clear any partial results
                    SecureHashUtils.clearSensitiveData(document.getElementById('generatedPassword'));
                } finally {
                    generateBtn.innerHTML = originalText;
                    generateBtn.disabled = false;
                }
            }

            getQuestions() {
                const questions = [];
                ['q1', 'q2', 'q3'].forEach(id => {
                    const value = document.getElementById(id).value.trim();
                    if (value && value.length <= MAX_QUESTION_LENGTH) {
                        questions.push(value);
                    }
                });
                return questions;
            }

            async copyToClipboard() {
                const generatedPassword = document.getElementById('generatedPassword');
                
                try {
                    // Use modern clipboard API if available
                    if (navigator.clipboard && window.isSecureContext) {
                        // Temporarily show password to get its value
                        const wasPassword = generatedPassword.type === 'password';
                        if (wasPassword) {
                            generatedPassword.type = 'text';
                        }
                        
                        await navigator.clipboard.writeText(generatedPassword.value);
                        
                        if (wasPassword) {
                            generatedPassword.type = 'password';
                        }
                    } else {
                        // Fallback for older browsers
                        const wasPassword = generatedPassword.type === 'password';
                        if (wasPassword) {
                            generatedPassword.type = 'text';
                        }
                        
                        generatedPassword.select();
                        document.execCommand('copy');
                        
                        if (wasPassword) {
                            generatedPassword.type = 'password';
                        }
                    }

                    // Show feedback
                    const copyBtn = document.getElementById('copyBtn');
                    const originalText = copyBtn.innerHTML;
                    copyBtn.innerHTML = '<i class="bi bi-check"></i> Copied!';
                    copyBtn.classList.add('btn-success');
                    copyBtn.classList.remove('btn-outline-secondary');
                    
                    // Auto-clear clipboard after 30 seconds for security
                    setTimeout(async () => {
                        if (navigator.clipboard && window.isSecureContext) {
                            await navigator.clipboard.writeText('');
                        }
                    }, 30000);
                    
                    setTimeout(() => {
                        copyBtn.innerHTML = originalText;
                        copyBtn.classList.remove('btn-success');
                        copyBtn.classList.add('btn-outline-secondary');
                    }, 2000);

                } catch (error) {
                    console.error('Copy failed:', error);
                    this.showWarning('Failed to copy to clipboard');
                }
            }

            clearForm() {
                // Clear the auto-clear timer when manually clearing
                if (this.autoClearTimer) {
                    clearTimeout(this.autoClearTimer);
                }
                
                // Securely clear sensitive inputs
                ['password', 'q1', 'q2', 'q3', 'generatedPassword'].forEach(id => {
                    SecureHashUtils.clearSensitiveData(document.getElementById(id));
                });

                // Reset form controls
                document.getElementById('showPasswordCheck').checked = false;
                document.getElementById('md5').checked = true;
                document.getElementById('iterations').value = '1';

                // Clear files
                this.selectedFiles.clear();
                this.updateFileList();
                document.getElementById('fileInput').value = '';

                // Reset hash algorithm
                this.selectedHash = 'md5';

                // Reset password visibility
                this.toggleAllPasswordVisibility(false);

                // Clear clipboard
                if (navigator.clipboard && window.isSecureContext) {
                    navigator.clipboard.writeText('').catch(console.error);
                }

                // Disable copy button
                document.getElementById('copyBtn').disabled = true;

                // Force garbage collection of sensitive data
                if (window.gc && typeof window.gc === 'function') {
                    setTimeout(window.gc, 1000);
                }
                
                // Restart the auto-clear timer
                this.startAutoClearTimer();
            }
        }

        // Initialize the application
        document.addEventListener('DOMContentLoaded', () => {
            // Show security warning if not in secure context
            showSecurityWarning();
            new PasswordHashGenerator();
        });
    </script>
</body>
</html>