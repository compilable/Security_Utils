<?php
// Start session for CSRF protection
session_start();

// Generate CSRF token if not exists
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Security headers
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; font-src 'self' https://cdn.jsdelivr.net; img-src 'self' data: blob:; connect-src 'self' https://cdn.jsdelivr.net; manifest-src 'none'; media-src 'none'; frame-src 'none'; object-src 'none'; base-uri 'self';");
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Cache-Control: no-cache, no-store, must-revalidate");
header("Pragma: no-cache");
header("Expires: 0");
header("Permissions-Policy: geolocation=(), microphone=(), camera=()");

// Configuration
const CYCLE_COUNT = 5;
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB
const MAX_FILES = 10;
const ALLOWED_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
const ALLOWED_HASH_ALGORITHMS = ['md5', 'sha256', 'sha512'];
const DEFAULT_HASH_ALGORITHM = 'md5';

// Use system temp directory for uploads
$uploadDir = sys_get_temp_dir() . '/image_randomizer/';
define('UPLOAD_DIR', $uploadDir);

// Create upload directory if it doesn't exist
if (!file_exists(UPLOAD_DIR)) {
    if (!mkdir(UPLOAD_DIR, 0755, true)) {
        // Fallback to system temp directory directly
        define('UPLOAD_DIR_FALLBACK', sys_get_temp_dir() . '/');
    }
}

// Validate file magic numbers for security
function validateFileMagicNumber($filePath, $expectedMimeType) {
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $detectedMimeType = finfo_file($finfo, $filePath);
    finfo_close($finfo);
    return $detectedMimeType === $expectedMimeType;
}

// Enhanced file validation
function isValidImageFile($filePath) {
    // Check if file exists and is readable
    if (!file_exists($filePath) || !is_file($filePath) || !is_readable($filePath)) {
        return false;
    }
    
    // Get image info
    $imageInfo = getimagesize($filePath);
    if (!$imageInfo || !in_array($imageInfo['mime'], ALLOWED_TYPES)) {
        return false;
    }
    
    // Validate magic numbers match MIME type
    return validateFileMagicNumber($filePath, $imageInfo['mime']);
}

// Rate limiting for file serving
function checkRateLimit() {
    $key = 'file_serve_' . $_SERVER['REMOTE_ADDR'];
    if (!isset($_SESSION[$key])) {
        $_SESSION[$key] = ['count' => 0, 'time' => time()];
    }
    
    $current_time = time();
    if ($current_time - $_SESSION[$key]['time'] > 60) {
        $_SESSION[$key] = ['count' => 0, 'time' => $current_time];
    }
    
    $_SESSION[$key]['count']++;
    return $_SESSION[$key]['count'] <= 30; // Max 30 requests per minute
}

// Hash algorithm helper function
function calculateFileHash($filePath, $algorithm = 'md5') {
    switch (strtolower($algorithm)) {
        case 'md5':
            return md5_file($filePath);
        case 'sha256':
            return hash_file('sha256', $filePath);
        case 'sha512':
            return hash_file('sha512', $filePath);
        default:
            throw new Exception('Unsupported hash algorithm: ' . $algorithm);
    }
}

// Process image randomization
function randomizeImage($imagePath, $cycles = CYCLE_COUNT, $hashAlgorithm = DEFAULT_HASH_ALGORITHM) {
    if (!file_exists($imagePath)) {
        throw new Exception('Image file does not exist');
    }

    // Validate hash algorithm
    if (!in_array(strtolower($hashAlgorithm), ALLOWED_HASH_ALGORITHMS)) {
        throw new Exception('Invalid hash algorithm');
    }

    $originalHash = calculateFileHash($imagePath, $hashAlgorithm);
    $imageInfo = getimagesize($imagePath);
    
    if (!$imageInfo) {
        throw new Exception('Invalid image file');
    }

    // Create image resource based on type
    switch ($imageInfo['mime']) {
        case 'image/jpeg':
            $image = imagecreatefromjpeg($imagePath);
            break;
        case 'image/png':
            $image = imagecreatefrompng($imagePath);
            break;
        case 'image/gif':
            $image = imagecreatefromgif($imagePath);
            break;
        case 'image/webp':
            $image = imagecreatefromwebp($imagePath);
            break;
        default:
            throw new Exception('Unsupported image format');
    }

    if (!$image) {
        throw new Exception('Failed to create image resource');
    }

    $width = imagesx($image);
    $height = imagesy($image);

    // Apply randomization cycles
    for ($cycle = 0; $cycle < $cycles; $cycle++) {
        $stepper = mt_rand(1, 10);
        
        for ($x = 0; $x < $width; $x += $stepper) {
            for ($y = 0; $y < $height; $y += $stepper) {
                if ($x < $width && $y < $height) {
                    $currentColor = imagecolorat($image, $x, $y);
                    $rgb = imagecolorsforindex($image, $currentColor);
                    $newColor = getRandomColor($rgb);
                    $newColorIndex = imagecolorallocate($image, $newColor['red'], $newColor['green'], $newColor['blue']);
                    imagesetpixel($image, $x, $y, $newColorIndex);
                }
            }
        }
    }

    // Save the modified image
    $newPath = $imagePath;
    switch ($imageInfo['mime']) {
        case 'image/jpeg':
            imagejpeg($image, $newPath, 90);
            break;
        case 'image/png':
            imagepng($image, $newPath);
            break;
        case 'image/gif':
            imagegif($image, $newPath);
            break;
        case 'image/webp':
            imagewebp($image, $newPath, 90);
            break;
    }

    imagedestroy($image);
    
    $newHash = calculateFileHash($newPath, $hashAlgorithm);
    return [
        'original_hash' => $originalHash,
        'new_hash' => $newHash,
        'path' => $newPath,
        'hash_algorithm' => strtoupper($hashAlgorithm)
    ];
}

function getRandomColor($rgb, $rangeStepper = 5) {
    $newRgb = [];
    
    foreach (['red', 'green', 'blue'] as $color) {
        $current = $rgb[$color];
        
        if ($rangeStepper > $current) {
            $start = max(0, $current - $rangeStepper);
            $end = min(255, $current + $rangeStepper);
        } else {
            $start = max(0, $current - $rangeStepper);
            $end = $current;
        }
        
        $newRgb[$color] = mt_rand($start, $end);
    }
    
    return $newRgb;
}

// Batch process all images in a folder
function batchRandomizeImages($folderPath, $cycles = CYCLE_COUNT, $hashAlgorithm = DEFAULT_HASH_ALGORITHM, $outputDir = null) {
    // Validate input parameters
    if (!is_dir($folderPath) || !is_readable($folderPath)) {
        throw new Exception('Invalid or unreadable folder path: ' . $folderPath);
    }
    
    if (!in_array(strtolower($hashAlgorithm), ALLOWED_HASH_ALGORITHMS)) {
        throw new Exception('Invalid hash algorithm: ' . $hashAlgorithm);
    }
    
    $cycles = max(1, min(10, intval($cycles)));
    
    // Set output directory (same as input if not specified)
    if ($outputDir === null) {
        $outputDir = $folderPath;
    } elseif (!is_dir($outputDir)) {
        if (!mkdir($outputDir, 0755, true)) {
            throw new Exception('Unable to create output directory: ' . $outputDir);
        }
    }
    
    // Get all image files from the folder
    $imageExtensions = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
    $imageFiles = [];
    
    foreach ($imageExtensions as $ext) {
        $files = glob($folderPath . '/*.' . $ext);
        $files = array_merge($files, glob($folderPath . '/*.' . strtoupper($ext)));
        $imageFiles = array_merge($imageFiles, $files);
    }
    
    if (empty($imageFiles)) {
        throw new Exception('No image files found in folder: ' . $folderPath);
    }
    
    $results = [];
    $errors = [];
    $processed = 0;
    $skipped = 0;
    
    foreach ($imageFiles as $imagePath) {
        try {
            // Validate the image file
            if (!isValidImageFile($imagePath)) {
                $errors[] = "Skipped invalid image: " . basename($imagePath);
                $skipped++;
                continue;
            }
            
            // Determine output path
            $filename = basename($imagePath);
            $outputPath = ($outputDir === $folderPath) ? $imagePath : $outputDir . '/' . $filename;
            
            // If output path is different from input, copy file first
            if ($outputPath !== $imagePath) {
                if (!copy($imagePath, $outputPath)) {
                    $errors[] = "Failed to copy file: " . $filename;
                    $skipped++;
                    continue;
                }
            }
            
            // Process the image
            $result = randomizeImage($outputPath, $cycles, $hashAlgorithm);
            $result['filename'] = $filename;
            $result['original_path'] = $imagePath;
            $result['output_path'] = $outputPath;
            $result['cycles'] = $cycles;
            $results[] = $result;
            $processed++;
            
        } catch (Exception $e) {
            $errors[] = "Error processing " . basename($imagePath) . ": " . $e->getMessage();
            $skipped++;
        }
    }
    
    return [
        'processed' => $processed,
        'skipped' => $skipped,
        'total_files' => count($imageFiles),
        'results' => $results,
        'errors' => $errors,
        'folder_path' => $folderPath,
        'output_dir' => $outputDir,
        'cycles' => $cycles,
        'hash_algorithm' => strtoupper($hashAlgorithm)
    ];
}

// Command line interface for batch processing
function handleCommandLineInterface() {
    global $argv, $argc;
    
    if ($argc < 2) {
        return false; // Not command line usage
    }
    
    $action = $argv[1] ?? '';
    
    if ($action === 'batch' && isset($argv[2])) {
        $folderPath = $argv[2];
        $cycles = isset($argv[3]) ? intval($argv[3]) : CYCLE_COUNT;
        $hashAlgorithm = isset($argv[4]) ? $argv[4] : DEFAULT_HASH_ALGORITHM;
        $outputDir = isset($argv[5]) ? $argv[5] : null;
        
        try {
            echo "Processing images in folder: $folderPath\n";
            echo "Cycles: $cycles, Hash Algorithm: $hashAlgorithm\n";
            if ($outputDir) {
                echo "Output Directory: $outputDir\n";
            }
            echo "----------------------------------------\n";
            
            $batchResult = batchRandomizeImages($folderPath, $cycles, $hashAlgorithm, $outputDir);
            
            echo "Processing completed!\n";
            echo "Total files found: " . $batchResult['total_files'] . "\n";
            echo "Successfully processed: " . $batchResult['processed'] . "\n";
            echo "Skipped: " . $batchResult['skipped'] . "\n";
            
            if (!empty($batchResult['errors'])) {
                echo "\nErrors:\n";
                foreach ($batchResult['errors'] as $error) {
                    echo "- $error\n";
                }
            }
            
            if (!empty($batchResult['results'])) {
                echo "\nProcessed Files:\n";
                foreach ($batchResult['results'] as $result) {
                    echo "- " . $result['filename'] . " (Hash: " . substr($result['new_hash'], 0, 8) . "...)\n";
                }
            }
            
        } catch (Exception $e) {
            echo "Error: " . $e->getMessage() . "\n";
            exit(1);
        }
        
        exit(0);
    }
    
    if ($action === 'help' || $action === '--help' || $action === '-h') {
        echo "Image Randomizer - Batch Processing\n";
        echo "Usage: php image-randomizer.php batch <folder_path> [cycles] [hash_algorithm] [output_dir]\n";
        echo "\n";
        echo "Arguments:\n";
        echo "  folder_path     Path to folder containing images to process\n";
        echo "  cycles          Number of randomization cycles (1-10, default: 5)\n";
        echo "  hash_algorithm  Hash algorithm to use (md5, sha256, sha512, default: md5)\n";
        echo "  output_dir      Output directory (optional, defaults to input folder)\n";
        echo "\n";
        echo "Examples:\n";
        echo "  php image-randomizer.php batch /path/to/images\n";
        echo "  php image-randomizer.php batch /path/to/images 3 sha256\n";
        echo "  php image-randomizer.php batch /path/to/images 5 md5 /path/to/output\n";
        exit(0);
    }
    
    return false;
}

// Check if running from command line
if (php_sapi_name() === 'cli') {
    handleCommandLineInterface();
}

// Handle file upload and processing
$results = [];
$errors = [];

// Handle image serving with enhanced security
if (isset($_GET['serve']) && isset($_GET['file'])) {
    // Rate limiting
    if (!checkRateLimit()) {
        http_response_code(429);
        exit('Rate limit exceeded');
    }
    
    // Sanitize filename - only allow alphanumeric, dots, dashes, underscores
    $filename = preg_replace('/[^a-zA-Z0-9._-]/', '', basename($_GET['file']));
    if (empty($filename) || strlen($filename) > 255) {
        http_response_code(400);
        exit('Invalid filename');
    }
    
    $cleanupDir = defined('UPLOAD_DIR_FALLBACK') ? UPLOAD_DIR_FALLBACK : UPLOAD_DIR;
    $filePath = realpath($cleanupDir . $filename);
    
    // Prevent directory traversal
    if ($filePath === false || strpos($filePath, realpath($cleanupDir)) !== 0) {
        http_response_code(403);
        exit('Access denied');
    }
    
    // Enhanced file validation
    if (isValidImageFile($filePath)) {
        $imageInfo = getimagesize($filePath);
        
        // Security headers for file serving
        header('Content-Type: ' . $imageInfo['mime']);
        header('Content-Length: ' . filesize($filePath));
        header('Cache-Control: private, max-age=1800, no-transform');
        header('X-Content-Type-Options: nosniff');
        header('Content-Disposition: inline; filename="' . htmlspecialchars($filename, ENT_QUOTES, 'UTF-8') . '"');
        
        readfile($filePath);
        exit;
    }
    
    // File not found or invalid
    http_response_code(404);
    exit('File not found');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['images'])) {
    // CSRF protection
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        http_response_code(403);
        $errors[] = 'Invalid CSRF token. Please refresh the page and try again.';
    } else {
        // Rate limiting for uploads
        $upload_key = 'upload_' . $_SERVER['REMOTE_ADDR'];
        if (!isset($_SESSION[$upload_key])) {
            $_SESSION[$upload_key] = ['count' => 0, 'time' => time()];
        }
        
        $current_time = time();
        if ($current_time - $_SESSION[$upload_key]['time'] > 300) { // 5 minutes
            $_SESSION[$upload_key] = ['count' => 0, 'time' => $current_time];
        }
        
        if ($_SESSION[$upload_key]['count'] >= 5) {
            $errors[] = 'Upload rate limit exceeded. Please wait before uploading again.';
        } else {
            $_SESSION[$upload_key]['count']++;
            
            $uploadedFiles = $_FILES['images'];
            $cycles = isset($_POST['cycles']) ? max(1, min(10, intval($_POST['cycles']))) : CYCLE_COUNT;
            $hashAlgorithm = isset($_POST['hashAlgorithm']) && in_array($_POST['hashAlgorithm'], ALLOWED_HASH_ALGORITHMS) 
                ? $_POST['hashAlgorithm'] : DEFAULT_HASH_ALGORITHM;
    
    if (is_array($uploadedFiles['name'])) {
        // Multiple files
        for ($i = 0; $i < count($uploadedFiles['name']); $i++) {
            if ($uploadedFiles['error'][$i] === UPLOAD_ERR_OK) {
                try {
                    processUploadedFile(
                        $uploadedFiles['tmp_name'][$i],
                        $uploadedFiles['name'][$i],
                        $uploadedFiles['type'][$i],
                        $uploadedFiles['size'][$i],
                        $cycles,
                        $hashAlgorithm
                    );
                } catch (Exception $e) {
                    $errors[] = "Error processing {$uploadedFiles['name'][$i]}: " . $e->getMessage();
                }
            }
        }
    } else {
        // Single file
        if ($uploadedFiles['error'] === UPLOAD_ERR_OK) {
            try {
                processUploadedFile(
                    $uploadedFiles['tmp_name'],
                    $uploadedFiles['name'],
                    $uploadedFiles['type'],
                    $uploadedFiles['size'],
                    $cycles,
                    $hashAlgorithm
                );
            } catch (Exception $e) {
                $errors[] = "Error processing {$uploadedFiles['name']}: " . $e->getMessage();
            }
        }
    }
        }
    }
}

// Handle batch processing via web interface (for demo purposes - in production, this might be restricted)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['batch_folder'])) {
    // CSRF protection
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        http_response_code(403);
        $errors[] = 'Invalid CSRF token. Please refresh the page and try again.';
    } else {
        $folderPath = $_POST['batch_folder'];
        $cycles = isset($_POST['batch_cycles']) ? max(1, min(10, intval($_POST['batch_cycles']))) : CYCLE_COUNT;
        $hashAlgorithm = isset($_POST['batch_hashAlgorithm']) && in_array($_POST['batch_hashAlgorithm'], ALLOWED_HASH_ALGORITHMS) 
            ? $_POST['batch_hashAlgorithm'] : DEFAULT_HASH_ALGORITHM;
        
        try {
            $batchResult = batchRandomizeImages($folderPath, $cycles, $hashAlgorithm);
            
            // Convert batch results to the same format as individual results for display
            foreach ($batchResult['results'] as $result) {
                $result['serve_url'] = ''; // No serve URL for local files
                $results[] = $result;
            }
            
            if (!empty($batchResult['errors'])) {
                $errors = array_merge($errors, $batchResult['errors']);
            }
            
            // Add summary message
            $results[] = [
                'filename' => 'BATCH SUMMARY',
                'original_hash' => 'Total Files: ' . $batchResult['total_files'],
                'new_hash' => 'Processed: ' . $batchResult['processed'] . ', Skipped: ' . $batchResult['skipped'],
                'path' => $batchResult['folder_path'],
                'hash_algorithm' => $batchResult['hash_algorithm'],
                'cycles' => $batchResult['cycles'],
                'serve_url' => ''
            ];
            
        } catch (Exception $e) {
            $errors[] = "Batch processing error: " . $e->getMessage();
        }
    }
}

function processUploadedFile($tmpName, $fileName, $fileType, $fileSize, $cycles, $hashAlgorithm = DEFAULT_HASH_ALGORITHM) {
    global $results;
    
    // Validate file exists and is uploaded file
    if (!is_uploaded_file($tmpName)) {
        throw new Exception('Invalid file upload.');
    }
    
    // Sanitize filename - remove dangerous characters
    $fileName = preg_replace('/[^a-zA-Z0-9._-]/', '_', $fileName);
    if (empty($fileName)) {
        throw new Exception('Invalid filename.');
    }
    
    // Validate file type using MIME type
    if (!in_array($fileType, ALLOWED_TYPES)) {
        throw new Exception('Invalid file type. Only JPEG, PNG, GIF, and WebP are allowed.');
    }
    
    // Validate file size
    if ($fileSize > MAX_FILE_SIZE || $fileSize <= 0) {
        throw new Exception('File size is invalid or exceeds maximum allowed size.');
    }
    
    // Validate magic numbers after file is moved
    if (!validateFileMagicNumber($tmpName, $fileType)) {
        throw new Exception('File content does not match declared type.');
    }
    
    // Generate secure unique filename
    $extension = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));
    $allowedExtensions = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
    if (!in_array($extension, $allowedExtensions)) {
        throw new Exception('Invalid file extension.');
    }
    
    $uniqueName = bin2hex(random_bytes(16)) . '_' . time() . '.' . $extension;
    
    // Use appropriate upload directory
    $uploadPath = defined('UPLOAD_DIR_FALLBACK') ? UPLOAD_DIR_FALLBACK . $uniqueName : UPLOAD_DIR . $uniqueName;
    
    // Move uploaded file
    if (!move_uploaded_file($tmpName, $uploadPath)) {
        throw new Exception('Failed to upload file.');
    }
    
    // Process the image
    $result = randomizeImage($uploadPath, $cycles, $hashAlgorithm);
    $result['filename'] = $fileName;
    $result['processed_filename'] = $uniqueName;
    $result['cycles'] = $cycles;
    $result['serve_url'] = '?serve=1&file=' . urlencode($uniqueName); // Add serve URL
    $results[] = $result;
}

// Clean up old files (files older than 1 hour)
$cleanupDir = defined('UPLOAD_DIR_FALLBACK') ? UPLOAD_DIR_FALLBACK : UPLOAD_DIR;
$files = glob($cleanupDir . '*');
if ($files) {
    $now = time();
    foreach ($files as $file) {
        if (is_file($file) && ($now - filemtime($file)) > 3600) {
            @unlink($file); // Use @ to suppress warnings
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Image Randomizer</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-9ndCyUaIbzAi2FUVXJi0CjmCapSmO7SnpJef0486qhLnuZ2cdeRhO02iuK6FUUVM" crossorigin="anonymous">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet" crossorigin="anonymous">
    <style>
        :root {
            --bg-color: #f8f9fa;
            --card-bg: #ffffff;
            --text-color: #212529;
            --border-color: #dee2e6;
            --muted-text: #6c757d;
        }
        
        [data-theme="dark"] {
            --bg-color: #121212;
            --card-bg: #1e1e1e;
            --text-color: #ffffff;
            --border-color: #404040;
            --muted-text: #aaaaaa;
        }
        
        body {
            background-color: var(--bg-color);
            color: var(--text-color);
            transition: background-color 0.3s ease, color 0.3s ease;
        }
        
        .card {
            background-color: var(--card-bg);
            border-color: var(--border-color);
            color: var(--text-color);
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
        
        .drop-zone {
            border: 2px dashed var(--border-color);
            border-radius: 0.5rem;
            padding: 2rem;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s ease;
            background-color: var(--card-bg);
        }
        
        .drop-zone:hover, .drop-zone.dragover {
            border-color: #0d6efd;
            background-color: rgba(13, 110, 253, 0.1);
        }
        
        .preview-container {
            max-height: 400px;
            overflow-y: auto;
        }
        
        .preview-item {
            position: relative;
            display: inline-block;
            margin: 0.5rem;
        }
        
        .preview-image {
            max-width: 150px;
            max-height: 150px;
            border-radius: 0.375rem;
            border: 1px solid var(--border-color);
        }
        
        .remove-btn {
            position: absolute;
            top: -8px;
            right: -8px;
            width: 24px;
            height: 24px;
            border-radius: 50%;
            background: #dc3545;
            border: none;
            color: white;
            font-size: 12px;
            cursor: pointer;
        }
        
        .hash-display {
            font-family: monospace;
            font-size: 0.875rem;
            word-break: break-all;
        }
    </style>
</head>
<body>
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
            <div class="col-lg-10">
                <div class="card">
                    <div class="card-header bg-primary text-white d-flex justify-content-between align-items-center">
                        <h4 class="mb-0"><i class="bi bi-image"></i> Image Randomizer</h4>
                        <small>Modify images by randomizing pixels</small>
                    </div>
                    <div class="card-body">
                        <!-- Upload Form -->
                        <form id="uploadForm" method="post" enctype="multipart/form-data">
                            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
                            <div class="mb-4">
                                <label class="form-label fw-bold">Select Images:</label>
                                <div class="drop-zone" id="dropZone">
                                    <i class="bi bi-cloud-upload fs-1 text-muted"></i>
                                    <p class="mt-2 mb-2">Drag and drop images here or click to select</p>
                                    <p class="text-muted small">Supports JPEG, PNG, GIF, WebP • Max <?php echo MAX_FILE_SIZE / (1024*1024); ?>MB per file • Max <?php echo MAX_FILES; ?> files</p>
                                    <input type="file" id="fileInput" name="images[]" multiple accept="image/*" style="display: none;">
                                </div>
                                <div id="previewContainer" class="preview-container mt-3"></div>
                            </div>

                            <div class="mb-4">
                                <label for="cycles" class="form-label fw-bold">Randomization Cycles:</label>
                                <select class="form-select" id="cycles" name="cycles">
                                    <?php for($i = 1; $i <= 10; $i++): ?>
                                        <option value="<?php echo $i; ?>" <?php echo $i === CYCLE_COUNT ? 'selected' : ''; ?>><?php echo $i; ?></option>
                                    <?php endfor; ?>
                                </select>
                                <div class="form-text">More cycles = more randomization (but longer processing time)</div>
                            </div>

                            <div class="mb-4">
                                <label class="form-label fw-bold">Hashing Algorithm:</label>
                                <div class="form-check">
                                    <input class="form-check-input" type="radio" name="hashAlgorithm" id="md5" value="md5" checked>
                                    <label class="form-check-label" for="md5">MD5</label>
                                </div>
                                <div class="form-check">
                                    <input class="form-check-input" type="radio" name="hashAlgorithm" id="sha256" value="sha256">
                                    <label class="form-check-label" for="sha256">SHA 256</label>
                                </div>
                                <div class="form-check">
                                    <input class="form-check-input" type="radio" name="hashAlgorithm" id="sha512" value="sha512">
                                    <label class="form-check-label" for="sha512">SHA 512</label>
                                </div>
                                <div class="form-text">Algorithm used to generate file hash fingerprints</div>
                            </div>

                            <div class="text-center">
                                <button type="submit" class="btn btn-primary btn-lg" id="processBtn" disabled>
                                    <i class="bi bi-gear"></i> Process Images
                                </button>
                            </div>
                        </form>

                        <!-- Batch Processing Form -->
                        <hr class="my-4">
                        <h5><i class="bi bi-folder"></i> Batch Process Folder</h5>
                        <div class="alert alert-warning">
                            <i class="bi bi-exclamation-triangle"></i> 
                            <strong>Warning:</strong> This feature processes local server folders. Use with caution in production environments.
                        </div>
                        
                        <form method="post">
                            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
                            <div class="mb-3">
                                <label for="batch_folder" class="form-label fw-bold">Folder Path:</label>
                                <input type="text" class="form-control" id="batch_folder" name="batch_folder" 
                                       placeholder="/path/to/image/folder" required>
                                <div class="form-text">Enter the full path to a folder containing image files</div>
                            </div>

                            <div class="row">
                                <div class="col-md-6">
                                    <label for="batch_cycles" class="form-label fw-bold">Randomization Cycles:</label>
                                    <select class="form-select" id="batch_cycles" name="batch_cycles">
                                        <?php for($i = 1; $i <= 10; $i++): ?>
                                            <option value="<?php echo $i; ?>" <?php echo $i === CYCLE_COUNT ? 'selected' : ''; ?>><?php echo $i; ?></option>
                                        <?php endfor; ?>
                                    </select>
                                </div>
                                
                                <div class="col-md-6">
                                    <label class="form-label fw-bold">Hashing Algorithm:</label>
                                    <div class="form-check">
                                        <input class="form-check-input" type="radio" name="batch_hashAlgorithm" id="batch_md5" value="md5" checked>
                                        <label class="form-check-label" for="batch_md5">MD5</label>
                                    </div>
                                    <div class="form-check">
                                        <input class="form-check-input" type="radio" name="batch_hashAlgorithm" id="batch_sha256" value="sha256">
                                        <label class="form-check-label" for="batch_sha256">SHA 256</label>
                                    </div>
                                    <div class="form-check">
                                        <input class="form-check-input" type="radio" name="batch_hashAlgorithm" id="batch_sha512" value="sha512">
                                        <label class="form-check-label" for="batch_sha512">SHA 512</label>
                                    </div>
                                </div>
                            </div>

                            <div class="text-center mt-3">
                                <button type="submit" class="btn btn-warning btn-lg">
                                    <i class="bi bi-folder-fill"></i> Process Folder
                                </button>
                            </div>
                        </form>

                        <!-- Results -->
                        <?php if (!empty($results) || !empty($errors)): ?>
                        <hr class="my-4">
                        <h5><i class="bi bi-check-circle-fill text-success"></i> Processing Results</h5>
                        
                        <?php foreach ($errors as $error): ?>
                        <div class="alert alert-danger">
                            <i class="bi bi-exclamation-triangle"></i> <?php echo htmlspecialchars($error); ?>
                        </div>
                        <?php endforeach; ?>

                        <?php foreach ($results as $result): ?>
                        <div class="card mb-3">
                            <div class="card-body">
                                <div class="row">
                                    <div class="col-md-6">
                                        <h6><i class="bi bi-file-earmark-image"></i> <?php echo htmlspecialchars($result['filename']); ?></h6>
                                        <p class="text-muted small mb-2">Processed with <?php echo $result['cycles']; ?> cycle(s) • <?php echo isset($result['hash_algorithm']) ? $result['hash_algorithm'] : 'MD5'; ?> Hash</p>
                                        
                                        <div class="mb-2">
                                            <strong>Original Hash:</strong><br>
                                            <span class="hash-display text-muted"><?php echo $result['original_hash']; ?></span>
                                        </div>
                                        
                                        <div class="mb-2">
                                            <strong>New Hash:</strong><br>
                                            <span class="hash-display text-success"><?php echo $result['new_hash']; ?></span>
                                        </div>
                                    </div>
                                    <div class="col-md-6 text-center">
                                        <img src="<?php echo htmlspecialchars($result['serve_url']); ?>" 
                                             alt="Processed image" 
                                             class="img-fluid rounded shadow-sm" 
                                             style="max-height: 200px;">
                                        
                                        <div class="mt-2">
                                            <a href="<?php echo htmlspecialchars($result['serve_url']); ?>" 
                                               download="<?php echo htmlspecialchars($result['filename']); ?>" 
                                               class="btn btn-outline-primary btn-sm">
                                                <i class="bi bi-download"></i> Download
                                            </a>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <?php endforeach; ?>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- Info Card -->
                <div class="card mt-4">
                    <div class="card-header">
                        <h6 class="mb-0"><i class="bi bi-info-circle"></i> How it works</h6>
                    </div>
                    <div class="card-body">
                        <ul class="mb-0">
                            <li><strong>Web Upload:</strong> Upload one or more images (JPEG, PNG, GIF, WebP)</li>
                            <li><strong>Batch Processing:</strong> Process entire folders of images via web interface or command line</li>
                            <li>The algorithm randomly modifies pixel colors across the image</li>
                            <li>Each cycle applies more randomization with varying step sizes</li>
                            <li>Hash fingerprints change, creating unique file signatures</li>
                            <li>Original image structure is preserved but modified</li>
                            <li>Uploaded files are automatically deleted after 1 hour for security</li>
                        </ul>
                        
                        <div class="mt-3">
                            <h6><i class="bi bi-terminal"></i> Command Line Usage</h6>
                            <div class="bg-dark text-light p-2 rounded">
                                <code>php image-randomizer.php batch /path/to/images [cycles] [hash_algorithm] [output_dir]</code>
                            </div>
                            <small class="text-muted">Example: <code>php image-randomizer.php batch ./photos 3 sha256</code></small>
                        </div>
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
                            &copy; <?php echo date('Y'); ?> Image Randomizer - Released under the 
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
    <script>
        // Theme management
        function initializeTheme() {
            const savedTheme = localStorage.getItem('theme') || 'light';
            setTheme(savedTheme);
            
            const themeToggle = document.getElementById('themeToggle');
            themeToggle.checked = savedTheme === 'dark';
            
            themeToggle.addEventListener('change', (e) => {
                const theme = e.target.checked ? 'dark' : 'light';
                setTheme(theme);
                localStorage.setItem('theme', theme);
            });
        }
        
        function setTheme(theme) {
            document.documentElement.setAttribute('data-theme', theme);
            updateThemeLabel(theme);
        }
        
        function updateThemeLabel(theme) {
            const themeLabel = document.getElementById('themeLabel');
            if (theme === 'dark') {
                themeLabel.innerHTML = '<i class="bi bi-moon-fill"></i> Dark';
            } else {
                themeLabel.innerHTML = '<i class="bi bi-sun-fill"></i> Light';
            }
        }

        // File handling
        let selectedFiles = [];
        const maxFiles = <?php echo MAX_FILES; ?>;
        const maxFileSize = <?php echo MAX_FILE_SIZE; ?>;

        function initializeFileHandling() {
            const dropZone = document.getElementById('dropZone');
            const fileInput = document.getElementById('fileInput');
            const previewContainer = document.getElementById('previewContainer');
            const processBtn = document.getElementById('processBtn');

            dropZone.addEventListener('click', () => fileInput.click());
            
            dropZone.addEventListener('dragover', (e) => {
                e.preventDefault();
                dropZone.classList.add('dragover');
            });
            
            dropZone.addEventListener('dragleave', () => {
                dropZone.classList.remove('dragover');
            });
            
            dropZone.addEventListener('drop', (e) => {
                e.preventDefault();
                dropZone.classList.remove('dragover');
                handleFiles(e.dataTransfer.files);
            });
            
            fileInput.addEventListener('change', (e) => {
                handleFiles(e.target.files);
            });
        }

        function handleFiles(files) {
            const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
            
            for (let file of files) {
                if (selectedFiles.length >= maxFiles) {
                    showAlert('Maximum ' + maxFiles + ' files allowed', 'warning');
                    break;
                }
                
                if (!allowedTypes.includes(file.type)) {
                    showAlert('File ' + file.name + ' is not a supported image format', 'danger');
                    continue;
                }
                
                if (file.size > maxFileSize) {
                    showAlert('File ' + file.name + ' exceeds maximum size', 'danger');
                    continue;
                }
                
                selectedFiles.push(file);
            }
            
            updatePreview();
            updateProcessButton();
        }

        function updatePreview() {
            const previewContainer = document.getElementById('previewContainer');
            previewContainer.innerHTML = '';
            
            selectedFiles.forEach((file, index) => {
                const previewItem = document.createElement('div');
                previewItem.className = 'preview-item';
                
                const img = document.createElement('img');
                img.className = 'preview-image';
                img.src = URL.createObjectURL(file);
                img.title = file.name;
                
                const removeBtn = document.createElement('button');
                removeBtn.className = 'remove-btn';
                removeBtn.innerHTML = '×';
                removeBtn.onclick = () => removeFile(index);
                
                const fileName = document.createElement('div');
                fileName.className = 'small text-muted text-center mt-1';
                fileName.textContent = file.name.length > 15 ? file.name.substring(0, 15) + '...' : file.name;
                
                previewItem.appendChild(img);
                previewItem.appendChild(removeBtn);
                previewItem.appendChild(fileName);
                previewContainer.appendChild(previewItem);
            });
        }

        function removeFile(index) {
            selectedFiles.splice(index, 1);
            updatePreview();
            updateProcessButton();
        }

        function updateProcessButton() {
            const processBtn = document.getElementById('processBtn');
            processBtn.disabled = selectedFiles.length === 0;
        }

        function showAlert(message, type = 'info') {
            const alertDiv = document.createElement('div');
            alertDiv.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
            alertDiv.style.top = '20px';
            alertDiv.style.right = '20px';
            alertDiv.style.zIndex = '9999';
            alertDiv.innerHTML = `
                ${message}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            `;
            document.body.appendChild(alertDiv);
            
            setTimeout(() => {
                if (alertDiv.parentNode) {
                    alertDiv.parentNode.removeChild(alertDiv);
                }
            }, 5000);
        }

        // Form submission
        document.getElementById('uploadForm').addEventListener('submit', function(e) {
            if (selectedFiles.length === 0) {
                e.preventDefault();
                showAlert('Please select at least one image', 'warning');
                return;
            }
            
            // Create FormData with selected files
            const formData = new FormData(this);
            formData.delete('images[]'); // Remove existing files
            
            selectedFiles.forEach(file => {
                formData.append('images[]', file);
            });
            
            const processBtn = document.getElementById('processBtn');
            processBtn.innerHTML = '<i class="bi bi-hourglass-split"></i> Processing...';
            processBtn.disabled = true;
        });

        // Initialize everything
        document.addEventListener('DOMContentLoaded', function() {
            initializeTheme();
            initializeFileHandling();
        });
    </script>
</body>
</html>