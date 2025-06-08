<?php
session_start();
require_once 'env_loader.php';

loadDotEnv(__DIR__ . '/.env');

// Configuration from environment variables
define('GITHUB_OWNER', $_ENV['GITHUB_OWNER'] ?? null);
define('GITHUB_REPO', $_ENV['GITHUB_REPO'] ?? null);
define('DATA_FILE', $_ENV['DATA_FILE'] ?? null);
define('ADMIN_USERNAME', $_ENV['ADMIN_USERNAME'] ?? false);
define('ADMIN_PASSWORD', $_ENV['ADMIN_PASSWORD'] ?? false);
define('DEBUG_MODE', ($_ENV['DEBUG_MODE'] ?? 'false') === 'true');

// Initialize session variables
if (!isset($_SESSION['content'])) {
    $_SESSION['content'] = getDefaultContent();
}
if (!isset($_SESSION['isAdmin'])) {
    $_SESSION['isAdmin'] = false;
}
if (!isset($_SESSION['editMode'])) {
    $_SESSION['editMode'] = false;
}
if (!isset($_SESSION['activeSection'])) {
    $_SESSION['activeSection'] = 'personal';
}
if (!isset($_SESSION['showLogin'])) {
    $_SESSION['showLogin'] = false;
}

// ===================================
// ROBUST SAVE SYSTEM - MAIN HANDLER
// ===================================

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    handleRobustSave();
}

function handleRobustSave()
{
    $action = $_POST['action'] ?? '';

    // Simple login handler with optional GitHub token
    if ($action === 'login') {
        $username = $_POST['username'] ?? '';
        $password = $_POST['password'] ?? '';
        $githubToken = $_POST['github_token'] ?? '';

        // Check basic credentials first
        if ($username !== ADMIN_USERNAME || $password !== ADMIN_PASSWORD) {
            $GLOBALS['loginError'] = 'Invalid username or password!';
            error_log("❌ Login failed: Invalid credentials");
            return;
        }

        // Determine which token to use
        $tokenToUse = null;
        $tokenSource = '';

        if (!empty($githubToken)) {
            // Admin provided a token, use it
            $tokenToUse = $githubToken;
            $tokenSource = 'admin-provided';
        } else {
            // Check if .env token is available
            $envToken = getEnvGitHubToken();
            if ($envToken && $envToken !== 'your_github_token_here') {
                $tokenToUse = $envToken;
                $tokenSource = 'env-file';
            }
        }

        if (!$tokenToUse) {
            $GLOBALS['loginError'] = 'GitHub token is required! Either provide one or configure .env file.';
            error_log("❌ Login failed: No GitHub token available");
            return;
        }

        // Verify the token works
        if (verifyGitHubToken($tokenToUse)) {
            $_SESSION['isAdmin'] = true;
            $_SESSION['showLogin'] = false;

            // Only store admin-provided tokens in session
            if ($tokenSource === 'admin-provided') {
                $_SESSION['github_token'] = $tokenToUse;
                error_log("✅ Admin login successful with admin-provided GitHub token");
            } else {
                error_log("✅ Admin login successful using .env GitHub token");
            }
        } else {
            $GLOBALS['loginError'] = 'Invalid GitHub token or no repository access!';
            error_log("❌ Login failed: Invalid GitHub token ($tokenSource)");
        }
        return;
    }

    // Show login
    if ($action === 'show_login') {
        $_SESSION['showLogin'] = true;
        return;
    }

    // Logout
    if ($action === 'logout') {
        $_SESSION['isAdmin'] = false;
        $_SESSION['editMode'] = false;
        // Security: Clear GitHub token on logout
        unset($_SESSION['github_token']);
        error_log("🔐 Admin logged out - GitHub token cleared");
        return;
    }

    // Navigation
    if ($action === 'navigate') {
        $_SESSION['activeSection'] = $_POST['section'];
        return;
    }

    // Toggle edit mode
    if ($action === 'toggle_edit') {
        $_SESSION['editMode'] = !$_SESSION['editMode'];
        return;
    }

    // ===================================
    // ROBUST SAVE TO GITHUB - SINGLE PATH
    // ===================================
    if ($action === 'robust_save' && $_SESSION['isAdmin'] && $_SESSION['editMode']) {

        // Clear any output buffers and prevent any HTML output
        while (ob_get_level()) {
            ob_end_clean();
        }
        ob_start();

        // Set JSON headers
        header('Content-Type: application/json');
        header('Cache-Control: no-cache, must-revalidate');

        // Log everything for debugging (but don't output to browser)
        error_log('🚀 ROBUST SAVE STARTED');
        error_log('📊 POST data received:');
        error_log('📊 Raw $_POST: ' . print_r($_POST, true));
        error_log('📊 Total POST fields: ' . count($_POST));

        try {
            // Step 1: Get current session content as base
            $content = $_SESSION['content'];
            error_log('📊 Base content loaded, sections: ' . count($content));

            // Step 2: Apply ALL form changes to content - SIMPLIFIED APPROACH
            $fieldsUpdated = 0;
            $fieldsProcessed = 0;
            $unrecognizedFields = [];

            // Process $_POST data with a recursive approach
            foreach ($_POST as $fieldName => $value) {
                if ($fieldName === 'action') {
                    continue;
                }

                try {
                    $fieldsProcessed++;
                    error_log("🔄 Processing: $fieldName");

                    // Convert nested arrays back to field names and process them
                    $fieldsFromNested = flattenPostData($fieldName, $value);

                    foreach ($fieldsFromNested as $flatFieldName => $flatValue) {
                        error_log("🔍 Flattened: $flatFieldName = '$flatValue'");

                        if (updateSingleField($content, $flatFieldName, $flatValue)) {
                            $fieldsUpdated++;
                            error_log("✅ Updated: $flatFieldName = '$flatValue'");
                        } else {
                            $unrecognizedFields[] = $flatFieldName;
                            error_log("❌ Failed to update: $flatFieldName");
                        }
                    }

                } catch (Exception $fieldError) {
                    error_log("❌ Error processing field $fieldName: " . $fieldError->getMessage());
                    $unrecognizedFields[] = $fieldName;
                }
            }

            error_log("📊 Total fields processed: $fieldsProcessed");
            error_log("📊 Total fields updated: $fieldsUpdated");

            if (!empty($unrecognizedFields)) {
                error_log("❌ Unrecognized fields: " . implode(', ', $unrecognizedFields));
            }

            // Step 3: Validate content has data
            if (empty($content) || !isset($content['personal']['name'])) {
                throw new Exception('Content validation failed - no personal name found');
            }

            error_log("📊 Validation passed. Personal name: " . $content['personal']['name']);

            // Step 4: Update session with new content
            $_SESSION['content'] = $content;
            error_log("✅ Session updated successfully");

            // Step 5: Save to GitHub
            $gitHubResult = saveDirectlyToGitHub($content);

            if ($gitHubResult['success']) {
                error_log("✅ GitHub save successful!");

                // Clean output buffer and send only JSON
                ob_clean();
                echo json_encode([
                    'success' => true,
                    'message' => '✅ Successfully saved to GitHub!',
                    'fields_processed' => $fieldsProcessed,
                    'fields_updated' => $fieldsUpdated,
                    'unrecognized_fields' => $unrecognizedFields,
                    'github_sha' => substr($gitHubResult['sha'], 0, 8)
                ]);
            } else {
                throw new Exception('GitHub save failed: ' . $gitHubResult['error']);
            }

        } catch (Exception $e) {
            error_log("❌ ROBUST SAVE FAILED: " . $e->getMessage());

            // Clean output buffer and send only JSON
            ob_clean();
            echo json_encode([
                'success' => false,
                'message' => '❌ Save failed: ' . $e->getMessage(),
                'fields_processed' => $fieldsProcessed ?? 0,
                'fields_updated' => $fieldsUpdated ?? 0,
                'unrecognized_fields' => $unrecognizedFields ?? []
            ]);
        }

        ob_end_flush();
        exit(); // Important: Stop execution after JSON response
    }

    // Handle other operations (add/remove items)
    handleOtherOperations($action);
}

// ===================================
// COMPLETE FIELD UPDATER WITH ALL PATTERNS
// ===================================
function updateSingleField(&$content, $fieldName, $value)
{
    error_log("🔍 Processing field: '$fieldName' = '$value'");

    // Personal fields: personal[name], personal[title], etc. (including profileImage)
    if (preg_match('/^personal\[([^\]]+)\]$/', $fieldName, $matches)) {
        $key = $matches[1];
        // Handle profileImage specially - don't overwrite with empty values
        if ($key === 'profileImage' && empty($value)) {
            error_log("⚠️ Skipping empty profileImage update");
            return false;
        }
        $content['personal'][$key] = $value;
        error_log("✅ Updated personal[$key] = " . (strlen($value) > 50 ? substr($value, 0, 50) . '...' : "'$value'"));
        return true;
    }

    // Advocacy simple fields: advocacy[title], advocacy[issue], advocacy[myActions]
    if (preg_match('/^advocacy\[([^\]]+)\]$/', $fieldName, $matches)) {
        $key = $matches[1];
        if (in_array($key, ['title', 'issue', 'myActions'])) {
            $content['advocacy'][$key] = $value;
            error_log("✅ Updated advocacy[$key] = '$value'");
            return true;
        }
    }

    // Advocacy array fields: advocacy[causes][0], advocacy[effects][1], advocacy[solutions][2]
    if (preg_match('/^advocacy\[([^\]]+)\]\[(\d+)\]$/', $fieldName, $matches)) {
        $arrayKey = $matches[1]; // causes, effects, solutions
        $index = (int) $matches[2];
        if (in_array($arrayKey, ['causes', 'effects', 'solutions'])) {
            if (!isset($content['advocacy'][$arrayKey])) {
                $content['advocacy'][$arrayKey] = [];
            }
            $content['advocacy'][$arrayKey][$index] = $value;
            error_log("✅ Updated advocacy[$arrayKey][$index] = '$value'");
            return true;
        }
    }

    // Education fields: education[college][title], etc.
    if (preg_match('/^education\[([^\]]+)\]\[([^\]]+)\]$/', $fieldName, $matches)) {
        $eduKey = $matches[1];
        $field = $matches[2];
        if (isset($content['education'][$eduKey])) {
            $content['education'][$eduKey][$field] = $value;
            error_log("✅ Updated education[$eduKey][$field] = '$value'");
            return true;
        } else {
            error_log("❌ Education key '$eduKey' not found");
        }
    }

    // Family title fields: family[father][title]
    if (preg_match('/^family\[([^\]]+)\]\[title\]$/', $fieldName, $matches)) {
        $familyKey = $matches[1];
        if (isset($content['family'][$familyKey])) {
            $content['family'][$familyKey]['title'] = $value;
            error_log("✅ Updated family[$familyKey][title] = '$value'");
            return true;
        } else {
            error_log("❌ Family key '$familyKey' not found");
            return false;
        }
    }

    // Family fields: family[father][list][0][name], etc.
    if (preg_match('/^family\[([^\]]+)\]\[list\]\[(\d+)\]\[([^\]]+)\]$/', $fieldName, $matches)) {
        $familyKey = $matches[1];
        $index = (int) $matches[2];
        $field = $matches[3];

        // Ensure the family structure exists
        if (!isset($content['family'][$familyKey])) {
            error_log("❌ Family key '$familyKey' not found");
            return false;
        }

        if (!isset($content['family'][$familyKey]['list'])) {
            error_log("❌ Family list for '$familyKey' not found");
            return false;
        }

        if (!isset($content['family'][$familyKey]['list'][$index])) {
            error_log("❌ Family member index $index for '$familyKey' not found");
            return false;
        }

        // Handle image fields specially - don't overwrite with empty values
        if ($field === 'image' && empty($value)) {
            error_log("⚠️ Skipping empty image update for family[$familyKey][list][$index][image]");
            return false;
        }

        $content['family'][$familyKey]['list'][$index][$field] = $value;
        $logValue = ($field === 'image' && strlen($value) > 50) ? substr($value, 0, 50) . '...' : "'$value'";
        error_log("✅ Updated family[$familyKey][list][$index][$field] = $logValue");
        return true;
    }

    // Friends fields: friends[school][title], friends[school][description]
    if (preg_match('/^friends\[([^\]]+)\]\[([^\]]+)\]$/', $fieldName, $matches)) {
        $friendKey = $matches[1];
        $field = $matches[2];
        if (isset($content['friends'][$friendKey]) && $field !== 'list') {
            $content['friends'][$friendKey][$field] = $value;
            error_log("✅ Updated friends[$friendKey][$field] = '$value'");
            return true;
        }
    }

    // Friends list fields: friends[school][list][0][name], friends[school][list][0][image]
    if (preg_match('/^friends\[([^\]]+)\]\[list\]\[(\d+)\]\[([^\]]+)\]$/', $fieldName, $matches)) {
        $friendKey = $matches[1];
        $index = (int) $matches[2];
        $field = $matches[3];
        if (isset($content['friends'][$friendKey]['list'][$index])) {
            // Handle image fields specially - don't overwrite with empty values
            if ($field === 'image' && empty($value)) {
                error_log("⚠️ Skipping empty image update for friends[$friendKey][list][$index][image]");
                return false;
            }
            $content['friends'][$friendKey]['list'][$index][$field] = $value;
            $logValue = ($field === 'image' && strlen($value) > 50) ? substr($value, 0, 50) . '...' : "'$value'";
            error_log("✅ Updated friends[$friendKey][list][$index][$field] = $logValue");
            return true;
        }
    }

    // Collections: collections[0][name], collections[0][icon], collections[0][description]
    if (preg_match('/^collections\[(\d+)\]\[([^\]]+)\]$/', $fieldName, $matches)) {
        $index = (int) $matches[1];
        $field = $matches[2];
        if (isset($content['collections'][$index])) {
            $content['collections'][$index][$field] = $value;
            error_log("✅ Updated collections[$index][$field] = '$value'");
            return true;
        }
    }

    // Achievements: achievements[0][title], etc.
    if (preg_match('/^achievements\[(\d+)\]\[([^\]]+)\]$/', $fieldName, $matches)) {
        $index = (int) $matches[1];
        $field = $matches[2];
        if (isset($content['achievements'][$index])) {
            $content['achievements'][$index][$field] = $value;
            error_log("✅ Updated achievements[$index][$field] = '$value'");
            return true;
        }
    }

    // Gallery: gallery[0][title], gallery[0][description], gallery[0][image]
    if (preg_match('/^gallery\[(\d+)\]\[([^\]]+)\]$/', $fieldName, $matches)) {
        $index = (int) $matches[1];
        $field = $matches[2];
        if (isset($content['gallery'][$index])) {
            // Handle image fields specially - don't overwrite with empty values
            if ($field === 'image' && empty($value)) {
                error_log("⚠️ Skipping empty image update for gallery[$index][image]");
                return false;
            }
            $content['gallery'][$index][$field] = $value;
            $logValue = ($field === 'image' && strlen($value) > 50) ? substr($value, 0, 50) . '...' : "'$value'";
            error_log("✅ Updated gallery[$index][$field] = $logValue");
            return true;
        }
    }

    error_log("❌ Field not recognized: '$fieldName'");
    return false; // Field not recognized
}

// ===================================
// HELPER FUNCTION TO FLATTEN NESTED POST DATA
// ===================================
function flattenPostData($prefix, $data)
{
    $result = [];

    if (!is_array($data)) {
        // Base case: it's a simple value
        $result[$prefix] = $data;
    } else {
        // Recursive case: it's an array
        foreach ($data as $key => $value) {
            $newPrefix = $prefix . '[' . $key . ']';
            $flattened = flattenPostData($newPrefix, $value);
            $result = array_merge($result, $flattened);
        }
    }

    return $result;
}

// ===================================
// GITHUB TOKEN VERIFICATION
// ===================================
function verifyGitHubToken($token)
{
    if (empty($token)) {
        return false;
    }

    try {
        $url = 'https://api.github.com/repos/' . GITHUB_OWNER . '/' . GITHUB_REPO;
        $headers = [
            'Authorization: token ' . $token,
            'Accept: application/vnd.github.v3+json',
            'User-Agent: Personal-Website-PHP'
        ];

        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'header' => implode("\r\n", $headers),
                'timeout' => 10,
                'ignore_errors' => true
            ]
        ]);

        $response = @file_get_contents($url, false, $context);

        // Check HTTP status code
        $httpCode = 0;
        if (isset($http_response_header)) {
            foreach ($http_response_header as $header) {
                if (preg_match('/HTTP\/\d\.\d\s+(\d+)/', $header, $matches)) {
                    $httpCode = (int) $matches[1];
                    break;
                }
            }
        }

        // Token is valid if we get 200 (success) response
        if ($httpCode === 200) {
            error_log("✅ GitHub token verified successfully");
            return true;
        } else {
            error_log("❌ GitHub token verification failed with HTTP $httpCode");
            return false;
        }
    } catch (Exception $e) {
        error_log("❌ GitHub token verification error: " . $e->getMessage());
        return false;
    }
}

// ===================================
// GITHUB TOKEN HELPER FUNCTIONS
// ===================================
function getEnvGitHubToken()
{
    return $_ENV['GITHUB_TOKEN'] ?? null;
}

function getAdminGitHubToken()
{
    return $_SESSION['github_token'] ?? null;
}

function getGitHubTokenForReading()
{
    // For reading operations, prefer .env token so visitors can see content
    $envToken = getEnvGitHubToken();
    if ($envToken && $envToken !== 'your_github_token_here') {
        return $envToken;
    }

    // Fallback to admin token if available
    return getAdminGitHubToken();
}

function getGitHubTokenForWriting()
{
    // For writing operations, require admin token for security
    $adminToken = getAdminGitHubToken();
    if ($adminToken) {
        return $adminToken;
    }

    // Fallback to .env token only if no admin token (for initial setup)
    $envToken = getEnvGitHubToken();
    if ($envToken && $envToken !== 'your_github_token_here') {
        return $envToken;
    }

    return null;
}
// ===================================
// DIRECT GITHUB SAVE - NO SYNC INTERFERENCE
// ===================================
function saveDirectlyToGitHub($content)
{
    $githubToken = getGitHubTokenForWriting();
    if (!$githubToken) {
        return ['success' => false, 'error' => 'No GitHub token available for writing - please login with admin token'];
    }

    try {
        // Convert content to JSON
        // Create a copy to avoid modifying the original
        $contentForSave = $content;

        // Remove profile image if it's too large (GitHub API has size limits)
        if (isset($contentForSave['personal']['profileImage'])) {
            $imageSize = strlen($contentForSave['personal']['profileImage']);
            if ($imageSize > 500000) { // 500KB limit for base64
                error_log("⚠️ Removing large profileImage ($imageSize bytes) for GitHub save");
                unset($contentForSave['personal']['profileImage']);
            } else {
                error_log("📸 Including profileImage in save ($imageSize bytes)");
            }
        }

        error_log("📊 Content structure validated");
        $jsonString = json_encode($contentForSave, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
        if ($jsonString === false) {
            return ['success' => false, 'error' => 'JSON encoding failed: ' . json_last_error_msg()];
        }

        error_log("📊 JSON size: " . strlen($jsonString) . " characters");

        // GitHub API URL
        $apiUrl = 'https://api.github.com/repos/' . GITHUB_OWNER . '/' . GITHUB_REPO . '/contents/' . DATA_FILE;

        // Headers
        $headers = [
            'Authorization: token ' . $githubToken,
            'Accept: application/vnd.github.v3+json',
            'User-Agent: Personal-Website-PHP',
            'Content-Type: application/json'
        ];

        // Get current file SHA (if exists)
        $currentSha = null;
        $getContext = stream_context_create([
            'http' => [
                'method' => 'GET',
                'header' => implode("\r\n", $headers),
                'timeout' => 30
            ]
        ]);

        $getResponse = @file_get_contents($apiUrl, false, $getContext);
        if ($getResponse !== false) {
            $fileInfo = json_decode($getResponse, true);
            if ($fileInfo && isset($fileInfo['sha'])) {
                $currentSha = $fileInfo['sha'];
                error_log("📊 Current SHA: " . substr($currentSha, 0, 8));
            }
        }

        // Prepare request body
        $requestBody = [
            'message' => 'Update website content - ' . date('Y-m-d H:i:s'),
            'content' => base64_encode($jsonString),
            'branch' => 'master' // Change to 'master' if needed
        ];

        if ($currentSha) {
            $requestBody['sha'] = $currentSha;
        }

        // Send PUT request
        $putContext = stream_context_create([
            'http' => [
                'method' => 'PUT',
                'header' => implode("\r\n", $headers),
                'content' => json_encode($requestBody),
                'timeout' => 30
            ]
        ]);

        error_log("🚀 Sending to GitHub...");
        $putResponse = @file_get_contents($apiUrl, false, $putContext);

        if ($putResponse !== false) {
            $result = json_decode($putResponse, true);
            if ($result && isset($result['content']['sha'])) {
                error_log("✅ GitHub save successful");
                return [
                    'success' => true,
                    'sha' => $result['content']['sha']
                ];
            }
        }

        // Check for errors
        $httpCode = 0;
        if (isset($http_response_header)) {
            foreach ($http_response_header as $header) {
                if (preg_match('/HTTP\/\d\.\d\s+(\d+)/', $header, $matches)) {
                    $httpCode = (int) $matches[1];
                    break;
                }
            }
        }

        $errorMsg = "HTTP $httpCode";
        if ($putResponse) {
            $errorData = json_decode($putResponse, true);
            if ($errorData && isset($errorData['message'])) {
                $errorMsg .= ': ' . $errorData['message'];
            }
        }

        error_log("❌ GitHub error: $errorMsg");
        return ['success' => false, 'error' => $errorMsg];

    } catch (Exception $e) {
        error_log("❌ GitHub exception: " . $e->getMessage());
        return ['success' => false, 'error' => $e->getMessage()];
    }
}

// ===================================
// CONTROLLED GITHUB SYNC (ONLY WHEN SAFE)
// ===================================
function safeGitHubSync()
{
    $githubToken = getGitHubTokenForReading();
    if (!$githubToken) {
        error_log("⚠️ No GitHub token available for reading content");
        return 'offline';
    }

    $url = 'https://api.github.com/repos/' . GITHUB_OWNER . '/' . GITHUB_REPO . '/contents/' . DATA_FILE;
    $headers = [
        'Authorization: token ' . $githubToken,
        'Accept: application/vnd.github.v3+json',
        'User-Agent: Personal-Website-PHP'
    ];

    $context = stream_context_create([
        'http' => [
            'method' => 'GET',
            'header' => implode("\r\n", $headers),
            'timeout' => 10
        ]
    ]);

    $response = @file_get_contents($url, false, $context);
    if ($response !== false) {
        $data = json_decode($response, true);
        if (isset($data['content'])) {
            $content = json_decode(base64_decode($data['content']), true);
            if ($content) {
                $_SESSION['content'] = $content;
                $_SESSION['github_file_sha'] = $data['sha'];
                error_log("📥 Synced from GitHub");
                return 'online';
            }
        }
    }

    return 'offline';
}

// Load content and determine cloud status
$cloudStatus = 'offline';

// Only try to sync content from GitHub if session is empty (first visit)
if (empty($_POST) && empty($_SESSION['content_loaded'])) {
    $cloudStatus = safeGitHubSync();
    $_SESSION['content_loaded'] = true; // Mark that we've loaded content
    error_log("📥 Initial GitHub sync completed");
} else if (!empty($_POST)) {
    // For admin operations, check if we have write access
    $writeToken = getGitHubTokenForWriting();
    $readToken = getGitHubTokenForReading();

    if ($writeToken) {
        $cloudStatus = 'online-write'; // Full admin access
    } elseif ($readToken) {
        $cloudStatus = 'online-read'; // Read-only access
    } else {
        $cloudStatus = 'offline';
    }
    error_log("🔄 Admin operation - not syncing from GitHub");
} else {
    error_log("🔄 Subsequent page load - using session content");
}

function handleOtherOperations($action)
{
    // Add debugging
    error_log("🔄 handleOtherOperations called with action: " . $action);
    error_log("🔄 Is admin: " . ($_SESSION['isAdmin'] ? 'true' : 'false'));
    error_log("🔄 Edit mode: " . ($_SESSION['editMode'] ? 'true' : 'false'));
    error_log("🔄 POST data: " . print_r($_POST, true));

    if (!$_SESSION['isAdmin'] || !$_SESSION['editMode']) {
        error_log("❌ Access denied - not admin or not in edit mode");
        return;
    }

    $content = $_SESSION['content'];
    $needsRedirect = false;

    switch ($action) {
        // ===================================
        // IMAGE UPLOAD HANDLER
        // ===================================
        case 'save_image':
            $section = $_POST['section'];
            $fieldPath = $_POST['field_path'];
            $imageData = $_POST['image_data'];

            error_log("🖼️ Saving image for $section -> $fieldPath");

            // Handle different image paths
            if ($section === 'personal' && $fieldPath === 'profileImage') {
                $content['personal']['profileImage'] = $imageData;
            } else if ($section === 'family' && preg_match('/^([^[]+)\[list\]\[(\d+)\]\[image\]$/', $fieldPath, $matches)) {
                $familyKey = $matches[1];
                $index = (int) $matches[2];
                if (isset($content['family'][$familyKey]['list'][$index])) {
                    $content['family'][$familyKey]['list'][$index]['image'] = $imageData;
                }
            } else if ($section === 'friends' && preg_match('/^([^[]+)\[list\]\[(\d+)\]\[image\]$/', $fieldPath, $matches)) {
                $friendKey = $matches[1];
                $index = (int) $matches[2];
                if (isset($content['friends'][$friendKey]['list'][$index])) {
                    $content['friends'][$friendKey]['list'][$index]['image'] = $imageData;
                }
            } else if ($section === 'gallery' && preg_match('/^(\d+)\[image\]$/', $fieldPath, $matches)) {
                $index = (int) $matches[1];
                if (isset($content['gallery'][$index])) {
                    $content['gallery'][$index]['image'] = $imageData;
                }
            }
            $needsRedirect = true;
            break;

        // ===================================
        // EDUCATION MANAGEMENT
        // ===================================
        case 'add_education':
            $key = $_POST['key'];
            $title = $_POST['title'];
            $content['education'][$key] = [
                'title' => $title,
                'school' => 'School Name',
                'years' => 'Years',
                'description' => 'Description',
                'subjects' => ['Subject 1', 'Subject 2'],
                'activities' => ['Activity 1', 'Activity 2']
            ];
            $_SESSION['activeSection'] = $key;
            $needsRedirect = true;
            break;

        case 'remove_education':
            unset($content['education'][$_POST['key']]);
            $_SESSION['activeSection'] = 'education';
            $needsRedirect = true;
            break;

        case 'add_subject':
            $sectionKey = $_POST['section_key'];
            $subject = $_POST['subject'];
            if (isset($content['education'][$sectionKey])) {
                if (!isset($content['education'][$sectionKey]['subjects'])) {
                    $content['education'][$sectionKey]['subjects'] = [];
                }
                $content['education'][$sectionKey]['subjects'][] = $subject;
                error_log("✅ Added subject '$subject' to education section '$sectionKey'");
            }
            $needsRedirect = true;
            break;

        case 'remove_subject':
            $sectionKey = $_POST['section_key'];
            $index = (int) $_POST['index'];
            if (isset($content['education'][$sectionKey]['subjects'][$index])) {
                unset($content['education'][$sectionKey]['subjects'][$index]);
                $content['education'][$sectionKey]['subjects'] = array_values($content['education'][$sectionKey]['subjects']);
                error_log("✅ Removed subject from education section '$sectionKey'");
            }
            $needsRedirect = true;
            break;

        case 'add_activity':
            $sectionKey = $_POST['section_key'];
            $activity = $_POST['activity'];
            if (isset($content['education'][$sectionKey])) {
                if (!isset($content['education'][$sectionKey]['activities'])) {
                    $content['education'][$sectionKey]['activities'] = [];
                }
                $content['education'][$sectionKey]['activities'][] = $activity;
                error_log("✅ Added activity '$activity' to education section '$sectionKey'");
            }
            $needsRedirect = true;
            break;

        case 'remove_activity':
            $sectionKey = $_POST['section_key'];
            $index = (int) $_POST['index'];
            if (isset($content['education'][$sectionKey]['activities'][$index])) {
                unset($content['education'][$sectionKey]['activities'][$index]);
                $content['education'][$sectionKey]['activities'] = array_values($content['education'][$sectionKey]['activities']);
                error_log("✅ Removed activity from education section '$sectionKey'");
            }
            $needsRedirect = true;
            break;

        // ===================================
        // FAMILY MANAGEMENT
        // ===================================
        case 'add_family':
            $key = $_POST['key'];
            $title = $_POST['title'];
            $content['family'][$key] = [
                'title' => $title,
                'list' => [['name' => 'Name', 'description' => 'Description', 'image' => null]]
            ];
            $_SESSION['activeSection'] = $key;
            error_log("✅ Added family category: $key");
            $needsRedirect = true;
            break;

        case 'remove_family':
            $key = $_POST['key'];
            unset($content['family'][$key]);
            $_SESSION['activeSection'] = 'family';
            error_log("✅ Removed family category: $key");
            $needsRedirect = true;
            break;

        case 'add_person_to_family':
            $familyKey = $_POST['familyKey'];
            if (isset($content['family'][$familyKey])) {
                if (!isset($content['family'][$familyKey]['list'])) {
                    $content['family'][$familyKey]['list'] = [];
                }
                $content['family'][$familyKey]['list'][] = [
                    'name' => 'New Person',
                    'description' => 'Description',
                    'image' => null
                ];
                error_log("✅ Added person to family category: $familyKey");
            } else {
                error_log("❌ Family category not found: $familyKey");
            }
            $needsRedirect = true;
            break;

        case 'remove_person_from_family':
            $familyKey = $_POST['familyKey'];
            $index = (int) $_POST['index'];
            if (isset($content['family'][$familyKey]['list'][$index])) {
                unset($content['family'][$familyKey]['list'][$index]);
                $content['family'][$familyKey]['list'] = array_values($content['family'][$familyKey]['list']);
                error_log("✅ Removed person $index from family category: $familyKey");
            } else {
                error_log("❌ Person $index not found in family category: $familyKey");
            }
            $needsRedirect = true;
            break;

        // ===================================
        // FRIENDS MANAGEMENT
        // ===================================
        case 'add_friends_category':
            $key = $_POST['key'];
            $title = $_POST['title'];
            $description = $_POST['description'];
            $content['friends'][$key] = [
                'title' => $title,
                'description' => $description,
                'list' => []
            ];
            $_SESSION['activeSection'] = $key;
            $needsRedirect = true;
            break;

        case 'remove_friends_category':
            unset($content['friends'][$_POST['key']]);
            $_SESSION['activeSection'] = 'friends';
            $needsRedirect = true;
            break;

        case 'add_friend':
            $friendKey = $_POST['friend_key'];
            $name = $_POST['name'];
            $content['friends'][$friendKey]['list'][] = [
                'name' => $name,
                'image' => null
            ];
            $needsRedirect = true;
            break;

        case 'remove_friend':
            $friendKey = $_POST['friend_key'];
            $index = (int) $_POST['index'];
            unset($content['friends'][$friendKey]['list'][$index]);
            $content['friends'][$friendKey]['list'] = array_values($content['friends'][$friendKey]['list']);
            $needsRedirect = true;
            break;

        // ===================================
        // COLLECTIONS MANAGEMENT
        // ===================================
        case 'add_collection':
            $name = $_POST['name'] ?? '';
            $icon = $_POST['icon'] ?? '';
            $description = $_POST['description'] ?? '';

            error_log("✅ Adding collection: name='$name', icon='$icon', description='$description'");

            if (empty($name) || empty($icon) || empty($description)) {
                error_log("❌ Missing collection data - name: '$name', icon: '$icon', description: '$description'");
                break;
            }

            if (!isset($content['collections'])) {
                $content['collections'] = [];
                error_log("📝 Initialized collections array");
            }

            $content['collections'][] = [
                'name' => $name,
                'icon' => $icon,
                'description' => $description
            ];

            error_log("✅ Collection added successfully. Total collections: " . count($content['collections']));
            $needsRedirect = true;
            break;

        case 'remove_collection':
            $index = (int) $_POST['index'];
            unset($content['collections'][$index]);
            $content['collections'] = array_values($content['collections']);
            $needsRedirect = true;
            break;

        // ===================================
        // ACHIEVEMENTS MANAGEMENT
        // ===================================
        case 'add_achievement':
            $title = $_POST['title'];
            $year = $_POST['year'];
            $description = $_POST['description'];
            $content['achievements'][] = [
                'title' => $title,
                'year' => $year,
                'description' => $description
            ];
            $needsRedirect = true;
            break;

        case 'remove_achievement':
            $index = (int) $_POST['index'];
            unset($content['achievements'][$index]);
            $content['achievements'] = array_values($content['achievements']);
            $needsRedirect = true;
            break;

        // ===================================
        // GALLERY MANAGEMENT
        // ===================================
        case 'add_gallery_item':
            $title = $_POST['title'];
            $description = $_POST['description'];
            $content['gallery'][] = [
                'title' => $title,
                'description' => $description,
                'image' => null
            ];
            $needsRedirect = true;
            break;

        case 'remove_gallery_item':
            $index = (int) $_POST['index'];
            unset($content['gallery'][$index]);
            $content['gallery'] = array_values($content['gallery']);
            $needsRedirect = true;
            break;

        // ===================================
        // ADVOCACY MANAGEMENT
        // ===================================
        case 'add_advocacy_item':
            $type = $_POST['type']; // causes, effects, solutions
            $item = $_POST['item'];
            if (in_array($type, ['causes', 'effects', 'solutions'])) {
                if (!isset($content['advocacy'][$type])) {
                    $content['advocacy'][$type] = [];
                }
                $content['advocacy'][$type][] = $item;
            }
            $needsRedirect = true;
            break;

        case 'remove_advocacy_item':
            $type = $_POST['type'];
            $index = (int) $_POST['index'];
            if (in_array($type, ['causes', 'effects', 'solutions']) && isset($content['advocacy'][$type][$index])) {
                unset($content['advocacy'][$type][$index]);
                $content['advocacy'][$type] = array_values($content['advocacy'][$type]);
            }
            $needsRedirect = true;
            break;

        // ===================================
        // DEFAULT CASE - LOG UNHANDLED ACTIONS
        // ===================================
        default:
            error_log("❌ Unhandled action in handleOtherOperations: " . $action);
            error_log("❌ POST data: " . print_r($_POST, true));
            break;
    }

    $_SESSION['content'] = $content;
    error_log("✅ Session content updated successfully");
    error_log("📊 Collections in session: " . count($content['collections'] ?? []));

    // Redirect to prevent form resubmission
    if ($needsRedirect) {
        error_log("🔄 Redirecting to prevent form resubmission");
        header('Location: ' . $_SERVER['REQUEST_URI']);
        exit();
    }
}

function getDefaultContent()
{
    return [
        'logo' => null,
        'personal' => [
            'name' => 'Your Name',
            'title' => 'Student | Dreamer | Future Leader',
            'about' => 'Hello! I\'m a passionate student currently pursuing my education and exploring various interests. I believe in continuous learning, building meaningful relationships, and making a positive impact in my community.',
            'age' => '[Your Age]',
            'location' => '[Your City, Country]',
            'interests' => 'Reading, Technology, Sports',
            'languages' => 'English, [Other Languages]',
            'email' => 'your.email@example.com',
            'phone' => '+1 (555) 123-4567',
            'social' => '@yourusername',
            'profileImage' => null
        ],
        'education' => [
            'gs' => [
                'title' => 'Grade School',
                'school' => 'Elementary School Name',
                'years' => '2010-2016',
                'description' => 'Foundation years where I developed basic academic skills and discovered my love for learning.',
                'subjects' => ['Mathematics', 'Science', 'English', '[Other subjects]'],
                'activities' => ['Student Council', 'Academic Clubs', 'Sports Teams', '[Other activities]']
            ],
            'hs' => [
                'title' => 'High School',
                'school' => 'High School Name',
                'years' => '2016-2020',
                'description' => 'Formative years that shaped my academic interests and helped me develop leadership skills.',
                'subjects' => ['Mathematics', 'Science', 'English', '[Other subjects]'],
                'activities' => ['Student Council', 'Academic Clubs', 'Sports Teams', '[Other activities]']
            ],
            'shs' => [
                'title' => 'Senior High School',
                'school' => 'Senior High School Name',
                'years' => '2020-2022',
                'description' => 'Specialized education that prepared me for college and helped me choose my career path.',
                'subjects' => ['Mathematics', 'Science', 'English', '[Other subjects]'],
                'activities' => ['Student Council', 'Academic Clubs', 'Sports Teams', '[Other activities]']
            ],
            'college' => [
                'title' => 'College',
                'school' => 'University Name',
                'years' => '2022-Present',
                'description' => 'Current academic journey where I\'m pursuing my degree and developing professional skills.',
                'subjects' => ['Mathematics', 'Science', 'English', '[Other subjects]'],
                'activities' => ['Student Council', 'Academic Clubs', 'Sports Teams', '[Other activities]']
            ]
        ],
        'family' => [
            'father' => [
                'title' => 'My Father',
                'list' => [['name' => 'Father\'s Name', 'description' => 'My father is my role model and biggest supporter. He has always encouraged me to pursue my dreams.', 'image' => null]]
            ],
            'mother' => [
                'title' => 'My Mother',
                'list' => [['name' => 'Mother\'s Name', 'description' => 'My mother is the heart of our family. Her love and care have shaped who I am today.', 'image' => null]]
            ],
            'siblings' => [
                'title' => 'My Siblings',
                'list' => [
                    ['name' => 'Brother/Sister Name', 'description' => 'My sibling is my best friend and partner in all adventures.', 'image' => null],
                    ['name' => 'Another Sibling', 'description' => 'Another amazing sibling who brings joy to our family.', 'image' => null]
                ]
            ],
            'grandparents' => [
                'title' => 'My Grand Parents',
                'list' => [['name' => 'Grandparents\' Names', 'description' => 'My grandparents are the wisdom keepers of our family, sharing stories and life lessons.', 'image' => null]]
            ]
        ],
        'collections' => [
            ['name' => 'Books', 'icon' => '📚', 'description' => 'Collection of favorite novels, academic books, and inspiring biographies.'],
            ['name' => 'Music', 'icon' => '🎵', 'description' => 'Vinyl records, CDs, and digital playlists spanning various genres.'],
            ['name' => 'Sports', 'icon' => '⚽', 'description' => 'Memorabilia from favorite teams and sports equipment collection.']
        ],
        'friends' => [
            'school' => [
                'title' => 'School Mates',
                'description' => 'Friends who share the academic journey with me.',
                'list' => [
                    ['name' => 'Friend 1', 'image' => null],
                    ['name' => 'Friend 2', 'image' => null],
                    ['name' => 'Friend 3', 'image' => null]
                ]
            ],
            'church' => [
                'title' => 'Church Mates',
                'description' => 'Friends from my faith community who support my spiritual growth.',
                'list' => [
                    ['name' => 'Friend 1', 'image' => null],
                    ['name' => 'Friend 2', 'image' => null],
                    ['name' => 'Friend 3', 'image' => null]
                ]
            ],
            'org' => [
                'title' => 'Organization Friends',
                'description' => 'Friends from various clubs and organizations I\'m part of.',
                'list' => [
                    ['name' => 'Friend 1', 'image' => null],
                    ['name' => 'Friend 2', 'image' => null],
                    ['name' => 'Friend 3', 'image' => null]
                ]
            ]
        ],
        'achievements' => [
            ['title' => 'Academic Excellence Award', 'year' => '2023', 'description' => 'Recognized for outstanding academic performance'],
            ['title' => 'Leadership Award', 'year' => '2023', 'description' => 'For demonstrating exceptional leadership skills'],
            ['title' => 'Community Service Recognition', 'year' => '2022', 'description' => 'For volunteer work in the local community'],
            ['title' => 'Sports Achievement', 'year' => '2022', 'description' => 'Achievement in school sports competition']
        ],
        'gallery' => [
            ['title' => 'Family Vacation', 'description' => 'Summer trip with family', 'image' => null],
            ['title' => 'Graduation Day', 'description' => 'Celebrating academic milestone', 'image' => null],
            ['title' => 'School Event', 'description' => 'Participating in school activities', 'image' => null]
        ],
        'advocacy' => [
            'title' => 'Climate Change Awareness',
            'issue' => 'Climate change is one of the most pressing challenges of our time, affecting ecosystems, weather patterns, and human lives globally.',
            'causes' => [
                'Greenhouse gas emissions from fossil fuels',
                'Deforestation and land use changes',
                'Industrial processes and agriculture',
                'Transportation and energy consumption'
            ],
            'effects' => [
                'Rising global temperatures',
                'Extreme weather events',
                'Sea level rise',
                'Impact on biodiversity'
            ],
            'solutions' => [
                'Education and awareness campaigns',
                'Sustainable lifestyle choices',
                'Support for renewable energy',
                'Community action and advocacy'
            ],
            'myActions' => 'I\'m committed to raising awareness about climate change through social media campaigns, participating in local environmental initiatives, and promoting sustainable practices in my school and community.'
        ],
        'multimedia' => [
            'audio' => ['title' => 'Sample Audio Description', 'file' => null],
            'video' => ['title' => 'Sample Video Description', 'file' => null]
        ]
    ];
}

function generateMenuItems()
{
    $content = $_SESSION['content'];
    $menuItems = [];

    // Personal
    $menuItems[] = ['id' => 'personal', 'label' => 'Personal', 'icon' => 'fas fa-user'];

    // Education
    $educationItems = [];
    foreach ($content['education'] as $key => $edu) {
        $educationItems[] = ['id' => $key, 'label' => $edu['title']];
    }
    if (!empty($educationItems)) {
        $menuItems[] = ['id' => 'education', 'label' => 'Education', 'icon' => 'fas fa-graduation-cap', 'subItems' => $educationItems];
    }

    // Family
    $familyItems = [];
    foreach ($content['family'] as $key => $family) {
        $familyItems[] = ['id' => $key, 'label' => $family['title']];
    }
    if (!empty($familyItems)) {
        $menuItems[] = ['id' => 'family', 'label' => 'Family', 'icon' => 'fas fa-users', 'subItems' => $familyItems];
    }

    // Collections
    $menuItems[] = ['id' => 'collections', 'label' => 'Collections', 'icon' => 'fas fa-heart'];

    // Friends
    $friendsItems = [];
    foreach ($content['friends'] as $key => $friends) {
        $friendsItems[] = ['id' => $key, 'label' => $friends['title']];
    }
    if (!empty($friendsItems)) {
        $menuItems[] = ['id' => 'friends', 'label' => 'Friends', 'icon' => 'fas fa-users', 'subItems' => $friendsItems];
    }

    // Other sections
    $menuItems[] = ['id' => 'achievements', 'label' => 'Achievements', 'icon' => 'fas fa-trophy'];
    $menuItems[] = ['id' => 'gallery', 'label' => 'Gallery', 'icon' => 'fas fa-camera'];
    $menuItems[] = ['id' => 'advocacy', 'label' => 'Advocacy', 'icon' => 'fas fa-bullhorn'];

    return $menuItems;
}

function renderEditableInput($value, $name, $type = 'text', $isTextarea = false)
{
    if (!$_SESSION['editMode']) {
        return htmlspecialchars($value);
    }

    if ($isTextarea) {
        return "<textarea name='$name' class='editable-textarea'>" . htmlspecialchars($value) . "</textarea>";
    }

    return "<input type='$type' name='$name' value='" . htmlspecialchars($value) . "' class='editable-input'>";
}

function renderContent()
{
    $content = $_SESSION['content'];
    $activeSection = $_SESSION['activeSection'];

    // Check if activeSection is a family member
    if (isset($content['family'][$activeSection])) {
        return renderFamilySection($content['family'][$activeSection], $activeSection);
    }

    // Check if activeSection is an education level
    if (isset($content['education'][$activeSection])) {
        return renderEducationSection($content['education'][$activeSection], $activeSection);
    }

    // Check if activeSection is a friends category
    if (isset($content['friends'][$activeSection])) {
        return renderFriendsSection($content['friends'][$activeSection], $activeSection);
    }

    // Handle main sections
    switch ($activeSection) {
        case 'personal':
            return renderPersonalSection($content['personal']);
        case 'education':
            return renderEducationOverview($content['education']);
        case 'family':
            return renderFamilyOverview($content['family']);
        case 'friends':
            return renderFriendsOverview($content['friends']);
        case 'collections':
            return renderCollectionsSection($content['collections']);
        case 'achievements':
            return renderAchievementsSection($content['achievements']);
        case 'gallery':
            return renderGallerySection($content['gallery']);
        case 'advocacy':
            return renderAdvocacySection($content['advocacy']);
        default:
            return '<div class="placeholder">Please select a section from the menu</div>';
    }
}

function renderPersonalSection($personal)
{
    $profileImageSrc = $personal['profileImage'] ?: '';
    $profileInitial = substr($personal['name'], 0, 1);

    ob_start();
    ?>
    <div class="content-grid">
        <div class="text-center">
            <div class="profile-container">
                <?php if ($profileImageSrc): ?>
                    <img src="<?= $profileImageSrc ?>" alt="Profile" class="profile-image">
                <?php else: ?>
                    <div class="profile-placeholder"><?= $profileInitial ?></div>
                <?php endif; ?>
                <?php if ($_SESSION['editMode']): ?>
                    <button class="upload-button" onclick="uploadImage('profileImage')">
                        <i class="fas fa-upload"></i>
                    </button>
                    <!-- Hidden input to store profile image data -->
                    <input type="hidden" name="personal[profileImage]" value="<?= htmlspecialchars($profileImageSrc) ?>"
                        class="editable-input">
                <?php endif; ?>
            </div>
            <h2 class="profile-name"><?= renderEditableInput($personal['name'], 'personal[name]') ?></h2>
            <p class="profile-title"><?= renderEditableInput($personal['title'], 'personal[title]') ?></p>
        </div>

        <div class="card">
            <h3 class="section-title">✨ About Me</h3>
            <p class="about-text"><?= renderEditableInput($personal['about'], 'personal[about]', 'text', true) ?></p>
        </div>

        <div class="grid-md-2">
            <div class="card">
                <h3 class="card-title">💫 Quick Facts</h3>
                <div class="facts-list">
                    <div class="fact-item">
                        <span class="fact-label">Age:</span>
                        <?= renderEditableInput($personal['age'], 'personal[age]') ?>
                    </div>
                    <div class="fact-item">
                        <span class="fact-label">Location:</span>
                        <?= renderEditableInput($personal['location'], 'personal[location]') ?>
                    </div>
                    <div class="fact-item">
                        <span class="fact-label">Interests:</span>
                        <?= renderEditableInput($personal['interests'], 'personal[interests]') ?>
                    </div>
                    <div class="fact-item">
                        <span class="fact-label">Languages:</span>
                        <?= renderEditableInput($personal['languages'], 'personal[languages]') ?>
                    </div>
                </div>
            </div>

            <div class="card">
                <h3 class="card-title">📞 Contact</h3>
                <div class="facts-list">
                    <div class="fact-item">
                        <span class="fact-label">Email:</span>
                        <?= renderEditableInput($personal['email'], 'personal[email]') ?>
                    </div>
                    <div class="fact-item">
                        <span class="fact-label">Phone:</span>
                        <?= renderEditableInput($personal['phone'], 'personal[phone]') ?>
                    </div>
                    <div class="fact-item">
                        <span class="fact-label">Social:</span>
                        <?= renderEditableInput($personal['social'], 'personal[social]') ?>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <?php
    return ob_get_clean();
}

function renderEducationOverview($education)
{
    ob_start();
    ?>
    <div class="content-grid">
        <div class="section-header">
            <h2 class="section-title"><i class="fas fa-graduation-cap"></i> My Education Journey</h2>
            <?php if ($_SESSION['editMode']): ?>
                <button class="add-button" onclick="addEducationLevel()">
                    <i class="fas fa-plus"></i> Add Education Level
                </button>
            <?php endif; ?>
        </div>

        <div class="grid-md-2">
            <?php foreach ($education as $key => $edu): ?>
                <div class="overview-card" onclick="navigateToSection('<?= $key ?>')">
                    <?php if ($_SESSION['editMode']): ?>
                        <button class="delete-button" onclick="event.stopPropagation(); removeEducationLevel('<?= $key ?>')">
                            <i class="fas fa-trash"></i>
                        </button>
                    <?php endif; ?>
                    <h3 class="card-title-colored"><?= htmlspecialchars($edu['title']) ?></h3>
                    <p class="card-subtitle"><?= htmlspecialchars($edu['school']) ?></p>
                    <p class="card-meta"><?= htmlspecialchars($edu['years']) ?></p>
                </div>
            <?php endforeach; ?>
        </div>
    </div>
    <?php
    return ob_get_clean();
}

function renderEducationSection($edu, $sectionKey)
{
    ob_start();
    ?>
    <div class="content-grid">
        <div class="section-header">
            <h2 class="section-title">Education Level</h2>
            <?php if ($_SESSION['editMode']): ?>
                <button class="delete-button-large" onclick="removeEducationLevel('<?= $sectionKey ?>')">
                    <i class="fas fa-trash"></i> Remove Level
                </button>
            <?php endif; ?>
        </div>

        <div class="card">
            <h3 class="card-title"><?= renderEditableInput($edu['title'], "education[$sectionKey][title]") ?></h3>
            <h4 class="card-subtitle-blue"><?= renderEditableInput($edu['school'], "education[$sectionKey][school]") ?></h4>
            <p class="card-meta"><?= renderEditableInput($edu['years'], "education[$sectionKey][years]") ?></p>
            <p class="card-description">
                <?= renderEditableInput($edu['description'], "education[$sectionKey][description]", 'text', true) ?>
            </p>
        </div>

        <div class="grid-md-2">
            <div class="card">
                <div class="section-header">
                    <h3 class="card-title">Subjects/Courses</h3>
                    <?php if ($_SESSION['editMode']): ?>
                        <button class="add-button-small" onclick="addSubject('<?= $sectionKey ?>')">
                            <i class="fas fa-plus"></i> Add
                        </button>
                    <?php endif; ?>
                </div>
                <ul class="list">
                    <?php foreach ($edu['subjects'] as $index => $subject): ?>
                        <li class="list-item">
                            • <?= $_SESSION['editMode'] ?
                                "<input type='text' value='" . htmlspecialchars($subject) . "' class='inline-input' name='education[$sectionKey][subjects][$index]'>" :
                                htmlspecialchars($subject) ?>
                            <?php if ($_SESSION['editMode']): ?>
                                <button class="remove-item-btn" onclick="removeSubject('<?= $sectionKey ?>', <?= $index ?>)"><i
                                        class="fas fa-times"></i></button>
                            <?php endif; ?>
                        </li>
                    <?php endforeach; ?>
                </ul>
            </div>

            <div class="card">
                <div class="section-header">
                    <h3 class="card-title">Activities</h3>
                    <?php if ($_SESSION['editMode']): ?>
                        <button class="add-button-small" onclick="addActivity('<?= $sectionKey ?>')">
                            <i class="fas fa-plus"></i> Add
                        </button>
                    <?php endif; ?>
                </div>
                <ul class="list">
                    <?php foreach ($edu['activities'] as $index => $activity): ?>
                        <li class="list-item">
                            • <?= $_SESSION['editMode'] ?
                                "<input type='text' value='" . htmlspecialchars($activity) . "' class='inline-input' name='education[$sectionKey][activities][$index]'>" :
                                htmlspecialchars($activity) ?>
                            <?php if ($_SESSION['editMode']): ?>
                                <button class="remove-item-btn" onclick="removeActivity('<?= $sectionKey ?>', <?= $index ?>)"><i
                                        class="fas fa-times"></i></button>
                            <?php endif; ?>
                        </li>
                    <?php endforeach; ?>
                </ul>
            </div>
        </div>
    </div>
    <?php
    return ob_get_clean();
}

function renderFamilyOverview($family)
{
    ob_start();
    ?>
    <div class="content-grid">
        <div class="section-header">
            <h2 class="section-title"><i class="fas fa-users"></i> My Beautiful Family</h2>
            <?php if ($_SESSION['editMode']): ?>
                <button class="add-button" onclick="addFamilyMember()">
                    <i class="fas fa-plus"></i> Add Family Member
                </button>
            <?php endif; ?>
        </div>

        <div class="grid-lg-3">
            <?php foreach ($family as $key => $familyGroup): ?>
                <?php $firstMember = $familyGroup['list'][0] ?? ['name' => 'No members', 'image' => null]; ?>
                <div class="overview-card family-card" onclick="navigateToSection('<?= $key ?>')">
                    <div class="click-indicator">Click to view</div>
                    <?php if ($_SESSION['editMode']): ?>
                        <button class="delete-button" onclick="event.stopPropagation(); removeFamilyMember('<?= $key ?>')">
                            <i class="fas fa-trash"></i>
                        </button>
                    <?php endif; ?>

                    <div class="family-avatar-container">
                        <?php if ($firstMember['image']): ?>
                            <img src="<?= $firstMember['image'] ?>" alt="<?= htmlspecialchars($firstMember['name']) ?>"
                                class="avatar-medium">
                        <?php else: ?>
                            <div class="avatar-placeholder-medium"><?= substr($firstMember['name'], 0, 1) ?></div>
                        <?php endif; ?>
                    </div>

                    <h3 class="card-title"><?= htmlspecialchars($familyGroup['title']) ?></h3>
                    <p class="member-count"><?= count($familyGroup['list']) ?>
                        <?= count($familyGroup['list']) === 1 ? 'member' : 'members' ?>
                    </p>
                    <p class="member-preview"><?= substr(htmlspecialchars($firstMember['description'] ?? ''), 0, 80) ?>...</p>

                    <div class="click-hint"><i class="fas fa-hand-point-up"></i> Click to see all members</div>
                </div>
            <?php endforeach; ?>
        </div>
    </div>
    <?php
    return ob_get_clean();
}

function renderFamilySection($familyGroup, $sectionKey)
{
    ob_start();
    ?>
    <div class="content-grid">
        <div class="section-header">
            <h2 class="section-title"><?= htmlspecialchars($familyGroup['title']) ?></h2>
            <div class="button-group">
                <?php if ($_SESSION['editMode']): ?>
                    <button class="add-button" onclick="addPersonToFamily('<?= $sectionKey ?>')">
                        <i class="fas fa-plus"></i> Add Person
                    </button>
                    <button class="delete-button-large" onclick="removeFamilyMember('<?= $sectionKey ?>')">
                        <i class="fas fa-trash"></i> Remove Category
                    </button>
                <?php endif; ?>
            </div>
        </div>

        <div class="grid-lg-3">
            <?php foreach ($familyGroup['list'] as $index => $person): ?>
                <div class="card family-member-card">
                    <?php if ($_SESSION['editMode']): ?>
                        <button class="delete-button" onclick="removePersonFromFamily('<?= $sectionKey ?>', <?= $index ?>)">
                            <i class="fas fa-trash"></i>
                        </button>
                    <?php endif; ?>

                    <div class="family-member-avatar">
                        <div class="avatar-container">
                            <?php if ($person['image']): ?>
                                <img src="<?= $person['image'] ?>" alt="<?= htmlspecialchars($person['name']) ?>"
                                    class="avatar-large">
                            <?php else: ?>
                                <div class="avatar-placeholder-large"><?= substr($person['name'], 0, 1) ?></div>
                            <?php endif; ?>
                            <?php if ($_SESSION['editMode']): ?>
                                <button class="upload-button-center"
                                    onclick="uploadFamilyImage('<?= $sectionKey ?>', <?= $index ?>)">
                                    <i class="fas fa-upload"></i>
                                </button>
                            <?php endif; ?>
                        </div>
                    </div>

                    <div class="text-center">
                        <h3 class="member-name">
                            <?= renderEditableInput($person['name'], "family[$sectionKey][list][$index][name]") ?>
                        </h3>
                        <p class="member-description">
                            <?= renderEditableInput($person['description'], "family[$sectionKey][list][$index][description]", 'text', true) ?>
                        </p>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>
    </div>
    <?php
    return ob_get_clean();
}

function renderFriendsOverview($friends)
{
    ob_start();
    ?>
    <div class="content-grid">
        <div class="section-header">
            <h2 class="section-title"><i class="fas fa-users"></i> My Amazing Friends</h2>
            <?php if ($_SESSION['editMode']): ?>
                <button class="add-button" onclick="addFriendsCategory()">
                    <i class="fas fa-plus"></i> Add Friends Group
                </button>
            <?php endif; ?>
        </div>

        <div class="grid-md-2">
            <?php foreach ($friends as $key => $group): ?>
                <div class="overview-card" onclick="navigateToSection('<?= $key ?>')">
                    <?php if ($_SESSION['editMode']): ?>
                        <button class="delete-button" onclick="event.stopPropagation(); removeFriendsCategory('<?= $key ?>')">
                            <i class="fas fa-trash"></i>
                        </button>
                    <?php endif; ?>
                    <h3 class="card-title-colored"><?= htmlspecialchars($group['title']) ?></h3>
                    <p class="card-description"><?= htmlspecialchars($group['description']) ?></p>
                    <div class="friends-preview">
                        <?php foreach (array_slice($group['list'], 0, 5) as $index => $friend): ?>
                            <div class="avatar-small-preview"><?= substr($friend['name'], 0, 1) ?></div>
                        <?php endforeach; ?>
                        <?php if (count($group['list']) > 5): ?>
                            <span class="more-friends">+<?= count($group['list']) - 5 ?> more friends</span>
                        <?php endif; ?>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>
    </div>
    <?php
    return ob_get_clean();
}

function renderFriendsSection($friendGroup, $sectionKey)
{
    ob_start();
    ?>
    <div class="content-grid">
        <div class="section-header">
            <h2 class="section-title"><?= renderEditableInput($friendGroup['title'], "friends[$sectionKey][title]") ?></h2>
            <div class="button-group">
                <?php if ($_SESSION['editMode']): ?>
                    <button class="add-button" onclick="addFriend('<?= $sectionKey ?>')">
                        <i class="fas fa-plus"></i> Add Friend
                    </button>
                    <button class="delete-button-large" onclick="removeFriendsCategory('<?= $sectionKey ?>')">
                        <i class="fas fa-trash"></i> Remove Category
                    </button>
                <?php endif; ?>
            </div>
        </div>

        <div class="card">
            <p class="card-description">
                <?= renderEditableInput($friendGroup['description'], "friends[$sectionKey][description]", 'text', true) ?>
            </p>

            <div class="grid-lg-3">
                <?php foreach ($friendGroup['list'] as $index => $friend): ?>
                    <div class="friend-item">
                        <?php if ($_SESSION['editMode']): ?>
                            <button class="delete-button-small" onclick="removeFriend('<?= $sectionKey ?>', <?= $index ?>)">
                                <i class="fas fa-trash"></i>
                            </button>
                        <?php endif; ?>
                        <div class="friend-avatar-container">
                            <?php if ($friend['image']): ?>
                                <img src="<?= $friend['image'] ?>" alt="<?= htmlspecialchars($friend['name']) ?>"
                                    class="avatar-small">
                            <?php else: ?>
                                <div class="avatar-placeholder-small friend-avatar"><?= substr($friend['name'], 0, 1) ?></div>
                            <?php endif; ?>
                            <?php if ($_SESSION['editMode']): ?>
                                <button class="upload-button-small"
                                    onclick="uploadFriendImage('<?= $sectionKey ?>', <?= $index ?>)">
                                    <i class="fas fa-upload"></i>
                                </button>
                            <?php endif; ?>
                        </div>
                        <p class="friend-name">
                            <?= renderEditableInput($friend['name'], "friends[$sectionKey][list][$index][name]") ?>
                        </p>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>
    </div>
    <?php
    return ob_get_clean();
}

function renderCollectionsSection($collections)
{
    ob_start();
    ?>
    <div class="content-grid">
        <div class="section-header">
            <h2 class="section-title">My Collections & Interests</h2>
            <?php if ($_SESSION['editMode']): ?>
                <button class="add-button" onclick="addCollection()">
                    <i class="fas fa-plus"></i> Add Collection
                </button>
            <?php endif; ?>
        </div>

        <div class="grid-lg-3">
            <?php foreach ($collections as $index => $collection): ?>
                <div class="card collection-card">
                    <?php if ($_SESSION['editMode']): ?>
                        <button class="delete-button" onclick="removeCollection(<?= $index ?>)">
                            <i class="fas fa-trash"></i>
                        </button>
                    <?php endif; ?>
                    <div class="text-center">
                        <div class="collection-icon">
                            <span class="collection-emoji"><?= $_SESSION['editMode'] ?
                                "<input type='text' value='" . htmlspecialchars($collection['icon']) . "' class='icon-input' name='collections[$index][icon]'>" :
                                htmlspecialchars($collection['icon']) ?></span>
                        </div>
                        <h3 class="collection-name"><?= renderEditableInput($collection['name'], "collections[$index][name]") ?>
                        </h3>
                    </div>
                    <p class="collection-description">
                        <?= renderEditableInput($collection['description'], "collections[$index][description]", 'text', true) ?>
                    </p>
                </div>
            <?php endforeach; ?>
        </div>
    </div>
    <?php
    return ob_get_clean();
}

function renderAchievementsSection($achievements)
{
    ob_start();
    ?>
    <div class="content-grid">
        <div class="section-header">
            <h2 class="section-title">My Achievements</h2>
            <?php if ($_SESSION['editMode']): ?>
                <button class="add-button" onclick="addAchievement()">
                    <i class="fas fa-plus"></i> Add Achievement
                </button>
            <?php endif; ?>
        </div>

        <div class="achievements-list">
            <?php foreach ($achievements as $index => $achievement): ?>
                <div class="achievement-item">
                    <?php if ($_SESSION['editMode']): ?>
                        <button class="delete-button" onclick="removeAchievement(<?= $index ?>)">
                            <i class="fas fa-trash"></i>
                        </button>
                    <?php endif; ?>
                    <div class="achievement-icon">
                        <i class="fas fa-trophy"></i>
                    </div>
                    <div class="achievement-content">
                        <h3 class="achievement-title">
                            <?= renderEditableInput($achievement['title'], "achievements[$index][title]") ?>
                        </h3>
                        <p class="achievement-description">
                            <?= renderEditableInput($achievement['description'], "achievements[$index][description]") ?>
                        </p>
                        <span
                            class="achievement-year"><?= renderEditableInput($achievement['year'], "achievements[$index][year]") ?></span>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>
    </div>
    <?php
    return ob_get_clean();
}

function renderGallerySection($gallery)
{
    ob_start();
    ?>
    <div class="content-grid">
        <div class="section-header">
            <h2 class="section-title">Photo Gallery</h2>
            <?php if ($_SESSION['editMode']): ?>
                <button class="add-button" onclick="addGalleryItem()">
                    <i class="fas fa-plus"></i> Add Photo
                </button>
            <?php endif; ?>
        </div>

        <div class="grid-lg-3">
            <?php foreach ($gallery as $index => $photo): ?>
                <div class="gallery-item">
                    <div class="gallery-image-container">
                        <?php if ($photo['image']): ?>
                            <img src="<?= $photo['image'] ?>" alt="<?= htmlspecialchars($photo['title']) ?>" class="gallery-image">
                        <?php else: ?>
                            <div class="gallery-placeholder">
                                <i class="fas fa-camera"></i>
                            </div>
                        <?php endif; ?>
                        <?php if ($_SESSION['editMode']): ?>
                            <button class="upload-button-gallery" onclick="uploadGalleryImage(<?= $index ?>)">
                                <i class="fas fa-upload"></i>
                            </button>
                            <button class="delete-button-gallery" onclick="removeGalleryItem(<?= $index ?>)">
                                <i class="fas fa-trash"></i>
                            </button>
                        <?php endif; ?>
                    </div>
                    <div class="gallery-content">
                        <h3 class="gallery-title"><?= renderEditableInput($photo['title'], "gallery[$index][title]") ?></h3>
                        <p class="gallery-description">
                            <?= renderEditableInput($photo['description'], "gallery[$index][description]") ?>
                        </p>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>
    </div>
    <?php
    return ob_get_clean();
}

function renderAdvocacySection($advocacy)
{
    ob_start();
    ?>
    <div class="content-grid">
        <h2 class="section-title">Advocacy for Social Change</h2>

        <div class="card">
            <h3 class="advocacy-title"><?= renderEditableInput($advocacy['title'], 'advocacy[title]') ?></h3>

            <div class="advocacy-grid">
                <div class="advocacy-section">
                    <h4 class="advocacy-subtitle">The Issue</h4>
                    <p class="advocacy-text"><?= renderEditableInput($advocacy['issue'], 'advocacy[issue]', 'text', true) ?>
                    </p>
                </div>

                <div class="advocacy-section">
                    <div class="section-header">
                        <h4 class="advocacy-subtitle">Causes</h4>
                        <?php if ($_SESSION['editMode']): ?>
                            <button class="add-button-small" onclick="addAdvocacyItem('causes')">
                                <i class="fas fa-plus"></i> Add
                            </button>
                        <?php endif; ?>
                    </div>
                    <ul class="advocacy-list">
                        <?php foreach ($advocacy['causes'] as $index => $cause): ?>
                            <li class="advocacy-list-item">
                                <?= $_SESSION['editMode'] ?
                                    "<input type='text' value='" . htmlspecialchars($cause) . "' class='advocacy-input' name='advocacy[causes][$index]'>" :
                                    htmlspecialchars($cause) ?>
                                <?php if ($_SESSION['editMode']): ?>
                                    <button class="remove-item-btn" onclick="removeAdvocacyItem('causes', <?= $index ?>)">
                                        <i class="fas fa-times"></i>
                                    </button>
                                <?php endif; ?>
                            </li>
                        <?php endforeach; ?>
                    </ul>
                </div>

                <div class="advocacy-section">
                    <div class="section-header">
                        <h4 class="advocacy-subtitle">Effects</h4>
                        <?php if ($_SESSION['editMode']): ?>
                            <button class="add-button-small" onclick="addAdvocacyItem('effects')">
                                <i class="fas fa-plus"></i> Add
                            </button>
                        <?php endif; ?>
                    </div>
                    <ul class="advocacy-list">
                        <?php foreach ($advocacy['effects'] as $index => $effect): ?>
                            <li class="advocacy-list-item">
                                <?= $_SESSION['editMode'] ?
                                    "<input type='text' value='" . htmlspecialchars($effect) . "' class='advocacy-input' name='advocacy[effects][$index]'>" :
                                    htmlspecialchars($effect) ?>
                                <?php if ($_SESSION['editMode']): ?>
                                    <button class="remove-item-btn" onclick="removeAdvocacyItem('effects', <?= $index ?>)">
                                        <i class="fas fa-times"></i>
                                    </button>
                                <?php endif; ?>
                            </li>
                        <?php endforeach; ?>
                    </ul>
                </div>

                <div class="advocacy-section">
                    <div class="section-header">
                        <h4 class="advocacy-subtitle">Process of Change</h4>
                        <?php if ($_SESSION['editMode']): ?>
                            <button class="add-button-small" onclick="addAdvocacyItem('solutions')">
                                <i class="fas fa-plus"></i> Add
                            </button>
                        <?php endif; ?>
                    </div>
                    <ul class="advocacy-list">
                        <?php foreach ($advocacy['solutions'] as $index => $solution): ?>
                            <li class="advocacy-list-item">
                                <?= $_SESSION['editMode'] ?
                                    "<input type='text' value='" . htmlspecialchars($solution) . "' class='advocacy-input' name='advocacy[solutions][$index]'>" :
                                    htmlspecialchars($solution) ?>
                                <?php if ($_SESSION['editMode']): ?>
                                    <button class="remove-item-btn" onclick="removeAdvocacyItem('solutions', <?= $index ?>)">
                                        <i class="fas fa-times"></i>
                                    </button>
                                <?php endif; ?>
                            </li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            </div>
        </div>

        <div class="card">
            <h3 class="advocacy-my-actions-title">My Actions</h3>
            <p class="advocacy-text"><?= renderEditableInput($advocacy['myActions'], 'advocacy[myActions]', 'text', true) ?>
            </p>
        </div>
    </div>
    <?php
    return ob_get_clean();
}

?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>✨ Personal Portfolio ✨</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: "Inter", "Segoe UI", -apple-system, BlinkMacSystemFont, sans-serif;
            background-color: #fefcff;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }

        /* Header Styles */
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 50%, #f093fb 100%);
            color: white;
            box-shadow: 0 20px 40px rgba(102, 126, 234, 0.15);
            position: relative;
            overflow: visible;
            z-index: 1000;
        }

        .header-overlay {
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(45deg, rgba(255, 255, 255, 0.1) 0%, transparent 50%, rgba(255, 255, 255, 0.05) 100%);
            pointer-events: none;
        }

        .header-content {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px 24px;
            position: relative;
            z-index: 2;
        }

        .header-top {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            gap: 16px;
        }

        .logo-section {
            display: flex;
            align-items: center;
            gap: 16px;
            flex: 1;
        }

        .logo {
            width: 48px;
            height: 48px;
            border-radius: 12px;
            object-fit: cover;
            border: 2px solid rgba(255, 255, 255, 0.3);
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
        }

        .logo-placeholder {
            width: 48px;
            height: 48px;
            border-radius: 12px;
            background: rgba(255, 255, 255, 0.2);
            display: flex;
            align-items: center;
            justify-content: center;
            border: 2px dashed rgba(255, 255, 255, 0.4);
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .logo-placeholder:hover {
            background: rgba(255, 255, 255, 0.3);
            border-color: rgba(255, 255, 255, 0.6);
        }

        .title {
            font-size: 28px;
            font-weight: 700;
            margin: 0;
            background: linear-gradient(45deg, #ffffff 0%, #f8fafc 100%);
            background-clip: text;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            text-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            flex: 1;
        }

        .admin-controls {
            display: flex;
            align-items: center;
            gap: 12px;
            flex-wrap: wrap;
        }

        .button {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 10px 18px;
            background-color: rgba(255, 255, 255, 0.15);
            color: white;
            border: none;
            border-radius: 12px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            backdrop-filter: blur(10px);
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
            text-decoration: none;
        }

        .button:hover {
            background-color: rgba(255, 255, 255, 0.25);
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.15);
        }

        .button-green {
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
            box-shadow: 0 4px 15px rgba(16, 185, 129, 0.3);
        }

        .button-red {
            background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
            box-shadow: 0 4px 15px rgba(239, 68, 68, 0.3);
        }

        /* Navigation */
        .nav {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }

        .nav-item {
            position: relative;
        }

        .nav-button {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 12px 20px;
            background-color: transparent;
            color: white;
            border: none;
            border-radius: 12px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            backdrop-filter: blur(10px);
        }

        .nav-button:hover,
        .nav-button.active {
            background-color: rgba(255, 255, 255, 0.2);
            box-shadow: 0 4px 15px rgba(255, 255, 255, 0.1);
            transform: translateY(-1px);
        }

        .dropdown {
            position: absolute;
            left: 0;
            top: 100%;
            margin-top: 8px;
            width: 220px;
            background-color: rgba(255, 255, 255, 0.95);
            color: #374151;
            border-radius: 16px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.15);
            opacity: 0;
            visibility: hidden;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            z-index: 99999;
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255, 255, 255, 0.2);
            overflow: hidden;
        }

        .dropdown.visible {
            opacity: 1;
            visibility: visible;
            transform: translateY(0);
        }

        .dropdown-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            width: 100%;
            text-align: left;
            padding: 12px 16px;
            background-color: transparent;
            color: #374151;
            border: none;
            cursor: pointer;
            font-size: 14px;
            transition: all 0.2s ease;
            border-bottom: 1px solid rgba(0, 0, 0, 0.05);
        }

        .dropdown-item:hover {
            background-color: rgba(102, 126, 234, 0.08);
            color: #667eea;
        }

        /* Mobile Menu Button */
        .mobile-menu-button {
            display: none;
            align-items: center;
            gap: 8px;
            padding: 12px 20px;
            background-color: rgba(255, 255, 255, 0.15);
            color: white;
            border: none;
            border-radius: 12px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            backdrop-filter: blur(10px);
        }

        .mobile-menu-button:hover {
            background-color: rgba(255, 255, 255, 0.25);
            transform: translateY(-2px);
        }

        /* Mobile Navigation Overlay */
        .mobile-nav-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.8);
            z-index: 9999;
            opacity: 0;
            visibility: hidden;
            transition: all 0.3s ease;
        }

        .mobile-nav-overlay.active {
            opacity: 1;
            visibility: visible;
        }

        .mobile-nav {
            position: fixed;
            top: 0;
            right: -100%;
            width: 300px;
            height: 100vh;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 50%, #f093fb 100%);
            z-index: 10000;
            transition: all 0.3s ease;
            padding: 20px;
            overflow-y: auto;
        }

        .mobile-nav.active {
            right: 0;
        }

        .mobile-nav-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 20px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.2);
        }

        .mobile-nav-title {
            color: white;
            font-size: 18px;
            font-weight: 600;
        }

        .mobile-nav-close {
            background: none;
            border: none;
            color: white;
            font-size: 24px;
            cursor: pointer;
            padding: 5px;
            border-radius: 8px;
            transition: all 0.3s ease;
        }

        .mobile-nav-close:hover {
            background: rgba(255, 255, 255, 0.1);
        }

        .mobile-nav-list {
            list-style: none;
            padding: 0;
            margin: 0;
        }

        .mobile-nav-item {
            margin-bottom: 8px;
        }

        .mobile-nav-button {
            display: flex;
            align-items: center;
            gap: 12px;
            width: 100%;
            padding: 16px;
            background: none;
            border: none;
            color: white;
            font-size: 16px;
            font-weight: 500;
            text-align: left;
            border-radius: 12px;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .mobile-nav-button:hover,
        .mobile-nav-button.active {
            background: rgba(255, 255, 255, 0.15);
            transform: translateX(5px);
        }

        .mobile-nav-submenu {
            margin-left: 20px;
            margin-top: 8px;
            padding-left: 16px;
            border-left: 2px solid rgba(255, 255, 255, 0.3);
        }

        .mobile-nav-submenu-item {
            margin-bottom: 4px;
        }

        .mobile-nav-subbutton {
            display: block;
            width: 100%;
            padding: 12px 16px;
            background: none;
            border: none;
            color: rgba(255, 255, 255, 0.8);
            font-size: 14px;
            text-align: left;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .mobile-nav-subbutton:hover,
        .mobile-nav-subbutton.active {
            background: rgba(255, 255, 255, 0.1);
            color: white;
            transform: translateX(5px);
        }

        /* Main Content */
        .main {
            max-width: 1400px;
            margin: 0 auto;
            padding: 40px 24px;
            flex: 1;
            position: relative;
            z-index: 1;
        }

        .content-grid {
            display: grid;
            gap: 24px;
        }

        .grid-md-2 {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 24px;
        }

        .grid-lg-3 {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 24px;
        }

        .card {
            background-color: white;
            border-radius: 20px;
            padding: 32px;
            box-shadow: 0 8px 30px rgba(0, 0, 0, 0.06);
            margin-bottom: 24px;
            border: 1px solid rgba(255, 255, 255, 0.8);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
        }

        .card:hover {
            transform: translateY(-4px);
            box-shadow: 0 16px 40px rgba(0, 0, 0, 0.12);
            border-color: rgba(102, 126, 234, 0.2);
        }

        .overview-card {
            background-color: white;
            border-radius: 20px;
            padding: 32px;
            box-shadow: 0 8px 30px rgba(0, 0, 0, 0.06);
            border: 2px solid transparent;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            cursor: pointer;
            position: relative;
            overflow: hidden;
        }

        .overview-card:hover {
            transform: translateY(-4px);
            box-shadow: 0 16px 40px rgba(0, 0, 0, 0.12);
            border-color: #667eea;
        }

        .family-card {
            text-align: center;
        }

        .family-card:hover {
            transform: translateY(-6px);
            box-shadow: 0 20px 50px rgba(102, 126, 234, 0.15);
        }

        /* Profile Section */
        .text-center {
            text-align: center;
        }

        .profile-container {
            position: relative;
            display: inline-block;
        }

        .profile-image {
            width: 140px;
            height: 140px;
            border-radius: 50%;
            margin: 0 auto 32px;
            object-fit: cover;
            border: 4px solid rgba(102, 126, 234, 0.1);
            box-shadow: 0 8px 30px rgba(102, 126, 234, 0.2);
        }

        .profile-placeholder {
            width: 140px;
            height: 140px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 50%, #f093fb 100%);
            border-radius: 50%;
            margin: 0 auto 32px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 56px;
            font-weight: 700;
            box-shadow: 0 8px 30px rgba(102, 126, 234, 0.3);
            border: 4px solid rgba(255, 255, 255, 0.2);
        }

        .profile-name {
            font-size: 36px;
            font-weight: 700;
            color: #1f2937;
            margin-bottom: 12px;
            line-height: 1.2;
        }

        .profile-title {
            font-size: 18px;
            color: #6b7280;
            font-weight: 400;
            line-height: 1.5;
        }

        /* Form Elements */
        .editable-input,
        .inline-input,
        .advocacy-input {
            width: 100%;
            padding: 8px;
            border: 1px solid #ccc;
            border-radius: 4px;
            font-family: inherit;
            font-size: inherit;
        }

        .editable-textarea {
            width: 100%;
            padding: 8px;
            border: 1px solid #ccc;
            border-radius: 4px;
            resize: none;
            font-family: inherit;
            font-size: inherit;
            min-height: 60px;
        }

        .icon-input {
            width: 40px;
            text-align: center;
            border: none;
            background: transparent;
            font-size: 32px;
        }

        /* Utility Classes */
        .section-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 32px;
        }

        .section-title {
            font-size: 32px;
            font-weight: 700;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            background-clip: text;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin: 0;
            line-height: 1.2;
        }

        .card-title {
            font-size: 20px;
            font-weight: 600;
            margin-bottom: 20px;
            color: #1f2937;
        }

        .card-title-colored {
            font-size: 20px;
            font-weight: 600;
            margin-bottom: 12px;
            color: #667eea;
        }

        .card-subtitle {
            color: #6b7280;
            font-size: 16px;
            margin-bottom: 6px;
            font-weight: 500;
        }

        .card-subtitle-blue {
            color: #3b82f6;
            font-size: 18px;
            margin-bottom: 8px;
        }

        .card-meta {
            color: #9ca3af;
            font-size: 14px;
            margin-bottom: 16px;
        }

        .card-description {
            color: #6b7280;
            line-height: 1.6;
        }

        .facts-list {
            color: #6b7280;
            line-height: 2;
            font-size: 16px;
        }

        .fact-item {
            display: flex;
            align-items: center;
            margin-bottom: 12px;
        }

        .fact-label {
            font-weight: 600;
            min-width: 80px;
            color: #374151;
        }

        .about-text {
            color: #6b7280;
            line-height: 1.7;
            font-size: 16px;
        }

        /* Buttons */
        .add-button {
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
            color: white;
            border: none;
            border-radius: 12px;
            padding: 12px 20px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 8px;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            box-shadow: 0 4px 15px rgba(16, 185, 129, 0.3);
        }

        .add-button:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(16, 185, 129, 0.4);
        }

        .add-button-small {
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
            color: white;
            border: none;
            border-radius: 8px;
            padding: 6px 12px;
            cursor: pointer;
            font-size: 12px;
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 6px;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            box-shadow: 0 4px 15px rgba(16, 185, 129, 0.3);
        }

        .upload-button {
            position: absolute;
            bottom: 8px;
            right: 8px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 10px;
            border-radius: 50%;
            border: none;
            cursor: pointer;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
            transition: all 0.3s ease;
        }

        .upload-button:hover {
            transform: scale(1.1);
            box-shadow: 0 6px 20px rgba(102, 126, 234, 0.4);
        }

        .upload-button-center {
            position: absolute;
            bottom: -8px;
            right: calc(50% - 40px);
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 8px;
            border-radius: 50%;
            border: none;
            cursor: pointer;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
            transition: all 0.3s ease;
        }

        .upload-button-small {
            position: absolute;
            bottom: -4px;
            right: -4px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 4px;
            border-radius: 50%;
            border: none;
            cursor: pointer;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
            transition: all 0.3s ease;
        }

        .upload-button-gallery {
            position: absolute;
            top: 8px;
            right: 8px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 8px;
            border-radius: 50%;
            border: none;
            cursor: pointer;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
            transition: all 0.3s ease;
        }

        .delete-button {
            position: absolute;
            top: 12px;
            right: 12px;
            background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
            color: white;
            padding: 8px;
            border-radius: 50%;
            border: none;
            cursor: pointer;
            box-shadow: 0 4px 15px rgba(239, 68, 68, 0.3);
            transition: all 0.3s ease;
            z-index: 10;
        }

        .delete-button:hover {
            transform: scale(1.1);
            box-shadow: 0 6px 20px rgba(239, 68, 68, 0.4);
        }

        .delete-button-large {
            background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
            color: white;
            border: none;
            border-radius: 12px;
            padding: 12px 20px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 8px;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            box-shadow: 0 4px 15px rgba(239, 68, 68, 0.3);
        }

        .delete-button-small {
            position: absolute;
            top: 0;
            right: 20px;
            background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
            color: white;
            padding: 4px;
            border-radius: 50%;
            border: none;
            cursor: pointer;
            box-shadow: 0 4px 15px rgba(239, 68, 68, 0.3);
            transition: all 0.3s ease;
            z-index: 10;
        }

        .delete-button-gallery {
            position: absolute;
            top: 8px;
            left: 8px;
            background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
            color: white;
            padding: 8px;
            border-radius: 50%;
            border: none;
            cursor: pointer;
            box-shadow: 0 4px 15px rgba(239, 68, 68, 0.3);
            transition: all 0.3s ease;
        }

        .remove-item-btn {
            background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
            color: white;
            border: none;
            border-radius: 50%;
            padding: 2px;
            cursor: pointer;
            margin-left: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            width: 20px;
            height: 20px;
        }

        .button-group {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }

        /* Avatars */
        .avatar-medium {
            width: 80px;
            height: 80px;
            border-radius: 50%;
            object-fit: cover;
            border: 3px solid rgba(102, 126, 234, 0.1);
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
            margin: 0 auto;
        }

        .avatar-placeholder-medium {
            width: 80px;
            height: 80px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 32px;
            font-weight: 600;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
            border: 3px solid rgba(255, 255, 255, 0.2);
            margin: 0 auto;
        }

        .avatar-large {
            width: 96px;
            height: 96px;
            border-radius: 50%;
            object-fit: cover;
            border: 3px solid rgba(102, 126, 234, 0.1);
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
            margin: 0 auto;
        }

        .avatar-placeholder-large {
            width: 96px;
            height: 96px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 32px;
            font-weight: 600;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
            border: 3px solid rgba(255, 255, 255, 0.2);
            margin: 0 auto;
        }

        .avatar-small {
            width: 72px;
            height: 72px;
            border-radius: 50%;
            object-fit: cover;
            border: 3px solid rgba(102, 126, 234, 0.1);
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
        }

        .avatar-placeholder-small {
            width: 72px;
            height: 72px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 28px;
            font-weight: 600;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
            border: 3px solid rgba(255, 255, 255, 0.2);
        }

        .friend-avatar {
            background: linear-gradient(135deg, #a855f7 0%, #ec4899 100%);
        }

        .avatar-small-preview {
            width: 36px;
            height: 36px;
            background: linear-gradient(135deg, #a855f7 0%, #ec4899 100%);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 14px;
            font-weight: 600;
            box-shadow: 0 4px 15px rgba(168, 85, 247, 0.3);
            border: 2px solid rgba(255, 255, 255, 0.2);
        }

        .avatar-container {
            position: relative;
            display: inline-block;
        }

        .family-avatar-container {
            margin-bottom: 20px;
            margin-top: 12px;
        }

        .family-member-card {
            text-align: center;
        }

        .family-member-avatar {
            text-align: center;
            margin-bottom: 20px;
        }

        .member-name {
            font-size: 20px;
            color: #667eea;
            margin-bottom: 12px;
            font-weight: 600;
        }

        .member-description {
            color: #6b7280;
            line-height: 1.6;
            font-size: 14px;
        }

        .member-count {
            color: #6b7280;
            font-size: 12px;
            margin-bottom: 8px;
        }

        .member-preview {
            color: #6b7280;
            font-size: 14px;
            line-height: 1.5;
            margin-bottom: 16px;
        }

        .click-indicator {
            position: absolute;
            top: 12px;
            left: 12px;
            background-color: #667eea;
            color: white;
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 10px;
            font-weight: 600;
            opacity: 0.8;
        }

        .click-hint {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            color: #667eea;
            font-size: 12px;
            font-weight: 500;
            margin-top: auto;
            padding-top: 12px;
            border-top: 1px solid #f1f5f9;
        }

        /* Friends Section */
        .friends-preview {
            display: flex;
            gap: 8px;
            align-items: center;
            flex-wrap: wrap;
        }

        .more-friends {
            color: #667eea;
            font-size: 14px;
            font-weight: 500;
            margin-left: 8px;
        }

        .friend-item {
            text-align: center;
            position: relative;
        }

        .friend-avatar-container {
            position: relative;
            display: inline-block;
        }

        .friend-name {
            font-size: 14px;
            color: #6b7280;
            margin-top: 8px;
        }

        /* Collections Section */
        .collection-card {
            text-align: center;
        }

        .collection-icon {
            width: 64px;
            height: 64px;
            background-color: #fef2f2;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 12px;
        }

        .collection-emoji {
            font-size: 32px;
        }

        .collection-name {
            font-size: 18px;
            font-weight: 600;
            color: #1f2937;
            margin-bottom: 12px;
        }

        .collection-description {
            color: #6b7280;
            font-size: 14px;
            text-align: center;
        }

        /* Achievements Section */
        .achievements-list {
            display: grid;
            gap: 16px;
        }

        .achievement-item {
            display: flex;
            align-items: center;
            gap: 20px;
            background-color: white;
            border-radius: 20px;
            padding: 28px;
            box-shadow: 0 8px 30px rgba(0, 0, 0, 0.06);
            margin-bottom: 16px;
            border: 1px solid rgba(255, 255, 255, 0.8);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
        }

        .achievement-icon {
            width: 56px;
            height: 56px;
            background: linear-gradient(135deg, #fbbf24 0%, #f59e0b 100%);
            border-radius: 16px;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 4px 15px rgba(251, 191, 36, 0.3);
            color: #d97706;
            font-size: 24px;
        }

        .achievement-content {
            flex: 1;
        }

        .achievement-title {
            font-size: 18px;
            font-weight: 600;
            color: #1f2937;
            margin-bottom: 4px;
        }

        .achievement-description {
            color: #6b7280;
            margin-bottom: 4px;
            font-size: 16px;
        }

        .achievement-year {
            font-size: 14px;
            color: #3b82f6;
        }

        /* Gallery Section */
        .gallery-item {
            background-color: white;
            border-radius: 20px;
            overflow: hidden;
            box-shadow: 0 8px 30px rgba(0, 0, 0, 0.06);
            border: 1px solid rgba(255, 255, 255, 0.8);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
        }

        .gallery-image-container {
            position: relative;
        }

        .gallery-image {
            width: 100%;
            height: 220px;
            object-fit: cover;
        }

        .gallery-placeholder {
            width: 100%;
            height: 220px;
            background: linear-gradient(135deg, #e0e7ff 0%, #c7d2fe 50%, #ddd6fe 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 48px;
            color: #6b7280;
        }

        .gallery-content {
            padding: 16px;
        }

        .gallery-title {
            font-weight: 600;
            color: #1f2937;
            margin-bottom: 8px;
            font-size: 18px;
        }

        .gallery-description {
            font-size: 14px;
            color: #6b7280;
        }

        /* Advocacy Section */
        .advocacy-grid {
            display: grid;
            gap: 24px;
        }

        .advocacy-section {
            margin-bottom: 24px;
        }

        .advocacy-title {
            font-size: 20px;
            font-weight: 600;
            color: #1f2937;
            margin-bottom: 16px;
        }

        .advocacy-subtitle {
            font-weight: 600;
            color: #3b82f6;
            margin-bottom: 8px;
            font-size: 18px;
        }

        .advocacy-text {
            color: #6b7280;
            font-size: 16px;
        }

        .advocacy-list {
            color: #6b7280;
            line-height: 1.8;
            padding-left: 20px;
            font-size: 16px;
            list-style: none;
        }

        .advocacy-list-item {
            margin-bottom: 4px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .advocacy-list-item::before {
            content: "•";
            margin-right: 8px;
        }

        .advocacy-my-actions-title {
            font-size: 18px;
            font-weight: 600;
            color: #1f2937;
            margin-bottom: 16px;
        }

        /* Lists */
        .list {
            color: #6b7280;
            line-height: 1.8;
            list-style: none;
            padding-left: 0;
        }

        .list-item {
            margin-bottom: 8px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        /* Footer */
        .footer {
            background: linear-gradient(135deg, #1e293b 0%, #334155 50%, #475569 100%);
            color: white;
            text-align: center;
            margin-top: auto;
            position: relative;
            overflow: hidden;
            padding: 32px 0;
        }

        .footer-overlay {
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(45deg, rgba(102, 126, 234, 0.1) 0%, transparent 50%, rgba(240, 147, 251, 0.1) 100%);
            pointer-events: none;
        }

        .footer-content {
            max-width: 1400px;
            margin: 0 auto;
            padding: 0 24px;
            position: relative;
            z-index: 2;
        }

        /* Login Modal */
        .login-modal {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 50%, #f093fb 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            z-index: 9999;
        }

        .login-card {
            background-color: rgba(255, 255, 255, 0.95);
            padding: 40px;
            border-radius: 24px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.2);
            width: 480px;
            max-width: 90vw;
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255, 255, 255, 0.3);
        }

        .form-group {
            margin-bottom: 24px;
        }

        .form-label {
            display: block;
            color: #374151;
            font-size: 14px;
            font-weight: 600;
            margin-bottom: 8px;
        }

        .form-input {
            width: 100%;
            padding: 14px 16px;
            border: 2px solid #e5e7eb;
            border-radius: 12px;
            font-size: 16px;
            outline: none;
            transition: all 0.3s ease;
            font-family: inherit;
            background-color: rgba(255, 255, 255, 0.8);
        }

        .form-input:focus {
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
            background-color: white;
        }

        .form-row {
            display: flex;
            gap: 16px;
        }

        .button-primary {
            flex: 1;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 14px 24px;
            border-radius: 12px;
            border: none;
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
        }

        .button-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(102, 126, 234, 0.4);
        }

        .button-secondary {
            flex: 1;
            background-color: #f3f4f6;
            color: #374151;
            padding: 14px 24px;
            border-radius: 12px;
            border: none;
            cursor: pointer;
            font-size: 16px;
            font-weight: 500;
            transition: all 0.3s ease;
        }

        /* GitHub Token Field Styling */
        .form-input[name="github_token"] {
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 14px;
            letter-spacing: 0.5px;
        }

        /* Login form instructions */
        details {
            cursor: pointer;
        }

        details summary {
            padding: 8px;
            border-radius: 6px;
            transition: background-color 0.2s ease;
        }

        details summary:hover {
            background-color: rgba(59, 130, 246, 0.1);
        }

        details[open] summary {
            margin-bottom: 8px;
        }

        /* Error message styling */
        .error-message {
            animation: shake 0.5s ease-in-out;
        }

        @keyframes shake {

            0%,
            100% {
                transform: translateX(0);
            }

            25% {
                transform: translateX(-5px);
            }

            75% {
                transform: translateX(5px);
            }
        }

        /* Save Status Indicator */
        .save-status {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 12px 20px;
            border-radius: 8px;
            color: white;
            font-weight: 500;
            z-index: 10000;
            opacity: 0;
            transition: all 0.3s ease;
            font-size: 14px;
        }

        .save-status.success {
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
            opacity: 1;
        }

        .save-status.error {
            background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
            opacity: 1;
        }

        .save-status.saving {
            background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
            opacity: 1;
        }

        /* Debug Button */
        .debug-button {
            position: fixed;
            top: 100px;
            right: 20px;
            z-index: 9999;
            background: #ff6b6b;
            color: white;
            border: none;
            padding: 10px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 12px;
        }

        /* Mobile Responsive */
        @media (max-width: 768px) {
            .header-content {
                padding: 12px 16px;
            }

            .header-top {
                flex-direction: column;
                align-items: flex-start;
                gap: 12px;
                margin-bottom: 12px;
            }

            .logo-section {
                width: 100%;
                gap: 12px;
            }

            .title {
                font-size: 18px;
            }

            .admin-controls {
                width: 100%;
                gap: 6px;
                justify-content: flex-start;
            }

            .button {
                padding: 8px 12px;
                font-size: 12px;
                border-radius: 8px;
                gap: 4px;
            }

            /* Hide desktop nav, show mobile menu button */
            .nav {
                display: none;
            }

            .mobile-menu-button {
                display: flex;
            }

            .main {
                padding: 20px 16px;
            }

            .card,
            .overview-card {
                border-radius: 16px;
                padding: 20px;
                margin-bottom: 16px;
            }

            .content-grid,
            .grid-md-2,
            .grid-lg-3 {
                gap: 16px;
                grid-template-columns: 1fr;
            }

            .section-header {
                flex-direction: column;
                gap: 12px;
                margin-bottom: 20px;
            }

            .section-title {
                font-size: 24px;
                text-align: center;
            }

            .profile-image,
            .profile-placeholder {
                width: 100px;
                height: 100px;
                margin-bottom: 20px;
            }

            .profile-name {
                font-size: 28px;
            }

            .footer-content {
                padding: 0 16px;
            }

            .debug-button {
                top: 80px;
                right: 10px;
                padding: 8px;
                font-size: 10px;
            }

            /* Mobile Nav styles adjustments */
            .mobile-nav {
                width: 280px;
            }

            .mobile-nav-button {
                padding: 12px;
                font-size: 14px;
            }

            .mobile-nav-subbutton {
                padding: 8px 12px;
                font-size: 13px;
            }
        }

        .placeholder {
            padding: 40px;
            text-align: center;
            color: #6b7280;
        }

        .hidden {
            display: none !important;
        }
    </style>
</head>

<body>
    <?php if ($_SESSION['showLogin']): ?>
        <!-- Login Modal -->
        <div class="login-modal">
            <div class="login-card">
                <h2 style="font-size: 24px; font-weight: bold; text-align: center; margin-bottom: 24px;">🔐 Admin Login</h2>

                <?php
                $envToken = getEnvGitHubToken();
                $hasEnvToken = $envToken && $envToken !== 'your_github_token_here';
                ?>

                <div
                    style="background: <?= $hasEnvToken ? '#f0f9ff' : '#fef3c7' ?>; padding: 12px; border-radius: 8px; margin-bottom: 20px; border: 1px solid <?= $hasEnvToken ? '#0ea5e9' : '#f59e0b' ?>;">
                    <div
                        style="color: <?= $hasEnvToken ? '#0369a1' : '#92400e' ?>; font-size: 14px; display: flex; align-items: center; gap: 8px;">
                        <i class="fas <?= $hasEnvToken ? 'fa-check-circle' : 'fa-exclamation-triangle' ?>"></i>
                        <?php if ($hasEnvToken): ?>
                            <span><strong>GitHub token found in .env</strong> - You can login without entering a token</span>
                        <?php else: ?>
                            <span><strong>No .env token configured</strong> - Please provide your GitHub token below</span>
                        <?php endif; ?>
                    </div>
                </div>

                <?php if (isset($GLOBALS['loginError'])): ?>
                    <div
                        style="color: #ef4444; text-align: center; margin-bottom: 16px; background: #fef2f2; padding: 12px; border-radius: 8px; border: 1px solid #fecaca;">
                        <i class="fas fa-exclamation-triangle"></i> <?= $GLOBALS['loginError'] ?>
                    </div>
                <?php endif; ?>

                <form method="POST">
                    <input type="hidden" name="action" value="login">
                    <div class="form-group">
                        <label class="form-label">
                            <i class="fas fa-user"></i> Username
                        </label>
                        <input type="text" name="username" class="form-input" required placeholder="Enter admin username"
                            value="veronica">
                    </div>
                    <div class="form-group">
                        <label class="form-label">
                            <i class="fas fa-lock"></i> Password
                        </label>
                        <input type="password" name="password" class="form-input" required
                            placeholder="Enter admin password">
                    </div>
                    <div class="form-group">
                        <label class="form-label">
                            <i class="fab fa-github"></i> GitHub Personal Access Token
                            <span style="color: #6b7280; font-weight: normal;">
                                <?= $hasEnvToken ? '(Optional - will use .env token if not provided)' : '(Required)' ?>
                            </span>
                        </label>
                        <input type="password" name="github_token" class="form-input" <?= $hasEnvToken ? '' : 'required' ?>
                            placeholder="<?= $hasEnvToken ? 'ghp_xxxxxxxxxxxx (optional)' : 'ghp_xxxxxxxxxxxx (required)' ?>">
                        <div style="color: #6b7280; font-size: 12px; margin-top: 4px;">
                            <i class="fas fa-info-circle"></i>
                            <?= $hasEnvToken ? 'Leave empty to use .env token, or provide your own for write access' : 'Required for saving changes to GitHub repository' ?>
                        </div>
                    </div>
                    <div class="form-row">
                        <button type="submit" class="button-primary">
                            <i class="fas fa-sign-in-alt"></i> Login
                        </button>
                        <button type="button" class="button-secondary" onclick="window.location.reload()">
                            <i class="fas fa-times"></i> Cancel
                        </button>
                    </div>
                </form>

                <?php if (!$hasEnvToken): ?>
                    <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #e5e7eb;">
                        <div style="background: #f9fafb; padding: 16px; border-radius: 8px; border: 1px solid #d1d5db;">
                            <h4 style="margin: 0 0 8px 0; color: #374151; font-size: 14px;">
                                <i class="fas fa-lightbulb" style="color: #f59e0b;"></i> Pro Tip: Configure .env file
                            </h4>
                            <p style="margin: 0; color: #6b7280; font-size: 12px;">
                                Create a <code>.env</code> file with <code>GITHUB_TOKEN=your_token_here</code> so visitors can
                                see content without requiring login.
                            </p>
                        </div>
                    </div>
                <?php endif; ?>

                <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #e5e7eb;">
                    <details style="color: #6b7280; font-size: 12px;">
                        <summary style="cursor: pointer; color: #3b82f6;">
                            <i class="fas fa-question-circle"></i> How to get a GitHub token?
                        </summary>
                        <div style="margin-top: 8px; padding-left: 16px;">
                            <p>1. Go to GitHub → Settings → Developer settings → Personal access tokens</p>
                            <p>2. Generate new token (classic) with <strong>repo</strong> permissions</p>
                            <p>3. Copy the token and use it above or in your .env file</p>
                            <p style="color: #ef4444; margin-top: 4px;">
                                <i class="fas fa-shield-alt"></i> Keep your token secure - don't share it!
                            </p>
                        </div>
                    </details>
                </div>
            </div>
        </div>
    <?php else: ?>
        <!-- Header -->
        <header class="header">
            <div class="header-overlay"></div>
            <div class="header-content">
                <div class="header-top">
                    <div class="logo-section">
                        <h1 class="title">✨ Personal Portfolio ✨</h1>

                        <!-- Cloud Status Indicator -->
                        <?php if ($_SESSION['isAdmin']): ?>
                            <div
                                style="display: flex; align-items: center; gap: 8px; font-size: 12px; color: rgba(255, 255, 255, 0.8);">
                                <?php
                                $statusColor = '#ef4444'; // default red
                                $statusText = 'Offline';

                                if ($cloudStatus === 'online-write') {
                                    $statusColor = '#10b981'; // green
                                    $statusText = '🔗 Full Access (Read+Write)';
                                } elseif ($cloudStatus === 'online-read') {
                                    $statusColor = '#f59e0b'; // yellow
                                    $statusText = '👁️ Read-Only Access';
                                } elseif ($cloudStatus === 'online') {
                                    $statusColor = '#10b981'; // green
                                    $statusText = '🔗 GitHub Connected';
                                } else {
                                    $statusText = '⚠️ GitHub Offline';
                                }
                                ?>
                                <div
                                    style="width: 8px; height: 8px; border-radius: 50%; background-color: <?= $statusColor ?>;">
                                </div>
                                <span><?= $statusText ?></span>
                            </div>
                        <?php endif; ?>
                    </div>

                    <div class="admin-controls">
                        <?php if ($_SESSION['isAdmin']): ?>
                            <form method="POST" style="display: inline;">
                                <input type="hidden" name="action" value="toggle_edit">
                                <button type="submit" class="button">
                                    <i class="fas <?= $_SESSION['editMode'] ? 'fa-times' : 'fa-edit' ?>"></i>
                                    <span><?= $_SESSION['editMode'] ? 'Cancel' : 'Edit' ?></span>
                                </button>
                            </form>

                            <?php if ($_SESSION['editMode']): ?>
                                <button type="button" class="button button-green" onclick="robustSaveToGitHub()">
                                    <i class="fas fa-save"></i>
                                    <span>Save to GitHub</span>
                                </button>
                            <?php endif; ?>

                            <button class="button" onclick="exportCurrentData()">
                                <i class="fas fa-download"></i>
                                <span>Export</span>
                            </button>

                            <form method="POST" style="display: inline;">
                                <input type="hidden" name="action" value="logout">
                                <button type="submit" class="button button-red">
                                    <i class="fas fa-sign-out-alt"></i>
                                    <span>Logout</span>
                                </button>
                            </form>
                        <?php else: ?>
                            <form method="POST" style="display: inline;">
                                <input type="hidden" name="action" value="show_login">
                                <button type="submit" class="button">
                                    <i class="fas fa-lock"></i>
                                    <span>Admin</span>
                                </button>
                            </form>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- Desktop Navigation -->
                <nav class="nav">
                    <?php foreach (generateMenuItems() as $item): ?>
                        <?php
                        $isActive = $_SESSION['activeSection'] === $item['id'];
                        if (isset($item['subItems'])) {
                            foreach ($item['subItems'] as $subItem) {
                                if ($_SESSION['activeSection'] === $subItem['id']) {
                                    $isActive = true;
                                    break;
                                }
                            }
                        }
                        ?>
                        <div class="nav-item" onmouseenter="showDropdown(this)" onmouseleave="hideDropdown(this)">
                            <form method="POST" style="display: inline;">
                                <input type="hidden" name="action" value="navigate">
                                <input type="hidden" name="section" value="<?= $item['id'] ?>">
                                <button type="submit" class="nav-button <?= $isActive ? 'active' : '' ?>">
                                    <i class="<?= $item['icon'] ?>"></i>
                                    <span><?= htmlspecialchars($item['label']) ?></span>
                                </button>
                            </form>

                            <?php if (isset($item['subItems']) && !empty($item['subItems'])): ?>
                                <div class="dropdown">
                                    <?php foreach ($item['subItems'] as $subItem): ?>
                                        <div class="dropdown-item">
                                            <form method="POST" style="flex: 1;">
                                                <input type="hidden" name="action" value="navigate">
                                                <input type="hidden" name="section" value="<?= $subItem['id'] ?>">
                                                <button type="submit"
                                                    style="background: none; border: none; color: <?= $_SESSION['activeSection'] === $subItem['id'] ? '#667eea' : '#374151' ?>; cursor: pointer; font-size: 14px; flex: 1; text-align: left; padding: 0; width: 100%;">
                                                    <?= htmlspecialchars($subItem['label']) ?>
                                                </button>
                                            </form>
                                        </div>
                                    <?php endforeach; ?>
                                </div>
                            <?php endif; ?>
                        </div>
                    <?php endforeach; ?>
                </nav>

                <!-- Mobile Menu Button -->
                <button class="mobile-menu-button" onclick="toggleMobileMenu()">
                    <i class="fas fa-bars"></i>
                    <span>Menu</span>
                </button>
            </div>
        </header>

        <!-- Mobile Navigation Overlay -->
        <div class="mobile-nav-overlay" id="mobileNavOverlay" onclick="closeMobileMenu()"></div>

        <!-- Mobile Navigation -->
        <nav class="mobile-nav" id="mobileNav">
            <div class="mobile-nav-header">
                <span class="mobile-nav-title">Navigation</span>
                <button class="mobile-nav-close" onclick="closeMobileMenu()">
                    <i class="fas fa-times"></i>
                </button>
            </div>

            <ul class="mobile-nav-list">
                <?php foreach (generateMenuItems() as $item): ?>
                    <?php
                    $isActive = $_SESSION['activeSection'] === $item['id'];
                    if (isset($item['subItems'])) {
                        foreach ($item['subItems'] as $subItem) {
                            if ($_SESSION['activeSection'] === $subItem['id']) {
                                $isActive = true;
                                break;
                            }
                        }
                    }
                    ?>
                    <li class="mobile-nav-item">
                        <form method="POST" style="width: 100%;">
                            <input type="hidden" name="action" value="navigate">
                            <input type="hidden" name="section" value="<?= $item['id'] ?>">
                            <button type="submit" class="mobile-nav-button <?= $isActive ? 'active' : '' ?>">
                                <i class="<?= $item['icon'] ?>"></i>
                                <span><?= htmlspecialchars($item['label']) ?></span>
                            </button>
                        </form>

                        <?php if (isset($item['subItems']) && !empty($item['subItems'])): ?>
                            <ul class="mobile-nav-submenu">
                                <?php foreach ($item['subItems'] as $subItem): ?>
                                    <li class="mobile-nav-submenu-item">
                                        <form method="POST" style="width: 100%;">
                                            <input type="hidden" name="action" value="navigate">
                                            <input type="hidden" name="section" value="<?= $subItem['id'] ?>">
                                            <button type="submit"
                                                class="mobile-nav-subbutton <?= $_SESSION['activeSection'] === $subItem['id'] ? 'active' : '' ?>">
                                                <?= htmlspecialchars($subItem['label']) ?>
                                            </button>
                                        </form>
                                    </li>
                                <?php endforeach; ?>
                            </ul>
                        <?php endif; ?>
                    </li>
                <?php endforeach; ?>
            </ul>
        </nav>

        <!-- Main Content -->
        <main class="main">
            <?= renderContent() ?>
        </main>

        <!-- Footer -->
        <footer class="footer">
            <div class="footer-overlay"></div>
            <div class="footer-content">
                <p style="font-size: 16px; font-weight: 500; margin-bottom: 8px;">&copy; 2024 My Personal Website. All
                    rights reserved.</p>
                <p style="color: #cbd5e1; font-size: 14px;">Built with ❤️ and PHP | Secure .env configuration</p>

                <?php
                $envToken = getEnvGitHubToken();
                $hasEnvToken = $envToken && $envToken !== 'your_github_token_here';
                ?>

                <?php if ($_SESSION['isAdmin']): ?>
                    <?php if ($cloudStatus === 'online-write'): ?>
                        <p style="color: #10b981; font-size: 12px; margin-top: 8px;">
                            ✅ Full GitHub access - Changes will be saved automatically!
                        </p>
                    <?php elseif ($cloudStatus === 'online-read'): ?>
                        <p style="color: #f59e0b; font-size: 12px; margin-top: 8px;">
                            👁️ Read-only access - Please provide admin token for saving changes
                        </p>
                    <?php else: ?>
                        <p style="color: #ef4444; font-size: 12px; margin-top: 8px;">
                            🔐 No GitHub access - Please login with valid token
                        </p>
                    <?php endif; ?>
                <?php else: ?>
                    <?php if ($hasEnvToken): ?>
                        <p style="color: #10b981; font-size: 12px; margin-top: 8px;">
                            🌍 Content loaded from GitHub via secure .env configuration
                        </p>
                    <?php else: ?>
                        <p style="color: #f59e0b; font-size: 12px; margin-top: 8px;">
                            ⚙️ Configure .env file for automatic GitHub content loading
                        </p>
                    <?php endif; ?>
                <?php endif; ?>
            </div>
        </footer>
    <?php endif; ?>

    <!-- Save Status Indicator -->
    <div id="saveStatus" class="save-status"></div>

    <script>
        // ===================================
        // MOBILE NAVIGATION FUNCTIONS
        // ===================================

        function toggleMobileMenu() {
            const overlay = document.getElementById('mobileNavOverlay');
            const nav = document.getElementById('mobileNav');

            overlay.classList.add('active');
            nav.classList.add('active');
            document.body.style.overflow = 'hidden'; // Prevent scrolling when menu is open
        }

        function closeMobileMenu() {
            const overlay = document.getElementById('mobileNavOverlay');
            const nav = document.getElementById('mobileNav');

            overlay.classList.remove('active');
            nav.classList.remove('active');
            document.body.style.overflow = ''; // Restore scrolling
        }

        // Close mobile menu when window is resized to desktop
        window.addEventListener('resize', function () {
            if (window.innerWidth > 768) {
                closeMobileMenu();
            }
        });

        // ===================================
        // MOBILE-FRIENDLY MODAL DIALOG SYSTEM
        // ===================================

        let currentModalConfig = null;

        function showModal(title, inputs, callback) {
            const modal = document.getElementById('customModal');
            const modalTitle = document.getElementById('modalTitle');
            const modalInputs = document.getElementById('modalInputs');

            if (!modal || !modalTitle || !modalInputs) {
                console.error('Modal elements not found');
                return;
            }

            modalTitle.textContent = title;
            modalInputs.innerHTML = '';

            // Store the callback for later use
            currentModalConfig = { callback, inputs: [] };

            // Create input fields
            inputs.forEach((input, index) => {
                const inputElement = input.type === 'textarea'
                    ? document.createElement('textarea')
                    : document.createElement('input');

                inputElement.type = input.type || 'text';
                inputElement.placeholder = input.placeholder || '';
                inputElement.value = input.defaultValue || '';
                inputElement.className = input.type === 'textarea' ? 'modal-textarea' : 'modal-input';
                inputElement.required = input.required || false;

                modalInputs.appendChild(inputElement);
                currentModalConfig.inputs.push(inputElement);

                // Focus first input
                if (index === 0) {
                    setTimeout(() => inputElement.focus(), 100);
                }
            });

            // Show modal
            modal.classList.add('active');
            document.body.style.overflow = 'hidden';
        }

        function closeModal() {
            const modal = document.getElementById('customModal');
            if (modal) {
                modal.classList.remove('active');
                document.body.style.overflow = '';
            }
            currentModalConfig = null;
        }

        function submitModal() {
            if (!currentModalConfig) {
                console.error('No modal config found');
                return;
            }

            const values = currentModalConfig.inputs.map(input => input.value.trim());

            // Check if all required fields are filled
            const allFilled = currentModalConfig.inputs.every((input, index) =>
                !input.required || values[index] !== ''
            );

            if (!allFilled) {
                alert('Please fill in all required fields');
                return;
            }

            // Call the callback with the values
            try {
                currentModalConfig.callback(values);
                closeModal();
            } catch (error) {
                console.error('Error in modal callback:', error);
                closeModal();
            }
        }

        // Close modal when clicking outside
        document.addEventListener('DOMContentLoaded', function () {
            const modal = document.getElementById('customModal');
            if (modal) {
                modal.addEventListener('click', function (e) {
                    if (e.target === this) {
                        closeModal();
                    }
                });

                // Handle Enter key for modal inputs
                modal.addEventListener('keydown', function (e) {
                    if (e.key === 'Enter' && !e.shiftKey) {
                        const target = e.target;
                        if (target && (target.classList.contains('modal-input') || target.classList.contains('modal-textarea'))) {
                            e.preventDefault();
                            submitModal();
                        }
                    }
                    if (e.key === 'Escape') {
                        closeModal();
                    }
                });
            }
        });

        // ===================================
        // FIXED SAVE SYSTEM - PROPER FORM DATA HANDLING
        // ===================================

        function robustSaveToGitHub() {
            console.log('🚀 Starting robust save to GitHub...');

            // Show saving status
            showSaveStatus('saving', 'Saving to GitHub...');

            // Disable save button
            const saveBtn = document.querySelector('button[onclick="robustSaveToGitHub()"]');
            if (saveBtn) {
                saveBtn.disabled = true;
                saveBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> <span>Saving...</span>';
            }

            // Create proper form data - this is the fix!
            const form = document.createElement('form');
            form.style.display = 'none';
            document.body.appendChild(form);

            // Add action field
            const actionInput = document.createElement('input');
            actionInput.type = 'hidden';
            actionInput.name = 'action';
            actionInput.value = 'robust_save';
            form.appendChild(actionInput);

            let fieldsCollected = 0;
            const collectedFields = {};

            // Get all editable inputs with their current values
            const inputSelectors = [
                'input.editable-input',
                'textarea.editable-textarea',
                'input.inline-input',
                'input.advocacy-input',
                'input.icon-input',
                'input[name^="personal["]',
                'input[name^="education["]',
                'input[name^="family["]',
                'input[name^="friends["]',
                'input[name^="collections["]',
                'input[name^="achievements["]',
                'input[name^="gallery["]',
                'input[name^="advocacy["]',
                'textarea[name^="personal["]',
                'textarea[name^="education["]',
                'textarea[name^="family["]',
                'textarea[name^="friends["]',
                'textarea[name^="collections["]',
                'textarea[name^="achievements["]',
                'textarea[name^="gallery["]',
                'textarea[name^="advocacy["]'
            ];

            inputSelectors.forEach(selector => {
                const inputs = document.querySelectorAll(selector);
                console.log(`📊 Found ${inputs.length} inputs for selector: ${selector}`);

                inputs.forEach(input => {
                    if (input.name && input.value !== undefined && !collectedFields[input.name]) {
                        // Create hidden input to properly send the field
                        const hiddenInput = document.createElement('input');
                        hiddenInput.type = 'hidden';
                        hiddenInput.name = input.name;
                        hiddenInput.value = input.value;
                        form.appendChild(hiddenInput);

                        collectedFields[input.name] = input.value;
                        fieldsCollected++;
                        console.log(`📝 Collected: ${input.name} = "${input.value}" (from ${selector})`);
                    }
                });
            });

            // Also try a more general approach to catch any missed fields
            const allInputs = document.querySelectorAll('input, textarea, select');
            allInputs.forEach(input => {
                if (input.name &&
                    input.value !== undefined &&
                    !collectedFields[input.name] &&
                    (input.name.includes('[') && input.name.includes(']'))) {

                    // Create hidden input to properly send the field
                    const hiddenInput = document.createElement('input');
                    hiddenInput.type = 'hidden';
                    hiddenInput.name = input.name;
                    hiddenInput.value = input.value;
                    form.appendChild(hiddenInput);

                    collectedFields[input.name] = input.value;
                    fieldsCollected++;
                    console.log(`📝 Collected (general): ${input.name} = "${input.value}"`);
                }
            });

            console.log(`✅ Total collected: ${fieldsCollected} form fields`);
            console.log('📊 All collected fields:', collectedFields);

            if (fieldsCollected === 0) {
                console.warn('⚠️ No fields collected! This might be the issue.');
                showSaveStatus('error', '❌ No fields found to save');
                document.body.removeChild(form);
                if (saveBtn) {
                    saveBtn.disabled = false;
                    saveBtn.innerHTML = '<i class="fas fa-save"></i> <span>Save to GitHub</span>';
                }
                return;
            }

            // Create FormData from the form (this preserves field names correctly)
            const formData = new FormData(form);

            // Debug: log what will actually be sent
            console.log('📤 Sending to server:');
            for (let [key, value] of formData.entries()) {
                console.log(`  ${key}: ${value}`);
            }

            // Send to server
            fetch('', {
                method: 'POST',
                body: formData
            })
                .then(response => {
                    console.log('📊 Response status:', response.status);
                    console.log('📊 Response headers:', response.headers.get('content-type'));

                    if (!response.ok) {
                        throw new Error(`HTTP ${response.status}`);
                    }

                    return response.text(); // Get as text first to debug
                })
                .then(responseText => {
                    console.log('📊 Raw response:', responseText);

                    // Try to parse as JSON
                    let result;
                    try {
                        result = JSON.parse(responseText);
                    } catch (parseError) {
                        console.error('❌ JSON Parse Error:', parseError);
                        console.error('❌ Response text:', responseText);
                        throw new Error('Server returned invalid JSON. Check for PHP errors.');
                    }

                    console.log('📊 Parsed result:', result);

                    if (result.success) {
                        showSaveStatus('success', `✅ Saved ${result.fields_updated}/${result.fields_processed} fields to GitHub!`);
                        console.log(`✅ Successfully saved ${result.fields_updated} out of ${result.fields_processed} fields to GitHub`);

                        if (result.unrecognized_fields && result.unrecognized_fields.length > 0) {
                            console.warn('⚠️ Some fields were not recognized:', result.unrecognized_fields);
                        }
                    } else {
                        throw new Error(result.message || 'Save failed');
                    }
                })
                .catch(error => {
                    console.error('❌ Save failed:', error);

                    // Check if it's a GitHub token issue
                    if (error.message.includes('GitHub token') || error.message.includes('401') || error.message.includes('403')) {
                        showSaveStatus('error', '🔐 GitHub token expired - Please login again');
                        setTimeout(() => {
                            if (confirm('GitHub token may be expired. Would you like to login again?')) {
                                // Trigger logout and redirect to login
                                const form = document.createElement('form');
                                form.method = 'POST';
                                form.innerHTML = '<input type="hidden" name="action" value="logout">';
                                document.body.appendChild(form);
                                form.submit();
                            }
                        }, 2000);
                    } else {
                        showSaveStatus('error', `❌ Save failed: ${error.message}`);
                    }
                })
                .finally(() => {
                    // Clean up the temporary form
                    if (form && form.parentNode) {
                        document.body.removeChild(form);
                    }

                    // Re-enable save button
                    if (saveBtn) {
                        saveBtn.disabled = false;
                        saveBtn.innerHTML = '<i class="fas fa-save"></i> <span>Save to GitHub</span>';
                    }
                });
        }

        // Debugging function to check current form state
        function debugFormState() {
            console.log('🔍 DEBUGGING FORM STATE:');

            const allInputs = document.querySelectorAll('input, textarea, select');
            const foundFields = {};

            allInputs.forEach(input => {
                if (input.name) {
                    foundFields[input.name] = {
                        value: input.value,
                        type: input.type || input.tagName,
                        className: input.className
                    };
                }
            });

            console.log('📊 All form fields found:', foundFields);

            // Check specifically for editable fields
            const editableInputs = document.querySelectorAll('.editable-input, .editable-textarea');
            console.log(`📊 Found ${editableInputs.length} editable inputs`);

            editableInputs.forEach(input => {
                console.log(`📝 Editable: ${input.name} = "${input.value}" (${input.className})`);
            });
        }

        // Add debug button (temporary - remove in production)
        function addDebugButton() {
            const debugBtn = document.createElement('button');
            debugBtn.innerHTML = '🔍 Debug';
            debugBtn.onclick = debugFormState;
            debugBtn.className = 'debug-button';
            document.body.appendChild(debugBtn);
        }

        // Show save status with auto-hide
        function showSaveStatus(type, message) {
            const statusEl = document.getElementById('saveStatus');
            statusEl.className = `save-status ${type}`;
            statusEl.innerHTML = `<i class="fas ${type === 'saving' ? 'fa-spinner fa-spin' : type === 'success' ? 'fa-check' : 'fa-exclamation-triangle'}"></i> ${message}`;

            // Auto-hide after delay (except for saving status)
            if (type !== 'saving') {
                setTimeout(() => {
                    statusEl.className = 'save-status';
                }, 6000); // Increased timeout to read the message
            }
        }

        // Improved auto-save on input changes (debounced)
        let autoSaveTimeout;
        document.addEventListener('input', function (e) {
            if (e.target.matches('.editable-input, .editable-textarea, .inline-input, .advocacy-input, .icon-input') ||
                (e.target.name && (e.target.name.includes('[') && e.target.name.includes(']')))) {

                console.log(`🔄 Input changed: ${e.target.name} = "${e.target.value}"`);

                clearTimeout(autoSaveTimeout);
                autoSaveTimeout = setTimeout(() => {
                    console.log(`🔄 Auto-saving field: ${e.target.name} = "${e.target.value}"`);
                    // Simple session update without GitHub save
                    const formData = new FormData();
                    formData.append('action', 'robust_save');
                    formData.append(e.target.name, e.target.value);

                    fetch('', {
                        method: 'POST',
                        body: formData
                    }).catch(err => console.log('Auto-save failed:', err));
                }, 1000);
            }
        });

        // Export current data
        function exportCurrentData() {
            console.log('📦 Exporting current data...');

            // Get base session data
            const data = <?= json_encode($_SESSION['content']) ?>;

            // Override with current form values
            const inputs = document.querySelectorAll('.editable-input, .editable-textarea, .inline-input, .advocacy-input, .icon-input');

            inputs.forEach(input => {
                if (input.name && input.value !== undefined) {
                    const fieldName = input.name;
                    const value = input.value;

                    // Parse field name and update data
                    if (fieldName.startsWith('personal[')) {
                        const key = fieldName.match(/personal\[([^\]]+)\]/)[1];
                        data.personal[key] = value;
                    } else if (fieldName.startsWith('advocacy[')) {
                        const key = fieldName.match(/advocacy\[([^\]]+)\]/)[1];
                        data.advocacy[key] = value;
                    }
                    // Add more parsing as needed
                }
            });

            // Download file
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `website-data-${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

            console.log('✅ Export completed');
        }

        // Navigation functions
        function navigateToSection(section) {
            const form = document.createElement('form');
            form.method = 'POST';
            form.innerHTML = `
                <input type="hidden" name="action" value="navigate">
                <input type="hidden" name="section" value="${section}">
            `;
            document.body.appendChild(form);
            form.submit();
        }

        // Dropdown functionality
        function showDropdown(navItem) {
            const dropdown = navItem.querySelector('.dropdown');
            if (dropdown) {
                dropdown.classList.add('visible');
            }
        }

        function hideDropdown(navItem) {
            const dropdown = navItem.querySelector('.dropdown');
            if (dropdown) {
                dropdown.classList.remove('visible');
            }
        }

        // Content management functions (simplified and working)
        function addEducationLevel() {
            const key = prompt('Enter education level key (e.g., "masters"):');
            const title = prompt('Enter education level title (e.g., "Master\'s Degree"):');
            if (key && title) {
                submitForm('add_education', { key, title });
            }
        }

        function removeEducationLevel(key) {
            if (confirm('Remove this education level?')) {
                submitForm('remove_education', { key });
            }
        }

        function addSubject(sectionKey) {
            const subject = prompt('Enter subject name:');
            if (subject) {
                submitForm('add_subject', { section_key: sectionKey, subject });
            }
        }

        function removeSubject(sectionKey, index) {
            if (confirm('Remove this subject?')) {
                submitForm('remove_subject', { section_key: sectionKey, index });
            }
        }

        function addActivity(sectionKey) {
            const activity = prompt('Enter activity name:');
            if (activity) {
                submitForm('add_activity', { section_key: sectionKey, activity });
            }
        }

        function removeActivity(sectionKey, index) {
            if (confirm('Remove this activity?')) {
                submitForm('remove_activity', { section_key: sectionKey, index });
            }
        }

        function addFamilyMember() {
            const key = prompt('Enter family category key (e.g., "uncle"):');
            const title = prompt('Enter family category title (e.g., "My Uncles"):');
            if (key && title) {
                submitForm('add_family', { key, title });
            }
        }

        function removeFamilyMember(key) {
            if (confirm('Remove this family category?')) {
                submitForm('remove_family', { key });
            }
        }

        function addPersonToFamily(familyKey) {
            submitForm('add_person_to_family', { familyKey });
        }

        function removePersonFromFamily(familyKey, index) {
            if (confirm('Remove this person?')) {
                submitForm('remove_person_from_family', { familyKey, index });
            }
        }

        function addCollection() {
            console.log('addCollection function called');
            const name = prompt('Enter collection name:');
            if (!name) return;

            const icon = prompt('Enter collection icon (emoji):');
            if (!icon) return;

            const description = prompt('Enter collection description:');
            if (!description) return;

            console.log('Submitting collection:', { name, icon, description });
            submitForm('add_collection', { name, icon, description });
        }

        function removeCollection(index) {
            if (confirm('Remove this collection?')) {
                submitForm('remove_collection', { index });
            }
        }

        function addAchievement() {
            const title = prompt('Enter achievement title:');
            if (!title) return;

            const year = prompt('Enter achievement year:');
            if (!year) return;

            const description = prompt('Enter achievement description:');
            if (!description) return;

            submitForm('add_achievement', { title, year, description });
        }

        function removeAchievement(index) {
            if (confirm('Remove this achievement?')) {
                submitForm('remove_achievement', { index });
            }
        }

        function addGalleryItem() {
            const title = prompt('Enter photo title:');
            if (!title) return;

            const description = prompt('Enter photo description:');
            if (!description) return;

            submitForm('add_gallery_item', { title, description });
        }

        function removeGalleryItem(index) {
            if (confirm('Remove this gallery item?')) {
                submitForm('remove_gallery_item', { index });
            }
        }

        function addAdvocacyItem(type) {
            const item = prompt(`Enter new ${type} item:`);
            if (item) {
                submitForm('add_advocacy_item', { type, item });
            }
        }

        function removeAdvocacyItem(type, index) {
            if (confirm(`Remove this ${type} item?`)) {
                submitForm('remove_advocacy_item', { type, index });
            }
        }

        function addFriendsCategory() {
            const key = prompt('Enter friends category key (e.g., "work"):');
            if (!key) return;

            const title = prompt('Enter friends category title (e.g., "Work Colleagues"):');
            if (!title) return;

            const description = prompt('Enter category description:');
            if (!description) return;

            submitForm('add_friends_category', { key, title, description });
        }

        function removeFriendsCategory(key) {
            if (confirm('Remove this friends category?')) {
                submitForm('remove_friends_category', { key });
            }
        }

        function addFriend(friendKey) {
            const name = prompt('Enter friend name:');
            if (name) {
                submitForm('add_friend', { friend_key: friendKey, name });
            }
        }

        function removeFriend(friendKey, index) {
            if (confirm('Remove this friend?')) {
                submitForm('remove_friend', { friend_key: friendKey, index });
            }
        }

        // Helper function to submit forms with better error handling
        function submitForm(action, data) {
            try {
                console.log('Submitting form with action:', action, 'and data:', data);

                const form = document.createElement('form');
                form.method = 'POST';
                form.style.display = 'none';

                // Add action
                const actionInput = document.createElement('input');
                actionInput.type = 'hidden';
                actionInput.name = 'action';
                actionInput.value = action;
                form.appendChild(actionInput);

                // Add data fields
                Object.keys(data).forEach(key => {
                    const input = document.createElement('input');
                    input.type = 'hidden';
                    input.name = key;
                    input.value = data[key];
                    form.appendChild(input);
                    console.log('Added field:', key, '=', data[key]);
                });

                document.body.appendChild(form);
                console.log('Submitting form...');
                form.submit();
            } catch (error) {
                console.error('Error submitting form:', error);
                alert('Error submitting form: ' + error.message);
            }
        }

        // ===================================
        // COMPLETE IMAGE UPLOAD IMPLEMENTATION
        // ===================================

        function uploadImage(imageType) {
            const input = document.createElement('input');
            input.type = 'file';
            input.accept = 'image/*';
            input.onchange = function (e) {
                const file = e.target.files[0];
                if (file) {
                    // Check file size (limit to 2MB for GitHub API)
                    if (file.size > 2 * 1024 * 1024) {
                        alert('Image size must be less than 2MB');
                        return;
                    }

                    const reader = new FileReader();
                    reader.onload = function (e) {
                        const imageUrl = e.target.result; // Base64 data URL

                        // Update the UI immediately
                        const profileContainer = document.querySelector('.profile-container');
                        if (profileContainer) {
                            const existingImg = profileContainer.querySelector('.profile-image');
                            const existingPlaceholder = profileContainer.querySelector('.profile-placeholder');

                            if (existingImg) {
                                existingImg.src = imageUrl;
                            } else if (existingPlaceholder) {
                                existingPlaceholder.outerHTML = `<img src="${imageUrl}" alt="Profile" class="profile-image">`;
                            }

                            // Update hidden input for form save
                            const hiddenInput = profileContainer.querySelector('input[name="personal[profileImage]"]');
                            if (hiddenInput) {
                                hiddenInput.value = imageUrl;
                            }
                        }

                        // Save to server
                        saveImageToServer('personal', 'profileImage', imageUrl);
                    };
                    reader.readAsDataURL(file);
                }
            };
            input.click();
        }

        function uploadFamilyImage(familyKey, index) {
            const input = document.createElement('input');
            input.type = 'file';
            input.accept = 'image/*';
            input.onchange = function (e) {
                const file = e.target.files[0];
                if (file) {
                    if (file.size > 2 * 1024 * 1024) {
                        alert('Image size must be less than 2MB');
                        return;
                    }

                    const reader = new FileReader();
                    reader.onload = function (e) {
                        const imageUrl = e.target.result;

                        // Update UI immediately
                        const memberCards = document.querySelectorAll('.family-member-card');
                        if (memberCards[index]) {
                            const avatarContainer = memberCards[index].querySelector('.avatar-container');
                            if (avatarContainer) {
                                avatarContainer.innerHTML = `<img src="${imageUrl}" alt="Family Member" class="avatar-large">`;
                                if (document.querySelector('.editable-input')) {
                                    avatarContainer.innerHTML += `<button class="upload-button-center" onclick="uploadFamilyImage('${familyKey}', ${index})"><i class="fas fa-upload"></i></button>`;
                                }
                            }
                        }

                        // Save to server
                        saveImageToServer('family', `${familyKey}[list][${index}][image]`, imageUrl);
                    };
                    reader.readAsDataURL(file);
                }
            };
            input.click();
        }

        function uploadFriendImage(friendKey, index) {
            const input = document.createElement('input');
            input.type = 'file';
            input.accept = 'image/*';
            input.onchange = function (e) {
                const file = e.target.files[0];
                if (file) {
                    if (file.size > 2 * 1024 * 1024) {
                        alert('Image size must be less than 2MB');
                        return;
                    }

                    const reader = new FileReader();
                    reader.onload = function (e) {
                        const imageUrl = e.target.result;

                        // Update UI immediately
                        const friendItems = document.querySelectorAll('.friend-item');
                        if (friendItems[index]) {
                            const avatarContainer = friendItems[index].querySelector('.friend-avatar-container');
                            if (avatarContainer) {
                                avatarContainer.innerHTML = `<img src="${imageUrl}" alt="Friend" class="avatar-small">`;
                                if (document.querySelector('.editable-input')) {
                                    avatarContainer.innerHTML += `<button class="upload-button-small" onclick="uploadFriendImage('${friendKey}', ${index})"><i class="fas fa-upload"></i></button>`;
                                }
                            }
                        }

                        // Save to server
                        saveImageToServer('friends', `${friendKey}[list][${index}][image]`, imageUrl);
                    };
                    reader.readAsDataURL(file);
                }
            };
            input.click();
        }

        function uploadGalleryImage(index) {
            const input = document.createElement('input');
            input.type = 'file';
            input.accept = 'image/*';
            input.onchange = function (e) {
                const file = e.target.files[0];
                if (file) {
                    if (file.size > 2 * 1024 * 1024) {
                        alert('Image size must be less than 2MB');
                        return;
                    }

                    const reader = new FileReader();
                    reader.onload = function (e) {
                        const imageUrl = e.target.result;

                        // Update UI immediately
                        const galleryItems = document.querySelectorAll('.gallery-item');
                        if (galleryItems[index]) {
                            const imageContainer = galleryItems[index].querySelector('.gallery-image-container');
                            if (imageContainer) {
                                imageContainer.innerHTML = `<img src="${imageUrl}" alt="Gallery" class="gallery-image">`;
                                if (document.querySelector('.editable-input')) {
                                    imageContainer.innerHTML += `
                                        <button class="upload-button-gallery" onclick="uploadGalleryImage(${index})"><i class="fas fa-upload"></i></button>
                                        <button class="delete-button-gallery" onclick="removeGalleryItem(${index})"><i class="fas fa-trash"></i></button>
                                    `;
                                }
                            }
                        }

                        // Save to server
                        saveImageToServer('gallery', `${index}[image]`, imageUrl);
                    };
                    reader.readAsDataURL(file);
                }
            };
            input.click();
        }

        function saveImageToServer(section, fieldPath, imageUrl) {
            const form = document.createElement('form');
            form.method = 'POST';
            form.style.display = 'none';

            const actionInput = document.createElement('input');
            actionInput.type = 'hidden';
            actionInput.name = 'action';
            actionInput.value = 'save_image';
            form.appendChild(actionInput);

            const sectionInput = document.createElement('input');
            sectionInput.type = 'hidden';
            sectionInput.name = 'section';
            sectionInput.value = section;
            form.appendChild(sectionInput);

            const pathInput = document.createElement('input');
            pathInput.type = 'hidden';
            pathInput.name = 'field_path';
            pathInput.value = fieldPath;
            form.appendChild(pathInput);

            const imageInput = document.createElement('input');
            imageInput.type = 'hidden';
            imageInput.name = 'image_data';
            imageInput.value = imageUrl;
            form.appendChild(imageInput);

            document.body.appendChild(form);
            form.submit();
        }

        // ===================================
        // COMPLETE CONTENT MANAGEMENT IMPLEMENTATION
        // ===================================

        // (All content management functions are now above using the modal system)

        // Initialize debugging (remove in production)
        document.addEventListener('DOMContentLoaded', function () {
            //addDebugButton();
            console.log('🚀 Improved save system with mobile-friendly modals loaded and ready!');

            // Run initial debug
            setTimeout(debugFormState, 1000);
        });

        console.log('🚀 Robust save system with mobile navigation loaded and ready!');

        // Test that functions are properly defined
        console.log('✅ Functions available:', {
            addCollection: typeof addCollection,
            addAchievement: typeof addAchievement,
            addFriend: typeof addFriend,
            submitForm: typeof submitForm
        });
    </script>
</body>

</html>