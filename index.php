<?php
// =============================================================
//  Admin Feedback System — Vulnerable App (CTF Lab)
//  KISS principle: everything in one file, no framework
// =============================================================

// ---------- PHASE 1: Headers & Session Init ----------
header('X-Powered-By: Node.js');          // FLAG: SCENARIO75{Node.js}
header('Content-Type: text/html; charset=utf-8');

// Issue pre-auth cookie (HttpOnly = FALSE — intentionally vulnerable)
// FLAG: SCENARIO75{pre_mfa_session} | SCENARIO75{pending_mfa_verification} | SCENARIO75{False}
if (!isset($_COOKIE['pre_mfa_session']) && !isset($_COOKIE['adm_sess_token'])) {
    setcookie('pre_mfa_session', 'pending_mfa_verification', [
        'expires'  => 0,
        'path'     => '/',
        'httponly' => false,   // INTENTIONALLY FALSE — FLAG: SCENARIO75{False}
        'samesite' => 'Lax',
    ]);
}

session_start();

// ---------- Routing ----------
$path = strtok($_SERVER['REQUEST_URI'], '?');

// robots.txt → dilayani Nginx sebagai file statis (lihat nginx.conf)
// FLAG: SCENARIO75{/api/verify-mfa} | SCENARIO75{/dashboard}

// MFA verify endpoint
if ($path === '/api/verify-mfa') {
    handle_mfa();
    exit;
}

// Dashboard — restricted area
// FLAG: SCENARIO75{/dashboard}
if ($path === '/dashboard') {
    handle_dashboard();
    exit;
}

// Feedback POST endpoint
// FLAG: SCENARIO75{POST}
if ($path === '/feedback') {
    handle_feedback();
    exit;
}

// Default: show login / feedback form
show_home();
exit;

// =============================================================
//  FUNCTIONS
// =============================================================

// ---------- Simple WAF ----------
// FLAG: SCENARIO75{403} | SCENARIO75{<svg>} | SCENARIO75{window['docu'+'ment']['coo'+'kie']}
function waf_check(string $input): bool {
    // Block <script> tags → returns false (blocked)
    if (preg_match('/<script[\s>]/i', $input)) {
        return false;
    }
    // Block literal "document.cookie"
    if (stripos($input, 'document.cookie') !== false) {
        return false;
    }
    // <svg onload=...> is ALLOWED — bypass path intentionally open
    return true;
}

// ---------- Home / Feedback Form ----------
function show_home(): void {
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Admin Feedback System</title>
<style>
  body{font-family:monospace;background:#0d0d0d;color:#00ff41;margin:40px auto;max-width:640px}
  input,textarea{width:100%;background:#111;color:#0f0;border:1px solid #0f0;padding:6px;box-sizing:border-box}
  button{background:#0f0;color:#000;border:none;padding:8px 24px;cursor:pointer;font-weight:bold}
  .msg{padding:8px;margin-top:10px}
  .err{color:#f55} .ok{color:#0f0}
</style>
</head>
<body>
<!--
  ██████╗  ██████╗ ██████╗  ██████╗ ████████╗███████╗
  ██╔══██╗██╔═══██╗██╔══██╗██╔═══██╗╚══██╔══╝██╔════╝
  ██████╔╝██║   ██║██████╔╝██║   ██║   ██║   ███████╗
  ██╔══██╗██║   ██║██╔══██╗██║   ██║   ██║   ╚════██║
  ██║  ██║╚██████╔╝██████╔╝╚██████╔╝   ██║   ███████║
  ╚═╝  ╚═╝ ╚═════╝ ╚═════╝  ╚═════╝   ╚═╝   ╚══════╝
  Hint: Have you checked robots.txt?   <!-- FLAG: SCENARIO75{robots.txt} -->
-->
<h2>[ Admin Feedback System ]</h2>
<p>Submit feedback below. All entries are reviewed by the administrator.</p>
<form action="/feedback" method="post">
  <label>Name:</label><br>
  <input type="text" name="name" required><br><br>
  <label>Message:</label><br>
  <textarea name="message" rows="5" required></textarea><br><br>
  <button type="submit">Send Feedback</button>
</form>
<?php
    $msg = $_GET['msg'] ?? '';
    if ($msg === 'blocked') {
        echo '<p class="msg err">⚠ Forbidden payload detected. (403)</p>';
    } elseif ($msg === 'sent') {
        echo '<p class="msg ok">✓ Feedback submitted.</p>';
    }
?>
</body>
</html>
    <?php
}

// ---------- Feedback Submission ----------
function handle_feedback(): void {
    // Only POST allowed — FLAG: SCENARIO75{POST}
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        echo 'Method Not Allowed';
        return;
    }

    $message = $_POST['message'] ?? '';

    // WAF check
    if (!waf_check($message)) {
        // Log WAF block to error.log
        $ts = date('Y/m/d H:i:s');
        $ip = $_SERVER['REMOTE_ADDR'] ?? '-';
        $entry = "[{$ts}] [WARN] WAF BLOCK from {$ip}: <script> tag detected in feedback submission\n";
        file_put_contents('/opt/admin/logs/error.log', $entry, FILE_APPEND | LOCK_EX);

        http_response_code(403);           // FLAG: SCENARIO75{403}
        echo '403 Forbidden — payload blocked by WAF';
        return;
    }

    // Store feedback in session so dashboard can reflect it
    // FLAG: SCENARIO75{fetch} — fetch() is allowed; no CSP blocking it
    $_SESSION['last_feedback'] = $message;

    header('Location: /?msg=sent');
}

// ---------- MFA Verify ----------
function handle_mfa(): void {
    // Simulate TOTP check — always fails for non-admin
    http_response_code(401);
    echo json_encode(['status' => 'fail', 'message' => 'Invalid OTP']);
}

// ---------- Dashboard ----------
// FLAG: SCENARIO75{/dashboard} | SCENARIO75{adm_sess} | SCENARIO75{xss-payload}
// FLAG: SCENARIO75{/api/verify-mfa} (skipped when valid cookie present)
// FLAG: SCENARIO75{RED_C00k13_MFA_Byp4ss_0wn3d}
function handle_dashboard(): void {
    $adm_cookie = $_COOKIE['adm_sess_token'] ?? '';

    // Session Replay path: if valid adm_sess_ cookie → skip MFA entirely
    // FLAG: SCENARIO75{adm_sess}
    $is_admin = str_starts_with($adm_cookie, 'adm_sess_');

    if (!$is_admin) {
        // Normal path: check PHP session login
        if (empty($_SESSION['authenticated'])) {
            // Prompt login with fake MFA (not bypassed)
            show_mfa_gate();
            return;
        }
    } else {
        // Cookie reuse — log CRITICAL event
        // FLAG: SCENARIO75{CRITICAL}
        $ts = date('Y/m/d H:i:s');
        $ip = $_SERVER['REMOTE_ADDR'] ?? '-';
        $entry = "[{$ts}] [CRITICAL] Authentication bypass anomaly detected — session replay from {$ip} cookie={$adm_cookie}\n";
        file_put_contents('/opt/admin/logs/error.log', $entry, FILE_APPEND | LOCK_EX);
    }

    // Retrieve stored XSS payload from session / cookie
    $xss_payload = $_SESSION['last_feedback'] ?? '';

    ?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Admin Dashboard</title>
<style>
  body{font-family:monospace;background:#0d0d0d;color:#00ff41;margin:40px auto;max-width:800px}
  .xss-payload{border:1px solid #0f0;padding:12px;margin:16px 0;background:#111}
  .flag-box{border:2px solid #ff0;padding:12px;color:#ff0;margin-top:24px}
</style>
</head>
<body>
<h2>[ Admin Dashboard — Welcome ]</h2>
<p>Logged in as: <strong>administrator</strong></p>

<h3>Latest Feedback:</h3>
<!-- FLAG: SCENARIO75{xss-payload} -->
<div class="xss-payload">
<?php
    // Intentionally not sanitised — XSS reflection
    echo $xss_payload ?: '<em>No feedback yet.</em>';
?>
</div>

<!-- FLAG: SCENARIO75{RED_C00k13_MFA_Byp4ss_0wn3d} -->
<div class="flag-box">
  🚩 SCENARIO75{RED_C00k13_MFA_Byp4ss_0wn3d}
</div>
</body>
</html>
    <?php
}

// ---------- Fake MFA Gate (for non-bypassed users) ----------
function show_mfa_gate(): void {
    ?>
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>MFA Required</title>
<style>body{font-family:monospace;background:#0d0d0d;color:#f90;margin:40px auto;max-width:400px}
input{width:100%;background:#111;color:#f90;border:1px solid #f90;padding:6px;box-sizing:border-box}
button{background:#f90;color:#000;border:none;padding:8px 24px;cursor:pointer;font-weight:bold}</style>
</head>
<body>
<h2>[ MFA Verification Required ]</h2>
<p>Enter your one-time password to continue.</p>
<form action="/api/verify-mfa" method="post">
  <input type="text" name="otp" placeholder="6-digit OTP" maxlength="6"><br><br>
  <button type="submit">Verify</button>
</form>
</body>
</html>
    <?php
}
