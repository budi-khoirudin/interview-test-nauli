<?php
// =============================================================
//  Admin Feedback System — Vulnerable App (CTF Lab)
//  KISS principle: everything in one file, no framework
//  Database: SQLite for feedback storage
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

// ---------- Database Init ----------
// SQLite database untuk simpan feedback dari attacker
$db_path = '/opt/admin/logs/feedback.db';
$db = new SQLite3($db_path);

// Create table jika belum ada
$db->exec('
    CREATE TABLE IF NOT EXISTS feedback (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        message TEXT NOT NULL,
        ip TEXT,
        user_agent TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
');

// ---------- Routing ----------
$path = strtok($_SERVER['REQUEST_URI'], '?');

// robots.txt → dilayani Nginx sebagai file statis (lihat nginx.conf)
// FLAG: SCENARIO75{/api/verify-mfa} | SCENARIO75{/dashboard}

// MFA verify endpoint
if ($path === '/api/verify-mfa') {
    handle_mfa();
    exit;
}

// Dashboard — restricted area (admin melihat semua feedback dari DB)
// FLAG: SCENARIO75{/dashboard}
if ($path === '/dashboard') {
    handle_dashboard($db);
    exit;
}

// Feedback POST endpoint
// FLAG: SCENARIO75{POST}
if ($path === '/feedback') {
    handle_feedback($db);
    exit;
}

// Default: show public feedback form (attacker input di sini)
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

// ---------- Home / Public Feedback Form ----------
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
        echo '<p class="msg ok">✓ Feedback submitted. Thank you!</p>';
    }
?>
</body>
</html>
    <?php
}

// ---------- Feedback Submission ----------
function handle_feedback(SQLite3 $db): void {
    // Only POST allowed — FLAG: SCENARIO75{POST}
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        echo 'Method Not Allowed';
        return;
    }

    $name    = $_POST['name'] ?? '';
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

    // Insert feedback ke database — TIDAK ADA SANITASI (vulnerable to XSS)
    // FLAG: SCENARIO75{fetch} — fetch() is allowed; no CSP blocking it
    $ip         = $_SERVER['REMOTE_ADDR'] ?? '';
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';

    $stmt = $db->prepare('INSERT INTO feedback (name, message, ip, user_agent) VALUES (:name, :message, :ip, :ua)');
    $stmt->bindValue(':name',    $name,        SQLITE3_TEXT);
    $stmt->bindValue(':message', $message,     SQLITE3_TEXT);
    $stmt->bindValue(':ip',      $ip,          SQLITE3_TEXT);
    $stmt->bindValue(':ua',      $user_agent,  SQLITE3_TEXT);
    $stmt->execute();

    header('Location: /?msg=sent');
}

// ---------- MFA Verify ----------
function handle_mfa(): void {
    // Simulate TOTP check — always fails for non-admin
    http_response_code(401);
    echo json_encode(['status' => 'fail', 'message' => 'Invalid OTP']);
}

// ---------- Dashboard — Admin melihat semua feedback dari database ----------
// FLAG: SCENARIO75{/dashboard} | SCENARIO75{adm_sess} | SCENARIO75{xss-payload}
// FLAG: SCENARIO75{/api/verify-mfa} (skipped when valid cookie present)
// FLAG: SCENARIO75{RED_C00k13_MFA_Byp4ss_0wn3d}
function handle_dashboard(SQLite3 $db): void {
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

    // Ambil semua feedback dari database
    $result = $db->query('SELECT * FROM feedback ORDER BY created_at DESC');

    ?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Admin Dashboard</title>
<style>
  body{font-family:monospace;background:#0d0d0d;color:#00ff41;margin:40px auto;max-width:900px}
  table{width:100%;border-collapse:collapse;margin:20px 0}
  th,td{border:1px solid #0f0;padding:8px;text-align:left}
  th{background:#1a1a1a}
  .xss-payload{background:#111;padding:8px}
  .flag-box{border:2px solid #ff0;padding:12px;color:#ff0;margin-top:24px}
  .meta{color:#666;font-size:0.85em}
</style>
</head>
<body>
<h2>[ Admin Dashboard — Welcome ]</h2>
<p>Logged in as: <strong>administrator</strong></p>

<h3>Feedback Submissions:</h3>
<table>
  <thead>
    <tr>
      <th>ID</th>
      <th>Name</th>
      <th>Message</th>
      <th>Metadata</th>
    </tr>
  </thead>
  <tbody>
<?php
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        echo '<tr>';
        echo '<td>' . htmlspecialchars($row['id']) . '</td>';
        echo '<td>' . htmlspecialchars($row['name']) . '</td>';
        
        // FLAG: SCENARIO75{xss-payload}
        // INTENTIONALLY NOT SANITISED — XSS reflection di sini
        echo '<td class="xss-payload">' . $row['message'] . '</td>';
        
        echo '<td class="meta">';
        echo 'IP: ' . htmlspecialchars($row['ip']) . '<br>';
        echo 'Time: ' . htmlspecialchars($row['created_at']);
        echo '</td>';
        echo '</tr>';
    }

    // Jika tidak ada feedback
    if ($db->querySingle('SELECT COUNT(*) FROM feedback') == 0) {
        echo '<tr><td colspan="4"><em>No feedback yet.</em></td></tr>';
    }
?>
  </tbody>
</table>

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
