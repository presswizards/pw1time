<?php

declare(strict_types=1);

/*
 * Browser verification gate (proof-of-browser challenge).
 *
 * Blocks curl, dumb bots, and blind form-POST scanners from reaching the
 * secret creation page -- without CAPTCHA and without server-side state.
 *
 * Flow:
 *   1. GET index.php            -> signed challenge (token + expiry + HMAC)
 *      rendered into JS that checks for a real browser, waits ~1.5s,
 *      then submits the challenge via a form POST to ?action=verify.
 *   2. POST ?action=verify      -> HMAC re-checked with hash_equals(),
 *      expiry enforced. If valid, a signed browser_verified cookie
 *      (Secure, HttpOnly, SameSite=Strict, 30 min) is set and the
 *      browser is redirected to pwcreate.php.
 *   3. pwcreate.php             -> requires a valid browser_verified
 *      cookie on BOTH the form GET and the creation POST.
 *
 * Stateless: nothing is stored server-side. The HMAC signature makes the
 * challenge self-validating. The HMAC secret lives outside the web root.
 */
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');

$secretFile = dirname(__DIR__) . '/.gate-secret';

const GATE_CHALLENGE_TTL = 300;   // challenge valid 5 minutes
const GATE_COOKIE_TTL = 1800;     // verified cookie valid 30 minutes

/*
 * Load the HMAC secret, creating it once (race-safe) if missing.
 * Fail closed: no secret, no verification, no creation page.
 */
function gateSecret(string $secretFile): string
{
    $secret = @is_file($secretFile) ? trim((string) @file_get_contents($secretFile)) : '';

    if ($secret === '') {
        $fresh = bin2hex(random_bytes(32));
        $fp = @fopen($secretFile, 'x');
        if ($fp) {
            fwrite($fp, $fresh . PHP_EOL);
            fclose($fp);
            @chmod($secretFile, 0600);
        }
        $secret = @is_file($secretFile) ? trim((string) @file_get_contents($secretFile)) : '';
    }

    return $secret;
}

/* Signed browser_verified cookie value: "<exp>|<hmac>". */
function gateCookieValue(string $secret, int $exp): string
{
    return $exp . '|' . hash_hmac('sha256', 'verified|' . $exp, $secret);
}

function gateCookieValid(string $secret): bool
{
    $raw = (string) ($_COOKIE['browser_verified'] ?? '');
    $parts = explode('|', $raw, 2);
    if (count($parts) !== 2 || !ctype_digit($parts[0])) {
        return false;
    }
    $exp = (int) $parts[0];
    if ($exp <= time()) {
        return false;
    }
    return hash_equals(hash_hmac('sha256', 'verified|' . $exp, $secret), $parts[1]);
}

function gateFail(string $message): never
{
    http_response_code(403);
    echo '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
        . '<meta name="viewport" content="width=device-width, initial-scale=1">'
        . '<title>Verification failed</title></head>'
        . '<body style="background:#0b0f14;color:#e8edf2;font-family:system-ui,sans-serif;'
        . 'display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0">'
        . '<div style="text-align:center;max-width:26rem;padding:2rem">'
        . '<h1>Verification failed</h1><p>' . htmlspecialchars($message, ENT_QUOTES, 'UTF-8') . '</p>'
        . '<p><a style="color:#7cc4ff" href="/index.php">Try again</a></p>'
        . '</div></body></html>';
    exit;
}

$secret = gateSecret($secretFile);
if ($secret === '') {
    gateFail('The verification service is unavailable. Please try again later.');
}

/* Already verified? Skip the challenge and go straight to creation. */
if ($_SERVER['REQUEST_METHOD'] === 'GET' && gateCookieValid($secret)) {
    header('Location: /pwcreate.php', true, 303);
    exit;
}

/*
 * Verification endpoint: the browser submits the signed challenge here.
 */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_GET['action'] ?? '') === 'verify') {
    $token = (string) ($_POST['token'] ?? '');
    $exp = (string) ($_POST['exp'] ?? '');
    $sig = (string) ($_POST['sig'] ?? '');

    if (!ctype_xdigit($token) || strlen($token) !== 32 || !ctype_digit($exp) || $sig === '') {
        gateFail('Invalid challenge. Please enable JavaScript and try again.');
    }

    $expInt = (int) $exp;
    if ($expInt <= time() || $expInt > time() + GATE_CHALLENGE_TTL + 60) {
        gateFail('Challenge expired. Please try again.');
    }

    $expected = hash_hmac('sha256', $token . '|' . $exp, $secret);
    if (!hash_equals($expected, $sig)) {
        gateFail('Invalid challenge signature.');
    }

    /* Optional sanity check on the browser-reported dimensions. */
    $sw = (string) ($_POST['sw'] ?? '');
    $sh = (string) ($_POST['sh'] ?? '');
    if (($sw !== '' && (!ctype_digit($sw) || (int) $sw <= 0))
        || ($sh !== '' && (!ctype_digit($sh) || (int) $sh <= 0))) {
        gateFail('Invalid browser submission.');
    }

    $cookieExp = time() + GATE_COOKIE_TTL;
    setcookie('browser_verified', gateCookieValue($secret, $cookieExp), [
        'expires' => $cookieExp,
        'path' => '/',
        'secure' => true,
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    header('Location: /pwcreate.php', true, 303);
    exit;
}

/* Anything else that is not the challenge GET gets the challenge page. */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    gateFail('Invalid request. Please enable JavaScript and try again.');
}

$token = bin2hex(random_bytes(16));
$exp = (string) (time() + GATE_CHALLENGE_TTL);
$sig = hash_hmac('sha256', $token . '|' . $exp, $secret);

$jsToken = json_encode($token, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
$jsExp = json_encode($exp, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
$jsSig = json_encode($sig, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Verify your browser</title>
<style>
  body{background:#0b0f14;color:#e8edf2;font-family:system-ui,-apple-system,sans-serif;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}
  .card{background:#141b24;border:1px solid #243040;border-radius:12px;padding:2.5rem 2rem;text-align:center;max-width:26rem;width:90%}
  .spin{width:2.5rem;height:2.5rem;border:3px solid #243040;border-top-color:#7cc4ff;border-radius:50%;margin:0 auto 1.25rem;animation:spin 1s linear infinite}
  @keyframes spin{to{transform:rotate(360deg)}}
  p{color:#9aa7b5;line-height:1.5}
</style>
</head>
<body>
<div class="card">
  <div class="spin"></div>
  <h1>Verify your browser</h1>
  <p id="status">Checking your browser before you continue&hellip;</p>
  <noscript><p>JavaScript is required to create a secret link.</p></noscript>
  <form id="verify" method="post" action="/index.php?action=verify" style="display:none">
    <input type="hidden" name="token" id="f_token">
    <input type="hidden" name="exp" id="f_exp">
    <input type="hidden" name="sig" id="f_sig">
    <input type="hidden" name="sw" id="f_sw">
    <input type="hidden" name="sh" id="f_sh">
  </form>
</div>
<script>
const token = <?php echo $jsToken; ?>;
const exp = <?php echo $jsExp; ?>;
const sig = <?php echo $jsSig; ?>;

function browserOk() {
  if (typeof window === 'undefined' || typeof document === 'undefined' || typeof navigator === 'undefined') {
    return false;
  }
  if (!window.crypto || !window.crypto.subtle) {
    return false;
  }
  if (navigator.cookieEnabled !== true) {
    return false;
  }
  if (typeof window.screen === 'undefined' || !(window.screen.width > 0) || !(window.screen.height > 0)) {
    return false;
  }
  return true;
}

if (!browserOk()) {
  document.getElementById('status').textContent = 'This page requires a standard browser with JavaScript, cookies, and Web Crypto enabled.';
} else {
  setTimeout(function () {
    document.getElementById('f_token').value = token;
    document.getElementById('f_exp').value = exp;
    document.getElementById('f_sig').value = sig;
    document.getElementById('f_sw').value = String(window.screen.width);
    document.getElementById('f_sh').value = String(window.screen.height);
    document.getElementById('verify').submit();
  }, 1500);
}
</script>
</body>
</html>
