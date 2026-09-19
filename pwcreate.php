<?php

declare(strict_types=1);

/*
 * Never let the browser cache any of these pages, so the one-time
 * link page can't be resurrected from back/forward cache either.
 */
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');

$jsonFile = dirname(__DIR__) . '/pw1time.json';
$pendingDir = dirname(__DIR__) . '/.pending';
$gateSecretFile = dirname(__DIR__) . '/.gate-secret';

const MAX_ENTRIES = 500;
const ENTRY_TTL = 10 * 86400;

/* ----------------------------------------------------------
 * Browser gate helpers (challenge issued by index.php)
 * ---------------------------------------------------------- */

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

/*
 * Browser verification gate: no valid signed cookie, no creation page.
 * GETs are sent back to the challenge; POSTs are rejected outright
 * (a redirect on POST would just bounce bots into a GET loop).
 */
$gateSecret = gateSecret($gateSecretFile);
if ($gateSecret === '' || !gateCookieValid($gateSecret)) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        http_response_code(403);
        echo renderForbidden();
        exit;
    }
    header('Location: /index.php', true, 303);
    exit;
}

/*
 * POST: store a ciphertext under a freshly generated key, then either
 * return the key as JSON (browser fetch flow) or redirect (PRG) so a
 * reload never re-submits the form.
 *
 * Zero-knowledge: the browser encrypts with AES-256-GCM before sending.
 * The server only ever sees base64url ciphertext + IV. Plaintext
 * submissions are rejected -- there is no plaintext fallback.
 */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $wantsJson = (($_GET['action'] ?? '') === 'store');

    /*
     * Honeypot: a JS-hidden field real humans never fill.
     * Any content means an automated bot submitted the form.
     */
    if (trim((string) ($_POST['company'] ?? '')) !== '') {
        http_response_code(403);
        echo renderForbidden();
        exit;
    }

    $enc = (string) ($_POST['enc'] ?? '');
    $iv = (string) ($_POST['iv'] ?? '');

    $b64url = '/^[A-Za-z0-9\-_]+$/';
    $ctBytes = false;
    $ivBytes = false;
    if ($enc !== '' && $iv !== '' && preg_match($b64url, $enc) && preg_match($b64url, $iv)
        && strlen($enc) <= 5500 && strlen($iv) <= 20) {
        $ctBytes = base64_decode(strtr($enc, '-_', '+/'), true);
        $ivBytes = base64_decode(strtr($iv, '-_', '+/'), true);
    }

    /*
     * Ciphertext is plaintext + 16-byte GCM tag; plaintext is capped at
     * 4000 bytes client-side, so valid ciphertext is 17..4016 bytes and
     * the IV is exactly the 12-byte GCM nonce.
     */
    $valid = is_string($ctBytes) && is_string($ivBytes)
        && strlen($ctBytes) >= 17 && strlen($ctBytes) <= 4096
        && strlen($ivBytes) === 12;

    if (!$valid) {
        $msg = '<em>Secrets must be encrypted in your browser before sending. Please enable JavaScript and try again.</em>';
        if ($wantsJson) {
            http_response_code(400);
            header('Content-Type: application/json');
            echo json_encode(['ok' => false, 'error' => 'invalid-encryption-payload']);
            exit;
        }
        diePage(renderForm($msg));
    }

    [$stored, $keyOrError, $httpCode] = storeCipher($jsonFile, $enc, $iv);

    if (!$stored) {
        if ($wantsJson) {
            http_response_code($httpCode);
            header('Content-Type: application/json');
            echo json_encode(['ok' => false, 'error' => $keyOrError]);
            exit;
        }
        $friendly = $keyOrError === 'vault-full'
            ? 'Vault is full (500 entries max). Please retry later.'
            : 'The vault is busy. Please try again.';
        diePage(renderForm('<em>' . htmlspecialchars($friendly, ENT_QUOTES, 'UTF-8') . '</em>'));
    }
    $key = $keyOrError;

    /*
     * One-time marker so the generated link is shown exactly once;
     * the marker is removed on first view, so reloading shows the form.
     */
    if (!is_dir($pendingDir)) {
        @mkdir($pendingDir, 0700, true);
    }
    @file_put_contents($pendingDir . '/' . $key, (string) time(), LOCK_EX);

    if ($wantsJson) {
        header('Content-Type: application/json');
        echo json_encode(['ok' => true, 'key' => $key]);
        exit;
    }

    header('Location: ' . ($_SERVER['SCRIPT_NAME'] ?? '/pwcreate.php') . '?created=' . $key, true, 303);
    exit;
}

/*
 * GET with ?created=<key>: show the link once, consume the marker,
 * then fall through to the form again on any subsequent visit.
 */
$created = $_GET['created'] ?? '';
if ($created !== '' && preg_match('/^[a-f0-9]{32,128}$/i', $created)) {
    $marker = $pendingDir . '/' . $created;
    if (is_file($marker)) {
        @unlink($marker);
        renderCreated($created);
    }
}

diePage(renderForm(''));


/* ----------------------------------------------------------
 * Functions
 * ---------------------------------------------------------- */

/*
 * Store AES-GCM ciphertext + IV under a fresh key.
 * Returns [stored, key-or-error-slug, http-code].
 */
function storeCipher(string $file, string $enc, string $iv): array
{
    $key = bin2hex(random_bytes(16)); // 32 hex chars, matches /^[a-f0-9]{32,128}$/i

    $fp = @fopen($file, 'c+');

    if (!$fp || !flock($fp, LOCK_EX)) {
        if ($fp) {
            fclose($fp);
        }
        return [false, 'vault-busy', 503];
    }

    rewind($fp);
    $data = json_decode(stream_get_contents($fp) ?: '{}', true);
    if (!is_array($data)) {
        $data = [];
    }

    /*
     * Purge entries older than 10 days before enforcing the cap,
     * so expired secrets never contribute to the maximum.
     */
    $now = time();
    foreach ($data as $existingKey => $entry) {
        if (is_array($entry) && isset($entry['ts']) && is_int($entry['ts']) && ($now - $entry['ts']) > ENTRY_TTL) {
            unset($data[$existingKey]);
        }
    }

    if (count($data) >= MAX_ENTRIES) {
        flock($fp, LOCK_UN);
        fclose($fp);
        return [false, 'vault-full', 429];
    }

    /* Ciphertext only -- the server never sees plaintext or the key. */
    $data[$key] = [
        'enc' => $enc,
        'iv' => $iv,
        'ts' => $now,
    ];

    rewind($fp);
    ftruncate($fp, 0);

    fwrite(
        $fp,
        encodeVault($data) . PHP_EOL
    );

    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);

    return [true, $key, 200];
}

function encodeVault(array $data): string
{
    $json = json_encode(
        $data === [] ? (object) [] : $data,
        JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
    );

    return $json === false ? '' : $json;
}


function baseUrl(): string
{
    $host = $_SERVER['HTTP_HOST'] ?? '';

    if ($host === '' || filter_var($host, FILTER_VALIDATE_IP)) {
        return 'https://pw1time.presswizards.com';
    }

    return 'https://' . $host;
}


function diePage(string $body): never
{
    http_response_code(200);
    echo $body;
    exit;
}


function renderForbidden(): string
{
    return <<<'HTML'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>403 - Forbidden</title>

<style>
@view-transition {
    navigation: auto;
}

html {
    background: #080b10;
}

* { box-sizing: border-box; }

body {
    margin: 0;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background:
        radial-gradient(circle at 50% 40%, #14232a 0, #080b10 45%);
    color: #fff;
    font-family: system-ui, -apple-system, sans-serif;
}

.modal {
    width: min(440px, calc(100% - 40px));
    padding: 42px;
    text-align: center;
    background: rgba(15,20,27,.96);
    border: 1px solid #27313d;
    border-radius: 18px;
    box-shadow:
        0 25px 70px rgba(0,0,0,.5),
        0 0 50px rgba(44,255,198,.04);
}

h2 {
    margin: 0 0 10px;
    font-size: 25px;
}

p {
    margin: 0 0 28px;
    color: #8d98a8;
    line-height: 1.5;
}
</style>
</head>

<body>

<div class="modal">
    <div class="status-dot"></div>
    <h2>403 - Forbidden</h2>
    <p>
        This request was blocked. Please close this page and try again.
    </p>
</div>

</body>
</html>
HTML;
}


function renderForm(string $error): string
{
    $errorBlock = '';
    if ($error !== '') {
        $errorBlock = '<div class="error">' . $error . '</div>';
    }

    /*
     * Base of the share link (key id + fragment are appended in the
     * browser). Used by the password generator to display the full
     * one-time link inline without a page navigation.
     */
    $jsRevealBase = json_encode(
        baseUrl() . '/pw1time.php?key=',
        JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT
    );

    return <<<HTML
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Add to Vault</title>

<style>
@view-transition {
    navigation: auto;
}

html {
    background: #080b10;
}

* { box-sizing: border-box; }

body {
    margin: 0;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background:
        radial-gradient(circle at 50% 40%, #14232a 0, #080b10 45%);
    color: #fff;
    font-family: system-ui, -apple-system, sans-serif;
}

.modal {
    width: min(620px, calc(100% - 40px));
    padding: 42px;
    text-align: center;
    background: rgba(15,20,27,.96);
    border: 1px solid #27313d;
    border-radius: 18px;
    box-shadow:
        0 25px 70px rgba(0,0,0,.5),
        0 0 50px rgba(44,255,198,.04);
}

.header {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 10px;
    margin-bottom: 24px;
}

.status-dot {
    width: 9px;
    height: 9px;
    background: #2cffc6;
    border-radius: 50%;
    box-shadow: 0 0 12px #2cffc6;
}

.status {
    color: #2cffc6;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 12px;
    letter-spacing: 1.5px;
}

h2 {
    margin: 0 0 10px;
    font-size: 25px;
}

p {
    margin: 0 0 24px;
    color: #8d98a8;
    line-height: 1.5;
}

textarea {
    width: 100%;
    padding: 14px;
    resize: vertical;
    min-height: 88px;
    background: #090d12;
    border: 1px solid #26343b;
    border-radius: 10px;
    color: #2cffc6;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 14px;
    line-height: 1.5;
}

textarea:focus {
    outline: none;
    border-color: #2cffc6;
    box-shadow: 0 0 18px rgba(44,255,198,.15);
}

button {
    width: 100%;
    padding: 14px 24px;
    margin-top: 18px;
    border: 0;
    border-radius: 9px;
    background: #2cffc6;
    color: #07110e;
    font-size: 15px;
    font-weight: 700;
    cursor: pointer;
    transition: transform .15s, box-shadow .15s;
}

button:hover {
    transform: translateY(-1px);
    box-shadow: 0 0 25px rgba(44,255,198,.22);
}

button.secondary {
    background: transparent;
    border: 1px solid #2cffc6;
    color: #2cffc6;
    box-shadow: none;
}

button.secondary:hover {
    background: rgba(44,255,198,.12);
    box-shadow: none;
    transform: translateY(-1px);
}

button:disabled {
    opacity: .55;
    cursor: wait;
    transform: none;
}

.error {
    margin: 0 0 16px;
    padding: 10px 12px;
    text-align: center;
    border: 1px solid #8c4a3f;
    border-radius: 8px;
    background: rgba(140,74,63,.12);
    color: #ffb4a8;
    font-size: 13px;
}

.form-hint {
    margin: 16px 0 0;
    color: #56616f;
    font-size: 11px;
    line-height: 1.5;
}

.security-info {
    margin: 14px 0 0;
    color: #8d98a8;
    font-size: 12px;
    text-align: center;
}

.info-tip {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 20px;
    height: 20px;
    margin-right: 8px;
    border: 1px solid #56616f;
    border-radius: 50%;
    color: #8d98a8;
    font-size: 12px;
    font-style: normal;
    font-weight: 700;
    cursor: help;
    position: relative;
    vertical-align: middle;
}

.info-tip:hover,
.info-tip:focus {
    color: #2cffc6;
    border-color: #2cffc6;
    outline: none;
}

.info-tip::after {
    content: attr(data-tip);
    display: none;
    position: absolute;
    bottom: 130%;
    left: 50%;
    transform: translateX(-50%);
    width: 220px;
    padding: 10px 12px;
    background: #090d12;
    border: 1px solid #26343b;
    border-radius: 8px;
    color: #8d98a8;
    font-size: 12px;
    font-weight: 400;
    line-height: 1.5;
    text-align: left;
    z-index: 10;
}

.info-tip:hover::after,
.info-tip:focus::after {
    display: block;
}

#generated-result {
    margin-top: 24px;
    padding-top: 24px;
    border-top: 1px solid #27313d;
    animation: resultIn .3s ease-out;
}

@keyframes resultIn {
    from { opacity: 0; transform: translateY(-8px); }
    to { opacity: 1; transform: translateY(0); }
}

.gen-label {
    margin: 0 0 8px;
    color: #8d98a8;
    font-size: 12px;
    letter-spacing: 1px;
    text-align: center;
}

.link-box {
    min-height: 52px;
    display: flex;
    align-items: center;
    padding: 12px 14px;
    background: #090d12;
    border: 1px solid #26343b;
    border-radius: 10px;
    overflow: hidden;
}

.link {
    width: 100%;
    color: #2cffc6;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 13px;
    line-height: 1.5;
    white-space: pre-wrap;
    word-break: break-all;
    text-shadow: 0 0 12px rgba(44,255,198,.25);
}

.copy-row {
    margin-top: 12px;
    display: flex;
    justify-content: center;
}

.copy-row + .gen-label {
    margin-top: 20px;
}

.copy {
    flex-shrink: 0;
    width: auto;
    display: inline-flex;
    align-items: center;
    gap: 7px;
    padding: 9px 12px;
    border: 1px solid #2cffc6;
    border-radius: 7px;
    background: transparent;
    color: #2cffc6;
    font-weight: 600;
    font-size: 13px;
    cursor: pointer;
    transition: background .15s, color .15s;
}

.copy:hover {
    background: #2cffc6;
    color: #07110e;
}

.done {
    margin: 14px 0 0;
    color: #2cffc6;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 12px;
    letter-spacing: 1px;
    text-align: center;
}

.linklike {
    margin-top: 14px;
    padding: 0;
    background: none;
    border: 0;
    color: #56616f;
    font-size: 12px;
    font-weight: 400;
    text-decoration: underline;
    cursor: pointer;
}

.linklike:hover {
    color: #8d98a8;
    transform: none;
    box-shadow: none;
}

.company {
    position: absolute;
    left: -9999px;
    top: -9999px;
    width: 1px;
    height: 1px;
    opacity: 0;
}
</style>
</head>

<body>

<div class="modal">
<center><img src="logo-extra.png" height="50" style="max-width:225px;display:block;border:none;margin:0 auto 24px;filter:drop-shadow(1px 0 0 gray) drop-shadow(-1px 0 0 gray) drop-shadow(0 1px 0 gray) drop-shadow(0 -1px 0 gray);" alt="Watchdog Studio"></center><br>

    <div class="header">
        <div class="status-dot"></div>
        <div class="status">NEW SECRET</div>
    </div>

    <div id="create-block">
    <h2>Add to Vault</h2>

    <p>
        Enter the secret value to store.
        A one-time link valid for only 10 days will be generated for it.
    </p>

    {$errorBlock}

    <form method="post" action="pwcreate.php" id="vault-form">
        <input type="text" name="company" id="company" class="company" tabindex="-1" autocomplete="off" aria-hidden="true">
        <textarea name="value" id="secret-input" placeholder="Secret value to store ..." autofocus required></textarea>
        <button type="submit" id="submit-btn">Add To Vault</button>
    </form>
    </div>

    <div id="generated-result" style="display:none">
        <p class="gen-label">GENERATED PASSWORD</p>
        <div class="link-box">
            <div class="link" id="gen-password"></div>
        </div>
        <div class="copy-row">
            <button class="copy" id="copy-password" type="button" title="Copy password">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none"
                     stroke="currentColor" stroke-width="2"
                     stroke-linecap="round" stroke-linejoin="round"
                     style="display:block;">
                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                </svg>
                Copy
            </button>
        </div>

        <p class="gen-label">ONE-TIME SHARE LINK</p>
        <div class="link-box">
            <div class="link" id="gen-link"></div>
        </div>
        <div class="copy-row">
            <button class="copy" id="copy-link" type="button" title="Copy link">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none"
                     stroke="currentColor" stroke-width="2"
                     stroke-linecap="round" stroke-linejoin="round"
                     style="display:block;">
                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                </svg>
                Copy
            </button>
        </div>

        <div class="done" id="gen-done"></div>
    </div>

    <button type="button" id="generate-btn" class="secondary">Auto-Generate Password + Link</button>
    <button type="button" id="gen-back" class="linklike" style="display:none">&lt; Back</button>

    <noscript><p class="form-hint">JavaScript is required: secrets are encrypted in your browser before sending.</p></noscript>

    <script>
        document.getElementById('company').style.display = 'none';
    </script>

    <script>
    /*
     * Zero-knowledge creation: secrets are encrypted in this browser
     * with AES-256-GCM before anything leaves the page. The server only
     * ever receives ciphertext + IV. Encryption keys never leave
     * this browser -- they travel in link fragments (#...), which
     * browsers never send to the server, and they are never stored in
     * cookies, localStorage, or sessionStorage. Plaintext lives only
     * in this script's memory and is never submitted to PHP.
     */
    (function () {
        const form = document.getElementById('vault-form');
        const input = document.getElementById('secret-input');
        const btn = document.getElementById('submit-btn');
        const genBtn = document.getElementById('generate-btn');
        const backBtn = document.getElementById('gen-back');
        const createBlock = document.getElementById('create-block');
        const resultBox = document.getElementById('generated-result');
        const genPassEl = document.getElementById('gen-password');
        const genLinkEl = document.getElementById('gen-link');
        const genDoneEl = document.getElementById('gen-done');

        const REVEAL_BASE = {$jsRevealBase};

        /* Unambiguous alphabet: no 0/O, 1/l/I. */
        const UPPER = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
        const LOWER = 'abcdefghijkmnopqrstuvwxyz';
        const DIGITS = '23456789';
        const SYMBOLS = '!@#$%^&*-_=+?';
        const ALL = UPPER + LOWER + DIGITS + SYMBOLS;

        function cryptoOk() {
            return !!(window.crypto && window.crypto.subtle && window.crypto.getRandomValues);
        }

        function b64urlEncode(buf) {
            const bytes = new Uint8Array(buf);
            let bin = '';
            for (let i = 0; i < bytes.length; i++) {
                bin += String.fromCharCode(bytes[i]);
            }
            return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        }

        function showError(msg) {
            let box = document.getElementById('client-error');
            if (!box) {
                box = document.createElement('div');
                box.id = 'client-error';
                box.className = 'error';
                form.parentNode.insertBefore(box, form);
            }
            box.textContent = msg;
            btn.disabled = false;
            btn.textContent = 'Add To Vault';
            genBtn.disabled = false;
            genBtn.textContent = 'Auto-Generate Password + Link';
        }

        function clearError() {
            const box = document.getElementById('client-error');
            if (box) {
                box.remove();
            }
        }

        /* Unbiased random index in [0, n) via rejection sampling. */
        function randIndex(n) {
            const limit = 256 - (256 % n);
            const buf = new Uint8Array(1);
            while (true) {
                window.crypto.getRandomValues(buf);
                if (buf[0] < limit) {
                    return buf[0] % n;
                }
            }
        }

        function generatePassword() {
            const chars = [
                UPPER[randIndex(UPPER.length)],
                LOWER[randIndex(LOWER.length)],
                DIGITS[randIndex(DIGITS.length)],
                SYMBOLS[randIndex(SYMBOLS.length)]
            ];
            for (let i = 4; i < 32; i++) {
                chars.push(ALL[randIndex(ALL.length)]);
            }
            for (let i = chars.length - 1; i > 0; i--) {
                const j = randIndex(i + 1);
                const t = chars[i];
                chars[i] = chars[j];
                chars[j] = t;
            }
            return chars.join('');
        }

        /*
         * Encrypt + store. Resolves {key, frag}; rejects with a reason.
         * Sends ciphertext + IV only -- never plaintext, never the key.
         */
        async function storeEncrypted(plainBytes) {
            const key = await window.crypto.subtle.generateKey(
                { name: 'AES-GCM', length: 256 },
                true,
                ['encrypt']
            );
            const iv = window.crypto.getRandomValues(new Uint8Array(12));
            const ct = await window.crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: iv },
                key,
                plainBytes
            );
            const rawKey = await window.crypto.subtle.exportKey('raw', key);

            const body = new URLSearchParams();
            body.set('enc', b64urlEncode(ct));
            body.set('iv', b64urlEncode(iv.buffer));

            const res = await fetch('pwcreate.php?action=store', {
                method: 'POST',
                headers: { 'Accept': 'application/json' },
                body: body
            });
            const data = await res.json().catch(function () { return null; });

            if (!res.ok || !data || data.ok !== true || typeof data.key !== 'string') {
                throw new Error((data && data.error) ? data.error : ('http-' + res.status));
            }

            return { key: data.key, frag: b64urlEncode(rawKey) };
        }

        /* Manual flow: encrypt the textarea, then show the link page. */
        form.addEventListener('submit', async function (ev) {
            ev.preventDefault();
            clearError();

            if (!cryptoOk()) {
                showError('Web Crypto is unavailable in this browser, so the secret cannot be encrypted. Nothing was sent.');
                return;
            }

            const plainBytes = new TextEncoder().encode(input.value);
            if (plainBytes.length === 0 || plainBytes.length > 4000) {
                showError('Secret must be 1 to 4000 bytes.');
                return;
            }

            btn.disabled = true;
            btn.textContent = 'Encrypting…';

            try {
                const stored = await storeEncrypted(plainBytes);
                /* Key travels in the fragment: never sent to the server. */
                window.location.href = 'pwcreate.php?created=' + encodeURIComponent(stored.key) + '#' + stored.frag;
            } catch (err) {
                showError('Could not store the secret (' + err.message + '). Nothing was stored in plaintext.');
            }
        });

        function flashGen(message) {
            genDoneEl.textContent = message;
            setTimeout(function () {
                genDoneEl.textContent = '';
            }, 3000);
        }

        async function copyText(text, okMessage) {
            try {
                await navigator.clipboard.writeText(text);
            } catch (err) {
                const ta = document.createElement('textarea');
                ta.value = text;
                document.body.appendChild(ta);
                ta.select();
                document.execCommand('copy');
                ta.remove();
            }
            flashGen(okMessage);
        }

        let generatedPassword = '';
        let generatedLink = '';

        document.getElementById('copy-password').addEventListener('click', function () {
            copyText(generatedPassword, 'Password copied to clipboard');
        });

        document.getElementById('copy-link').addEventListener('click', function () {
            copyText(generatedLink, 'Link copied to clipboard');
        });

        /* < Back: clear the generated output and restore the form. */
        backBtn.addEventListener('click', function () {
            generatedPassword = '';
            generatedLink = '';
            genPassEl.textContent = '';
            genLinkEl.textContent = '';
            genDoneEl.textContent = '';
            clearError();
            resultBox.style.display = 'none';
            backBtn.style.display = 'none';
            createBlock.style.display = 'block';
            genBtn.disabled = false;
            genBtn.textContent = 'Auto-Generate Password + Link';
            createBlock.scrollIntoView({ behavior: 'smooth', block: 'start' });
        });

        /*
         * Generator flow: the password lives in memory only, is
         * encrypted like any secret, and then takes over the card --
         * the form hides, the password + link show with copy buttons,
         * and < Back restores the form.
         */
        genBtn.addEventListener('click', async function () {
            clearError();

            if (!cryptoOk()) {
                showError('Web Crypto is unavailable in this browser, so no password can be generated. Nothing was sent.');
                return;
            }

            genBtn.disabled = true;
            genBtn.textContent = 'Generating…';
            resultBox.style.display = 'none';
            backBtn.style.display = 'none';

            let password;
            try {
                password = generatePassword();
            } catch (err) {
                showError('Password generation failed. Nothing was sent.');
                return;
            }

            genBtn.textContent = 'Encrypting…';
            let stored;
            try {
                stored = await storeEncrypted(new TextEncoder().encode(password));
            } catch (err) {
                showError('Could not store the generated password (' + err.message + '). Nothing was stored in plaintext.');
                return;
            }

            /*
             * Consume the one-time link marker (the inline panel shows
             * the link itself, so the ?created= page is never visited).
             * Failure here is harmless: the marker is inert.
             */
            try {
                await fetch('pwcreate.php?created=' + encodeURIComponent(stored.key));
            } catch (err) { /* inert marker on failure */ }

            generatedPassword = password;
            generatedLink = REVEAL_BASE + stored.key + '#' + stored.frag;
            genPassEl.textContent = generatedPassword;
            genLinkEl.textContent = generatedLink;
            createBlock.style.display = 'none';
            resultBox.style.display = 'block';
            backBtn.style.display = 'block';
            genBtn.disabled = false;
            genBtn.textContent = 'Auto-Generate Password + Link';

            try {
                await navigator.clipboard.writeText(generatedLink);
                flashGen('Link copied to your clipboard automatically');
            } catch (err) {
                flashGen('Use the Copy buttons to copy the password and link');
            }

            resultBox.scrollIntoView({ behavior: 'smooth', block: 'start' });
        });
    })();
    </script>

    <p class="form-hint">
        Your secret is encrypted in this browser before sending; the server
        never sees it in readable form. Every visit starts a fresh entry.
        Values are stored until their one-time link is revealed, then
        permanently deleted. Unrevealed links expire automatically after
        10 days. Maximum secret size is 4,000 characters.
    </p>

    <p class="security-info">
        <span class="info-tip" tabindex="0" aria-label="About this vault's security" data-tip="Secrets are encrypted in your browser with AES-256-GCM before sending, so the server never sees them. Pages are never cached, visitors pass a JavaScript browser check, and bots are blocked by anti-spam controls.">i</span> Security Info
    </p>
</div>

</body>
</html>
HTML;
}


function renderCreated(string $key): never
{
    $link = baseUrl() . '/pw1time.php?key=' . $key;

    $displayKey = htmlspecialchars($link, ENT_QUOTES, 'UTF-8');

    $jsLink = json_encode(
        $link,
        JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT
    );

    echo <<<HTML
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Vault Link Created</title>

<style>
@view-transition {
    navigation: auto;
}

html {
    background: #080b10;
}

* { box-sizing: border-box; }

body {
    margin: 0;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background:
        radial-gradient(circle at 50% 40%, #10282a 0, #080b10 48%);
    color: #fff;
    font-family: system-ui, -apple-system, sans-serif;
}

.modal {
    position: relative;
    width: min(620px, calc(100% - 40px));
    padding: 42px;
    background: rgba(14,20,27,.97);
    border: 1px solid #26333b;
    border-radius: 18px;
    box-shadow:
        0 25px 80px rgba(0,0,0,.55),
        0 0 70px rgba(44,255,198,.06);
    overflow: hidden;
    animation: modalIn .45s ease-out;
}

@keyframes modalIn {
    from { opacity: 0; transform: translateY(10px) scale(.98); }
    to   { opacity: 1; transform: translateY(0) scale(1); }
}

.header {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 24px;
}

.status-dot {
    width: 9px;
    height: 9px;
    background: #2cffc6;
    border-radius: 50%;
    box-shadow: 0 0 12px #2cffc6;
}

.status {
    color: #2cffc6;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 12px;
    letter-spacing: 1.5px;
}

h2 {
    margin: 0 0 8px;
    font-size: 25px;
}

.subtitle {
    margin: 0 0 25px;
    color: #8995a5;
    font-size: 14px;
}

.link-box {
    min-height: 58px;
    display: flex;
    align-items: center;
    padding: 14px 16px;
    background: #090d12;
    border: 1px solid #26343b;
    border-radius: 10px;
    overflow: hidden;
}

.link {
    width: 100%;
    color: #2cffc6;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 13px;
    line-height: 1.5;
    white-space: pre-wrap;
    word-break: break-all;
    text-shadow: 0 0 12px rgba(44,255,198,.25);
}

.copy {
    flex-shrink: 0;
    display: inline-flex;
    align-items: center;
    gap: 7px;
    padding: 9px 12px;
    border: 1px solid #2cffc6;
    border-radius: 7px;
    background: transparent;
    color: #2cffc6;
    font-weight: 600;
    font-size: 13px;
    cursor: pointer;
    transition: background .15s, color .15s;
}

.copy:hover {
    background: #2cffc6;
    color: #07110e;
}

.copy-row {
    margin-top: 16px;
    display: flex;
    justify-content: center;
}

.notice {
    margin-top: 20px;
    color: #778391;
    font-size: 13px;
    line-height: 1.5;
    text-align: center;
}

.expiry {
    margin: 6px 0 0;
    color: #56616f;
    font-size: 11px;
    line-height: 1.5;
    text-align: center;
}

.done {
    margin: 18px 0 0;
    color: #2cffc6;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 12px;
    letter-spacing: 1px;
    text-align: center;
}
</style>
</head>

<body>

<div class="modal">
<center><img src="logo-extra.png" height="50" style="max-width:225px;display:block;border:none;margin:0 auto 24px;filter:drop-shadow(1px 0 0 gray) drop-shadow(-1px 0 0 gray) drop-shadow(0 1px 0 gray) drop-shadow(0 -1px 0 gray);" alt="Watchdog Studio"></center><br>

    <div class="header">
        <div class="status-dot"></div>
        <div class="status" id="status">STORED</div>
    </div>

    <h2>Vault Link Created - Valid for 10 Days</h2>

    <p class="subtitle">
        One-time secure share
    </p>

    <div class="link-box">
        <div class="link" id="link">{$displayKey}</div>
    </div>

    <div class="copy-row">
        <button class="copy" id="copy" type="button" title="Copy link">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none"
                 stroke="currentColor" stroke-width="2"
                 stroke-linecap="round" stroke-linejoin="round"
                 style="display:block;">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
            </svg>
            Copy
        </button>
    </div>

    <p class="notice" id="notice">
        Copy and send or save, you will only see this link once now.
    </p>

    <p class="expiry">
        Unrevealed links expire automatically after 10 days.
    </p>

    <div class="done" id="done"></div>

</div>

<script>

const linkEl = document.getElementById('link');
const copyBtn = document.getElementById('copy');
const doneEl = document.getElementById('done');
const noticeEl = document.getElementById('notice');

const linkText = {$jsLink};

/*
 * The decryption key arrives in the URL fragment (#...), which the
 * browser never sends to the server -- PHP rendered the link above
 * without it. Complete the shareable link here, in this browser only.
 */
let fullLink = linkText;
const frag = window.location.hash ? window.location.hash.slice(1) : '';
if (/^[A-Za-z0-9\-_]{43}$/.test(frag)) {
    fullLink = linkText + '#' + frag;
    linkEl.textContent = fullLink;
} else {
    linkEl.textContent = 'Missing decryption key: this page was opened without the link fragment, so the complete link cannot be shown. Create the secret again.';
    noticeEl.textContent = 'No link was stored or copied. Go back and create the secret again to get a complete link.';
    copyBtn.style.display = 'none';
}

const btnMarkup = {
    copy: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" ' +
        'stroke="currentColor" stroke-width="2" stroke-linecap="round" ' +
        'stroke-linejoin="round" style="display:block;margin:0 auto;">' +
        '<rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>' +
        '<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>' +
        '</svg> Copy',
    copied: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" ' +
        'stroke="currentColor" stroke-width="2" stroke-linecap="round" ' +
        'stroke-linejoin="round" style="display:block;margin:0 auto;">' +
        '<polyline points="20 6 9 17 4 12"></polyline></svg>' +
        ' Copied'
};

function flashCopied(message) {
    copyBtn.innerHTML = btnMarkup.copied;
    doneEl.textContent = message;
    setTimeout(function () {
        copyBtn.innerHTML = btnMarkup.copy;
        doneEl.textContent = '';
    }, 3000);
}

async function copyLink() {
    try {
        await navigator.clipboard.writeText(fullLink);
    } catch (err) {
        const ta = document.createElement('textarea');
        ta.value = fullLink;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        ta.remove();
    }
    flashCopied('Copied to clipboard');
}

copyBtn.addEventListener('click', copyLink);

/*
 * Auto-copy once the page has rendered. If the browser blocks
 * clipboard access without a user gesture, the button remains
 * available to copy manually.
 */
copyLink().then(function () {
    doneEl.textContent = 'Link copied to your clipboard automatically';
    setTimeout(function () {
        copyBtn.innerHTML = btnMarkup.copy;
        if (doneEl.textContent === 'Link copied to your clipboard automatically') {
            doneEl.textContent = '';
        }
    }, 3000);
}).catch(function () {
    doneEl.textContent = 'Copy not available automatically — use the Copy button';
    setTimeout(function () {
        doneEl.textContent = '';
    }, 3000);
});

</script>

</body>
</html>
HTML;

    exit;
}