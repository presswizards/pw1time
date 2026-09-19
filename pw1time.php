<?php

declare(strict_types=1);

/*
 * Never let the browser cache any of these pages. In particular,
 * no-store excludes the reveal page from the back/forward bfcache,
 * so Back/Forward cannot resurface a once-revealed secret.
 */
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');

$jsonFile = dirname(__DIR__) . '/pw1time.json';
$revealDir = dirname(__DIR__) . '/.revealed';
$key = $_GET['key'] ?? '';
$revealed = ($_GET['revealed'] ?? '') === '1';

const ENTRY_TTL = 10 * 86400;

if (!preg_match('/^[a-f0-9]{32,128}$/i', $key)) {
    invalid();
}

/*
 * GET with revealed=1: the secret was consumed by a POST that redirected
 * here (PRG, legacy flow). The value is stashed on disk so the redirect
 * target can display it without re-submitting anything; it's deleted
 * after display, so a reload shows invalid instead of a resubmit
 * dialog. Encrypted records no longer use this path (they are
 * fetched, decrypted, and consumed inline on the confirm page);
 * the ENC1: branch below only serves stashes predating that change.
 */
if ($revealed) {
    $stash = $revealDir . '/' . $key;

    if (!is_file($stash)) {
        invalid();
    }

    $value = @file_get_contents($stash);
    @unlink($stash);

    if ($value === false) {
        invalid();
    }

    /*
     * Backward compatibility: an encrypted stash is tagged ENC1: and
     * carries a JSON envelope {enc, iv} for browser-side decryption;
     * anything else is a legacy plaintext record shown with the
     * original behavior. The tag removes any ambiguity with a legacy
     * secret that merely happens to look like JSON.
     */
    if (str_starts_with($value, 'ENC1:')) {
        $envelope = json_decode(substr($value, 5), true);
        if (is_array($envelope) && isset($envelope['enc'], $envelope['iv'])
            && is_string($envelope['enc']) && is_string($envelope['iv'])) {
            showCipher($envelope['enc'], $envelope['iv']);
        }
        invalid();
    }

    showValue($value);
}

/*
 * GET with action=fetch: return the ciphertext envelope for an
 * encrypted record WITHOUT consuming it. Read-only by design: the
 * file is never written here, so scanners, retries, and missing or
 * wrong keys can never burn the secret. Legacy records are refused
 * (they keep the normal reveal flow); only {enc, iv} ever leaves.
 */
if (($_GET['action'] ?? '') === 'fetch' && $_SERVER['REQUEST_METHOD'] === 'GET') {
    header('Content-Type: application/json');
    $data = loadJson($jsonFile);

    if (!array_key_exists($key, $data)) {
        http_response_code(404);
        echo json_encode(['ok' => false, 'error' => 'not-found']);
        exit;
    }

    $entry = $data[$key];
    if (isEntryExpired($entry, time())) {
        http_response_code(404);
        echo json_encode(['ok' => false, 'error' => 'not-found']);
        exit;
    }

    $cipher = entryCipher($entry);
    if ($cipher === null) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => 'legacy-record']);
        exit;
    }

    echo json_encode(['ok' => true, 'enc' => $cipher['enc'], 'iv' => $cipher['iv']]);
    exit;
}

/*
 * POST with action=consume: atomically delete an encrypted record
 * AFTER the browser has decrypted it locally. Only the key ID is
 * needed -- and only ever returned -- so this endpoint can neither
 * expose plaintext nor ciphertext. Legacy records are refused
 * outright (never deleted here); they keep the normal reveal flow.
 */
if (($_GET['action'] ?? '') === 'consume' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');

    $fp = @fopen($jsonFile, 'c+');
    if (!$fp || !flock($fp, LOCK_EX)) {
        if ($fp) {
            fclose($fp);
        }
        http_response_code(503);
        echo json_encode(['ok' => false, 'error' => 'vault-busy']);
        exit;
    }

    rewind($fp);
    $data = json_decode(stream_get_contents($fp) ?: '{}', true);
    if (!is_array($data)) {
        $data = [];
    }

    $now = time();
    foreach ($data as $existingKey => $existingEntry) {
        if (isEntryExpired($existingEntry, $now)) {
            unset($data[$existingKey]);
        }
    }

    if (!array_key_exists($key, $data)) {
        flock($fp, LOCK_UN);
        fclose($fp);
        http_response_code(404);
        echo json_encode(['ok' => false, 'error' => 'not-found']);
        exit;
    }

    if (entryCipher($data[$key]) === null) {
        flock($fp, LOCK_UN);
        fclose($fp);
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => 'legacy-record']);
        exit;
    }

    unset($data[$key]);

    $newJson = encodeVault($data);
    if ($newJson === '') {
        flock($fp, LOCK_UN);
        fclose($fp);
        http_response_code(500);
        echo json_encode(['ok' => false, 'error' => 'write-failed']);
        exit;
    }

    rewind($fp);
    ftruncate($fp, 0);
    $writeOk = fwrite($fp, $newJson . PHP_EOL) !== false;
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);

    if (!$writeOk) {
        http_response_code(500);
        echo json_encode(['ok' => false, 'error' => 'write-failed']);
        exit;
    }

    echo json_encode(['ok' => true]);
    exit;
}

/*
 * GET: Verify key exists, but do not consume it.
 * This prevents email scanners from burning the link.
 * Expired entries are purged and treated as invalid.
 */
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    $data = loadJson($jsonFile);
    $data = pruneExpired($jsonFile, $data);

    if (!array_key_exists($key, $data)) {
        invalid();
    }

    showConfirmation($key, entryCipher($data[$key]) !== null);
}

/*
 * POST (no action): legacy reveal path -- lock JSON, retrieve value,
 * remove only this key, write the remaining data back, stash the
 * value, and redirect so reloading the revealed page never
 * re-submits the POST. Encrypted records are refused above: they
 * are deleted only via the explicit consume endpoint, after the
 * browser decrypts them locally.
 */
$fp = @fopen($jsonFile, 'c+');

if (!$fp || !flock($fp, LOCK_EX)) {
    if ($fp) {
        fclose($fp);
    }
    invalid();
}

rewind($fp);
$contents = stream_get_contents($fp);
$data = json_decode($contents ?: '{}', true);

if (!is_array($data)) {
    flock($fp, LOCK_UN);
    fclose($fp);
    invalid();
}

/*
 * Purge entries older than 10 days while the file is locked,
 * so expired secrets can't be revealed later.
 */
$now = time();
foreach ($data as $existingKey => $existingEntry) {
    if (isEntryExpired($existingEntry, $now)) {
        unset($data[$existingKey]);
    }
}

if (!array_key_exists($key, $data)) {
    flock($fp, LOCK_UN);
    fclose($fp);
    invalid();
}

/*
 * Encrypted records must never be consumed here. They are fetched
 * read-only, decrypted in the browser, and deleted only via the
 * explicit consume endpoint -- so a missing/wrong key or a
 * non-JS POST can never burn the secret. Legacy records continue
 * through the stash + redirect flow below, unchanged.
 */
if (entryCipher($data[$key]) !== null) {
    flock($fp, LOCK_UN);
    fclose($fp);
    if (($_GET['action'] ?? '') === 'reveal') {
        header('Content-Type: application/json');
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => 'encrypted-requires-decrypt-flow']);
        exit;
    }
    http_response_code(400);
    echo '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
        . '<meta name="viewport" content="width=device-width, initial-scale=1">'
        . '<title>JavaScript required</title></head>'
        . '<body style="background:#0b0f14;color:#e8edf2;font-family:system-ui,sans-serif;'
        . 'display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0">'
        . '<div style="text-align:center;max-width:26rem;padding:2rem">'
        . '<h1>JavaScript required</h1>'
        . '<p>This secret is end-to-end encrypted and must be decrypted in your browser before it can be revealed. Nothing was deleted.</p>'
        . '</div></body></html>';
    exit;
}

$entry = $data[$key];

/* Legacy plaintext only (encrypted records exit above): stash the
 * value for the redirect target, unchanged behavior. */
$stashPayload = entryValue($entry);
unset($data[$key]);

$newJson = encodeVault($data);

if ($newJson === '') {
    flock($fp, LOCK_UN);
    fclose($fp);
    invalid();
}

rewind($fp);
ftruncate($fp, 0);

if (fwrite($fp, $newJson . PHP_EOL) === false) {
    flock($fp, LOCK_UN);
    fclose($fp);
    invalid();
}

fflush($fp);
flock($fp, LOCK_UN);
fclose($fp);

/*
 * Stash the value for the redirect target. If the stash can't be
 * written we still lost the JSON entry, so write it first (create
 * mode under lock) and abort if it fails.
 */
if (!is_dir($revealDir)) {
    @mkdir($revealDir, 0700, true);
}

$sfp = @fopen($revealDir . '/' . $key, 'x');

if (!$sfp) {
    invalid();
}

if (flock($sfp, LOCK_EX) && fwrite($sfp, $stashPayload) !== false) {
    fflush($sfp);
    flock($sfp, LOCK_UN);
}
fclose($sfp);

/*
 * Browser fetch flow (used to preserve the URL-fragment decryption
 * key across the redirect): answer JSON so the browser can navigate
 * itself and re-attach the fragment. Plain form posts keep the 303.
 */
if (($_GET['action'] ?? '') === 'reveal') {
    header('Content-Type: application/json');
    echo json_encode(['ok' => true, 'goto' => '/pw1time.php?key=' . $key . '&revealed=1']);
    exit;
}

header(
    'Location: /pw1time.php?key=' . urlencode($key) . '&revealed=1',
    true,
    303
);
exit;


/* ----------------------------------------------------------
 * Functions
 * ---------------------------------------------------------- */

function encodeVault(array $data): string
{
    $json = json_encode(
        $data === [] ? (object) [] : $data,
        JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
    );

    return $json === false ? '' : $json;
}

function loadJson(string $file): array
{
    if (!is_file($file) || !is_readable($file)) {
        return [];
    }

    $contents = @file_get_contents($file);

    if ($contents === false) {
        return [];
    }

    $data = json_decode($contents, true);

    return is_array($data) ? $data : [];
}


/*
 * True when an entry has aged out of the 10-day window.
 * Entries may be either {"value":...,"ts":...} or a legacy
 * plain string (backfilled before timestamps); legacy entries
 * are never treated as expired.
 */
function isEntryExpired(mixed $entry, int $now): bool
{
    if (!is_array($entry) || !isset($entry['ts']) || !is_int($entry['ts'])) {
        return false;
    }

    return ($now - $entry['ts']) > ENTRY_TTL;
}


/*
 * Extract the secret text from an entry, tolerating the legacy
 * string form used before timestamps were introduced.
 */
function entryValue(mixed $entry): string
{
    if (is_array($entry) && isset($entry['value']) && is_string($entry['value'])) {
        return $entry['value'];
    }

    return is_string($entry) ? $entry : '';
}


/*
 * Extract ciphertext + IV from a zero-knowledge entry, or null for
 * legacy plaintext entries. Detection is structural (array keys),
 * so existing records are never reinterpreted or migrated.
 */
function entryCipher(mixed $entry): ?array
{
    if (is_array($entry) && isset($entry['enc'], $entry['iv'])
        && is_string($entry['enc']) && is_string($entry['iv'])) {
        return ['enc' => $entry['enc'], 'iv' => $entry['iv']];
    }

    return null;
}


/*
 * Prune expired entries from a loaded dataset and persist the
 * result if anything was removed.
 */
function pruneExpired(string $file, array $data): array
{
    $now = time();

    $changed = false;
    foreach ($data as $existingKey => $existingEntry) {
        if (isEntryExpired($existingEntry, $now)) {
            unset($data[$existingKey]);
            $changed = true;
        }
    }

    if (!$changed) {
        return $data;
    }

    $fp = @fopen($file, 'c+');

    if (!$fp || !flock($fp, LOCK_EX)) {
        if ($fp) {
            fclose($fp);
        }
        return $data;
    }

    $newJson = encodeVault($data);

    if ($newJson !== '') {
        rewind($fp);
        ftruncate($fp, 0);
        fwrite($fp, $newJson . PHP_EOL);
    }

    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);

    return $data;
}


function invalid(): never
{
    http_response_code(404);

    echo <<<'HTML'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Invalid URL</title>

<style>
@view-transition {
    navigation: auto;
}

html {
    background: #080b10;
}

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: #080b10;
    color: #fff;
    font-family: system-ui, -apple-system, sans-serif;
}

.card {
    width: min(440px, calc(100% - 40px));
    padding: 38px;
    text-align: center;
    background: #10151d;
    border: 1px solid #252d38;
    border-radius: 16px;
}

h2 {
    margin-top: 0;
}

p {
    color: #8d98a8;
}
</style>
</head>

<body>
<div class="card">
<center><img src="logo-extra.png" height="50" style="max-width:225px;display:block;border:none;margin:0 auto 24px;filter:drop-shadow(1px 0 0 gray) drop-shadow(-1px 0 0 gray) drop-shadow(0 1px 0 gray) drop-shadow(0 -1px 0 gray);" alt="Watchdog Studio"></center><br>

    <h2>Invalid URL</h2>
    <p>This link is invalid, expired, or has already been used.</p>
</div>
</body>
</html>
HTML;

    exit;
}


function showConfirmation(string $key, bool $isEncrypted): never
{
    $key = htmlspecialchars($key, ENT_QUOTES, 'UTF-8');

    $keyWarning = '';
    if ($isEncrypted) {
        $keyWarning = <<<HTML
    <p class="key-warning" id="key-warning" style="display:none">
        This link is missing its decryption key (the part after #).
        Ask the sender for the complete link. Nothing will be deleted
        until the secret is successfully decrypted in your browser.
    </p>
HTML;
    }

    $jsIsEncrypted = $isEncrypted ? 'true' : 'false';
    echo <<<HTML
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Secure Information</title>

<style>
@view-transition {
    navigation: auto;
}

html {
    background: #080b10;
}

* {
    box-sizing: border-box;
}

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

.icon {
    width: 60px;
    height: 60px;
    margin: 0 auto 22px;
    display: flex;
    align-items: center;
    justify-content: center;
    border-radius: 50%;
    border: 1px solid #2cffc6;
    color: #2cffc6;
    font-size: 27px;
    box-shadow: 0 0 25px rgba(44,255,198,.12);
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

.subtitle {
    margin: 0 0 25px;
    color: #8995a5;
    font-size: 14px;
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

button {
    width: 100%;
    padding: 14px 24px;
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

button:disabled {
    opacity: .55;
    cursor: wait;
}

.error {
    margin: 20px 0 0;
    padding: 10px 12px;
    text-align: center;
    border: 1px solid #8c4a3f;
    border-radius: 8px;
    background: rgba(140,74,63,.12);
    color: #ffb4a8;
    font-size: 13px;
    line-height: 1.5;
}

.key-warning {
    margin: 0 0 20px;
    padding: 10px 12px;
    text-align: center;
    border: 1px solid #8c6a3f;
    border-radius: 8px;
    background: rgba(140,106,63,.12);
    color: #ffd9a8;
    font-size: 13px;
    line-height: 1.5;
}

.secret-box {
    position: relative;
    min-height: 80px;
    display: flex;
    align-items: center;
    padding: 18px;
    background: #090d12;
    border: 1px solid #26343b;
    border-radius: 10px;
    overflow: hidden;
    margin-top: 20px;
}

.secret {
    width: 100%;
    color: #2cffc6;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 15px;
    line-height: 1.6;
    white-space: pre-wrap;
    word-break: break-word;
    text-shadow: 0 0 12px rgba(44,255,198,.25);
}

.secret-error {
    color: #ffb4a8;
    text-shadow: none;
}

.scan {
    position: absolute;
    left: 0;
    right: 0;
    height: 2px;
    background: #2cffc6;
    box-shadow: 0 0 18px #2cffc6;
    animation: scan 1.25s ease-in-out forwards;
}

@keyframes scan {
    0% { top: 0; opacity: 0; }
    10% { opacity: 1; }
    90% { opacity: 1; }
    100% { top: 100%; opacity: 0; }
}

.progress {
    height: 2px;
    margin-top: 15px;
    background: #182027;
    overflow: hidden;
    border-radius: 2px;
}

.progress-bar {
    height: 100%;
    width: 0;
    background: #2cffc6;
    box-shadow: 0 0 10px rgba(44,255,198,.7);
    animation: progress 2s ease-out forwards;
}

@keyframes progress {
    to { width: 100%; }
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
    <div id="confirm-top">
    <div class="icon">⌁</div>

    <h2>Secure Information</h2>

    <p>
        This information can only be viewed once.
        Once revealed, it will be permanently deleted.
    </p>

    {$keyWarning}

    <div id="confirm-block">
    <form method="post" action="?key={$key}" id="reveal-form">
        <button type="submit" id="reveal-btn">Reveal Secure Information</button>
    </form>
    </div>
    </div>

    <div id="reveal-top" style="display:none">
    <div class="header">
        <div class="status-dot"></div>
        <div class="status" id="status">DECRYPTING</div>
    </div>

    <h2>Secure Information</h2>

    <p class="subtitle">
        One-time secure reveal
    </p>
    </div>

    <p class="error" id="reveal-error" style="display:none"></p>

    <div id="secret-block" style="display:none">
        <div class="secret-box">
            <div class="scan"></div>
            <div class="secret" id="secret"></div>
        </div>

        <div class="progress">
            <div class="progress-bar"></div>
        </div>

        <div class="copy-row">
            <button class="copy" id="copy" type="button" title="Copy" style="visibility:hidden">
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

        <p class="notice" id="secret-notice">
            This information has been permanently deleted
            from the server.
        </p>

        <div class="done" id="done"></div>
    </div>
</div>

<script>
/*
 * The decryption key lives in the URL fragment (#...), which the
 * browser never sends to the server. Capture it immediately, then
 * strip it from the visible URL. The key is kept only in this
 * variable: never sent, never stored.
 *
 * Encrypted records: fetch the ciphertext (read-only, never
 * consumed), decrypt locally, POST the consume request, and display
 * the plaintext only after the server confirms {ok:true}. A
 * missing/wrong key, failed authentication, or failed consume
 * consumes and reveals nothing -- the record stays intact for
 * another attempt.
 * Legacy records: classic reveal POST, unchanged.
 */
(function () {
    const IS_ENCRYPTED = {$jsIsEncrypted};

    const frag = window.location.hash ? window.location.hash.slice(1) : '';
    try {
        history.replaceState(null, '', location.pathname + location.search);
    } catch (err) { /* cosmetic only */ }

    const form = document.getElementById('reveal-form');
    const btn = document.getElementById('reveal-btn');
    const errBox = document.getElementById('reveal-error');
    const keyWarning = document.getElementById('key-warning');

    if (IS_ENCRYPTED && keyWarning && !/^[A-Za-z0-9\-_]{43}$/.test(frag)) {
        keyWarning.style.display = 'block';
    }

    function fail(msg, enableBtn) {
        errBox.textContent = msg;
        errBox.style.display = 'block';
        if (enableBtn !== false) {
            btn.disabled = false;
        }
    }

    /* ---- shared reveal-animation + copy widgets ---- */

    const display = document.getElementById('secret');
    const copyBtn = document.getElementById('copy');
    const doneEl = document.getElementById('done');
    const statusEl = document.getElementById('status');

    const chars =
        'ABCDEFGHIJKLMNOPQRSTUVWXYZ' +
        'abcdefghijklmnopqrstuvwxyz' +
        '0123456789!@#$%^&*';

    const duration = 2000;
    let secret = '';
    let start = 0;

    function randomChar() {
        return chars[Math.floor(Math.random() * chars.length)];
    }

    function animate(now) {
        const progress = Math.min((now - start) / duration, 1);
        const resolved = Math.floor(secret.length * progress);
        let output = '';
        for (let i = 0; i < secret.length; i++) {
            if (secret[i] === '\\n') {
                output += '\\n';
            } else if (i < resolved) {
                output += secret[i];
            } else {
                output += randomChar();
            }
        }
        display.textContent = output;
        if (progress < 1) {
            requestAnimationFrame(animate);
        } else {
            display.textContent = secret;
            statusEl.textContent = 'DECRYPTED • DESTROYED';
            copyBtn.style.visibility = 'visible';
        }
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

    copyBtn.addEventListener('click', function () {
        try {
            navigator.clipboard.writeText(secret);
        } catch (err) {
            const ta = document.createElement('textarea');
            ta.value = secret;
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            ta.remove();
        }
        flashCopied('Copied to clipboard');
    });

    function showSecret(plaintext) {
        secret = plaintext;
        document.getElementById('confirm-top').style.display = 'none';
        document.getElementById('reveal-top').style.display = 'block';
        errBox.style.display = 'none';
        document.getElementById('secret-block').style.display = 'block';
        statusEl.textContent = 'DECRYPTING';
        start = performance.now();
        requestAnimationFrame(animate);
    }

    function b64urlDecode(s) {
        const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
        const bin = atob(b64);
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) {
            bytes[i] = bin.charCodeAt(i);
        }
        return bytes.buffer;
    }

    async function postConsume() {
        const res = await fetch('?key={$key}&action=consume', {
            method: 'POST',
            headers: { 'Accept': 'application/json' }
        });
        const data = await res.json().catch(function () { return null; });
        if (!res.ok || !data || data.ok !== true) {
            throw new Error((data && data.error) ? data.error : ('http-' + res.status));
        }
    }

    /* ---- legacy path: classic reveal POST, unchanged ---- */

    async function revealLegacy(ev) {
        ev.preventDefault();
        errBox.style.display = 'none';
        btn.disabled = true;

        try {
            const res = await fetch('?key={$key}&action=reveal', {
                method: 'POST',
                headers: { 'Accept': 'application/json' }
            });
            const data = await res.json().catch(function () { return null; });

            if (!res.ok || !data || data.ok !== true || typeof data.goto !== 'string') {
                throw new Error((data && data.error) ? data.error : ('http-' + res.status));
            }

            window.location.href = data.goto + (frag ? '#' + frag : '');
        } catch (err) {
            fail('Reveal failed (' + err.message + '). You can try again unless the link now reports invalid, which means it was already consumed.');
        }
    }

    /* ---- encrypted path: fetch, decrypt, then consume ---- */

    async function revealEncrypted(ev) {
        ev.preventDefault();
        errBox.style.display = 'none';
        btn.disabled = true;

        if (!window.crypto || !window.crypto.subtle) {
            fail('Web Crypto is unavailable in this browser, so this secret cannot be decrypted. Nothing was deleted.');
            return;
        }

        if (!/^[A-Za-z0-9\-_]{43}$/.test(frag)) {
            fail('This link is missing its decryption key (the part after #). Nothing was deleted. Ask the sender for the complete link.');
            return;
        }

        btn.textContent = 'Fetching…';
        let envelope;
        try {
            const res = await fetch('?key={$key}&action=fetch', {
                headers: { 'Accept': 'application/json' }
            });
            envelope = await res.json().catch(function () { return null; });
            if (!res.ok || !envelope || envelope.ok !== true
                || typeof envelope.enc !== 'string' || typeof envelope.iv !== 'string') {
                throw new Error((envelope && envelope.error) ? envelope.error : ('http-' + res.status));
            }
        } catch (err) {
            fail('Could not retrieve the secret (' + err.message + '). Nothing was deleted; you can try again.');
            btn.textContent = 'Reveal Secure Information';
            return;
        }

        btn.textContent = 'Decrypting…';
        let plaintext;
        try {
            const key = await window.crypto.subtle.importKey(
                'raw',
                b64urlDecode(frag),
                { name: 'AES-GCM' },
                false,
                ['decrypt']
            );
            const plain = await window.crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: new Uint8Array(b64urlDecode(envelope.iv)) },
                key,
                b64urlDecode(envelope.enc)
            );
            plaintext = new TextDecoder().decode(plain);
        } catch (err) {
            fail('Decryption failed: the link key does not match this secret, or the data is corrupt. Nothing was deleted -- ask the sender for the complete link.');
            btn.textContent = 'Reveal Secure Information';
            return;
        }

        /*
         * The plaintext stays in memory only. It is displayed only
         * after the server confirms deletion -- if consume fails,
         * the record is intact and nothing is revealed.
         */
        btn.textContent = 'Deleting…';
        try {
            await postConsume();
        } catch (err) {
            fail('Could not delete the secret on the server (' + err.message + '). Nothing was revealed and the record is intact -- you can try again. If the link now reports invalid, a previous attempt already deleted it without displaying.');
            btn.textContent = 'Reveal Secure Information';
            return;
        }

        showSecret(plaintext);
    }

    form.addEventListener('submit', IS_ENCRYPTED ? revealEncrypted : revealLegacy);
})();
</script>

</body>
</html>
HTML;

    exit;
}


function showValue(mixed $value): never
{
    if (!is_string($value)) {
        $value = json_encode(
            $value,
            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
        ) ?: '';
    }

    /*
     * JSON encoding lets us safely pass the secret to JavaScript.
     */
    $jsValue = json_encode(
        $value,
        JSON_HEX_TAG |
        JSON_HEX_AMP |
        JSON_HEX_APOS |
        JSON_HEX_QUOT
    );

    echo <<<HTML
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">

<title>Secure Information</title>

<style>

@view-transition {
    navigation: auto;
}

html {
    background: #080b10;
}

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;

    background:
        radial-gradient(circle at 50% 40%, #10282a 0, #080b10 48%);

    color: #fff;

    font-family:
        system-ui,
        -apple-system,
        sans-serif;
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
    from {
        opacity: 0;
        transform: translateY(10px) scale(.98);
    }

    to {
        opacity: 1;
        transform: translateY(0) scale(1);
    }
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

    box-shadow:
        0 0 12px #2cffc6;
}

.status {
    color: #2cffc6;

    font-family:
        ui-monospace,
        SFMono-Regular,
        Menlo,
        monospace;

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

.secret-box {
    position: relative;

    min-height: 100px;

    display: flex;
    align-items: center;

    padding: 22px;

    background: #090d12;

    border: 1px solid #26343b;

    border-radius: 10px;

    overflow: hidden;
}

.secret {
    width: 100%;

    color: #2cffc6;

    font-family:
        ui-monospace,
        SFMono-Regular,
        Menlo,
        Monaco,
        Consolas,
        monospace;

    font-size: 16px;

    line-height: 1.6;

    white-space: pre-wrap;
    word-break: break-word;

    text-shadow:
        0 0 12px rgba(44,255,198,.25);
}

/*
 * Scanner beam
 */
.scan {
    position: absolute;

    left: 0;
    right: 0;

    height: 2px;

    background: #2cffc6;

    box-shadow:
        0 0 18px #2cffc6;

    animation: scan 1.25s ease-in-out forwards;
}

@keyframes scan {

    0% {
        top: 0;
        opacity: 0;
    }

    10% {
        opacity: 1;
    }

    90% {
        opacity: 1;
    }

    100% {
        top: 100%;
        opacity: 0;
    }
}

.progress {
    height: 2px;

    margin-top: 15px;

    background: #182027;

    overflow: hidden;

    border-radius: 2px;
}

.progress-bar {
    height: 100%;

    width: 0;

    background: #2cffc6;

    box-shadow:
        0 0 10px rgba(44,255,198,.7);

    animation: progress 2s ease-out forwards;
}

@keyframes progress {
    to {
        width: 100%;
    }
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
        <div class="status" id="status">
            DECRYPTING
        </div>
    </div>

    <h2>Secure Information</h2>

    <p class="subtitle">
        One-time secure reveal
    </p>

    <div class="secret-box">

        <div class="scan"></div>

        <div
            class="secret"
            id="secret"
        ></div>

    </div>

    <div class="progress">
        <div class="progress-bar"></div>
    </div>

    <div class="copy-row">

        <button
            class="copy"
            id="copy"
            type="button"
            title="Copy"
            style="visibility:hidden"
        >
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

    <p class="notice">
        This information has been permanently deleted
        from the server.
    </p>

    <div class="done" id="done"></div>

</div>


<script>

const secret = {$jsValue};

const display =
    document.getElementById('secret');

const status =
    document.getElementById('status');

const copy =
    document.getElementById('copy');


const chars =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ' +
    'abcdefghijklmnopqrstuvwxyz' +
    '0123456789!@#$%^&*';


const duration = 2000;

const start = performance.now();


function randomChar() {

    return chars[
        Math.floor(
            Math.random() * chars.length
        )
    ];

}


function animate(now) {

    const elapsed =
        now - start;

    const progress =
        Math.min(
            elapsed / duration,
            1
        );

    /*
     * Characters resolve from
     * left to right.
     */
    const resolved =
        Math.floor(
            secret.length * progress
        );

    let output = '';

    for (
        let i = 0;
        i < secret.length;
        i++
    ) {

        if (secret[i] === '\\n') {

            output += '\\n';

        } else if (i < resolved) {

            output += secret[i];

        } else {

            output += randomChar();

        }

    }

    display.textContent = output;


    if (progress < 1) {

        requestAnimationFrame(
            animate
        );

    } else {

        display.textContent =
            secret;

        status.textContent =
            'DECRYPTED • DESTROYED';

        copy.style.visibility =
            'visible';

    }

}


requestAnimationFrame(
    animate
);


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

const done =
    document.getElementById('done');


function flashCopied(message) {
    copy.innerHTML = btnMarkup.copied;
    done.textContent = message;
    setTimeout(function () {
        copy.innerHTML = btnMarkup.copy;
        done.textContent = '';
    }, 3000);
}


copy.addEventListener(
    'click',
    () => {
        try {
            navigator.clipboard.writeText(secret);
        } catch (err) {
            const ta = document.createElement('textarea');
            ta.value = secret;
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            ta.remove();
        }
        flashCopied('Copied to clipboard');
    }
);

</script>

</body>
</html>
HTML;

    exit;
}


function showCipher(string $enc, string $iv): never
{
    /*
     * The page carries ciphertext + IV only. The AES key arrives in
     * the URL fragment, which the browser never sent to the server.
     * Decrypt locally, then run the same reveal animation on the
     * recovered plaintext. Failures show an error -- never plaintext,
     * never the ciphertext as if it were the secret.
     */
    $jsCipher = json_encode(
        ['enc' => $enc, 'iv' => $iv],
        JSON_HEX_TAG |
        JSON_HEX_AMP |
        JSON_HEX_APOS |
        JSON_HEX_QUOT
    );

    echo <<<HTML
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">

<title>Secure Information</title>

<style>

@view-transition {
    navigation: auto;
}

html {
    background: #080b10;
}

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;

    background:
        radial-gradient(circle at 50% 40%, #10282a 0, #080b10 48%);

    color: #fff;

    font-family:
        system-ui,
        -apple-system,
        sans-serif;
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
    from {
        opacity: 0;
        transform: translateY(10px) scale(.98);
    }

    to {
        opacity: 1;
        transform: translateY(0) scale(1);
    }
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

    box-shadow:
        0 0 12px #2cffc6;
}

.status {
    color: #2cffc6;

    font-family:
        ui-monospace,
        SFMono-Regular,
        Menlo,
        monospace;

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

.secret-box {
    position: relative;

    min-height: 100px;

    display: flex;
    align-items: center;

    padding: 22px;

    background: #090d12;

    border: 1px solid #26343b;

    border-radius: 10px;

    overflow: hidden;
}

.secret {
    width: 100%;

    color: #2cffc6;

    font-family:
        ui-monospace,
        SFMono-Regular,
        Menlo,
        Monaco,
        Consolas,
        monospace;

    font-size: 16px;

    line-height: 1.6;

    white-space: pre-wrap;
    word-break: break-word;

    text-shadow:
        0 0 12px rgba(44,255,198,.25);
}

.secret-error {
    color: #ffb4a8;
    text-shadow: none;
}

/*
 * Scanner beam
 */
.scan {
    position: absolute;

    left: 0;
    right: 0;

    height: 2px;

    background: #2cffc6;

    box-shadow:
        0 0 18px #2cffc6;

    animation: scan 1.25s ease-in-out forwards;
}

@keyframes scan {

    0% {
        top: 0;
        opacity: 0;
    }

    10% {
        opacity: 1;
    }

    90% {
        opacity: 1;
    }

    100% {
        top: 100%;
        opacity: 0;
    }
}

.progress {
    height: 2px;

    margin-top: 15px;

    background: #182027;

    overflow: hidden;

    border-radius: 2px;
}

.progress-bar {
    height: 100%;

    width: 0;

    background: #2cffc6;

    box-shadow:
        0 0 10px rgba(44,255,198,.7);

    animation: progress 2s ease-out forwards;
}

@keyframes progress {
    to {
        width: 100%;
    }
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
        <div class="status" id="status">
            DECRYPTING
        </div>
    </div>

    <h2>Secure Information</h2>

    <p class="subtitle">
        One-time secure reveal
    </p>

    <div class="secret-box">

        <div class="scan"></div>

        <div
            class="secret"
            id="secret"
        ></div>

    </div>

    <div class="progress">
        <div class="progress-bar"></div>
    </div>

    <div class="copy-row">

        <button
            class="copy"
            id="copy"
            type="button"
            title="Copy"
            style="visibility:hidden"
        >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none"
                 stroke="currentColor" stroke-width="2"
                 stroke-linecap="round" stroke-linejoin="round"
                 style="display:block;">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2-2v1"></path>
            </svg>
            Copy
        </button>

    </div>

    <p class="notice">
        This information has been permanently deleted
        from the server.
    </p>

    <div class="done" id="done"></div>

</div>


<script>

const cipher = {$jsCipher};

const display =
    document.getElementById('secret');

const status =
    document.getElementById('status');

const copy =
    document.getElementById('copy');


const chars =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ' +
    'abcdefghijklmnopqrstuvwxyz' +
    '0123456789!@#$%^&*';


const duration = 2000;

let secret = '';
let start = 0;


function randomChar() {

    return chars[
        Math.floor(
            Math.random() * chars.length
        )
    ];

}


function animate(now) {

    const elapsed =
        now - start;

    const progress =
        Math.min(
            elapsed / duration,
            1
        );

    /*
     * Characters resolve from
     * left to right.
     */
    const resolved =
        Math.floor(
            secret.length * progress
        );

    let output = '';

    for (
        let i = 0;
        i < secret.length;
        i++
    ) {

        if (secret[i] === '\\n') {

            output += '\\n';

        } else if (i < resolved) {

            output += secret[i];

        } else {

            output += randomChar();

        }

    }

    display.textContent = output;


    if (progress < 1) {

        requestAnimationFrame(
            animate
        );

    } else {

        display.textContent =
            secret;

        status.textContent =
            'DECRYPTED • DESTROYED';

        copy.style.visibility =
            'visible';

    }

}


function fail(message) {
    display.textContent = message;
    display.classList.add('secret-error');
    status.textContent = 'DECRYPTION FAILED';
}


function b64urlDecode(s) {
    const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
        bytes[i] = bin.charCodeAt(i);
    }
    return bytes.buffer;
}


async function boot() {
    /*
     * Capture the key first, then strip it from the visible URL.
     * The key lives only in this closure: never sent, never stored.
     */
    const frag = window.location.hash ? window.location.hash.slice(1) : '';
    try {
        history.replaceState(null, '', location.pathname + location.search);
    } catch (err) { /* cosmetic only */ }

    if (!window.crypto || !window.crypto.subtle) {
        fail('Web Crypto is unavailable in this browser, so this secret cannot be decrypted.');
        return;
    }

    if (!/^[A-Za-z0-9\-_]{43}$/.test(frag)) {
        fail('This link is missing its decryption key (the part after #). Ask the sender for the complete link. The secret on the server was already destroyed when revealed.');
        return;
    }

    let key;
    try {
        key = await window.crypto.subtle.importKey(
            'raw',
            b64urlDecode(frag),
            { name: 'AES-GCM' },
            false,
            ['decrypt']
        );
    } catch (err) {
        fail('The decryption key in this link is malformed.');
        return;
    }

    let plain;
    try {
        plain = await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: new Uint8Array(b64urlDecode(cipher.iv)) },
            key,
            b64urlDecode(cipher.enc)
        );
    } catch (err) {
        fail('Decryption failed. The link key does not match this secret, or the data is corrupt.');
        return;
    }

    secret = new TextDecoder().decode(plain);
    start = performance.now();

    requestAnimationFrame(
        animate
    );
}


boot();


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

const done =
    document.getElementById('done');


function flashCopied(message) {
    copy.innerHTML = btnMarkup.copied;
    done.textContent = message;
    setTimeout(function () {
        copy.innerHTML = btnMarkup.copy;
        done.textContent = '';
    }, 3000);
}


copy.addEventListener(
    'click',
    () => {
        try {
            navigator.clipboard.writeText(secret);
        } catch (err) {
            const ta = document.createElement('textarea');
            ta.value = secret;
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            ta.remove();
        }
        flashCopied('Copied to clipboard');
    }
);

</script>

</body>
</html>
HTML;

    exit;
}
