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
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
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
 * here (PRG). The value is stashed on disk so the redirect target can
 * display it without re-submitting anything; it's deleted after display,
 * so a reload shows the form/invalid state instead of a resubmit dialog.
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

    showValue($value);
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

    showConfirmation($key);
}

/*
 * POST: lock JSON, retrieve value, remove only this key,
 * write the remaining data back, stash the value, and redirect
 * so reloading the revealed page never re-submits the POST.
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

$value = entryValue($data[$key]);
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

if (flock($sfp, LOCK_EX) && fwrite($sfp, $value) !== false) {
    fflush($sfp);
    flock($sfp, LOCK_UN);
}
fclose($sfp);

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


function showConfirmation(string $key): never
{
    $key = htmlspecialchars($key, ENT_QUOTES, 'UTF-8');

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
</style>
</head>

<body>

<div class="modal">
<center><img src="logo-extra.png" height="50" style="max-width:225px;display:block;border:none;margin:0 auto 24px;filter:drop-shadow(1px 0 0 gray) drop-shadow(-1px 0 0 gray) drop-shadow(0 1px 0 gray) drop-shadow(0 -1px 0 gray);" alt="Watchdog Studio"></center><br>
    <div class="icon">⌁</div>

    <h2>Secure Information</h2>

    <p>
        This information can only be viewed once.
        Once revealed, it will be permanently deleted.
    </p>

    <form method="post" action="?key={$key}">
        <button type="submit">Reveal Secure Information</button>
    </form>
</div>

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
