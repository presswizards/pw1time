<?php

declare(strict_types=1);

/*
 * Never let the browser cache any of these pages, so the one-time
 * link page can't be resurrected from back/forward cache either.
 */
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');

$jsonFile = dirname(__DIR__) . '/pw1time.json';
$pendingDir = dirname(__DIR__) . '/.pending';

const MAX_ENTRIES = 500;
const ENTRY_TTL = 10 * 86400;

/*
 * POST: store a secret under a freshly generated key, then redirect (PRG)
 * so a reload never re-submits the form.
 */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $value = (string) ($_POST['value'] ?? '');
    $value = trim($value);

    /*
     * Honeypot: a JS-hidden field real humans never fill.
     * Any content means an automated bot submitted the form.
     */
    if (trim((string) ($_POST['company'] ?? '')) !== '') {
        http_response_code(403);
        echo renderForbidden();
        exit;
    }

    if ($value === '') {
        diePage(renderForm('<em>Please enter a value to store.</em>'));
    }

    if (strlen($value) > 4000) {
        diePage(renderForm('<em>Value is too long (max 4000 characters).</em>'));
    }

    $key = storeValue($jsonFile, $value);

    /*
     * One-time marker so the generated link is shown exactly once;
     * the marker is removed on first view, so reloading shows the form.
     */
    if (!is_dir($pendingDir)) {
        @mkdir($pendingDir, 0700, true);
    }
    @file_put_contents($pendingDir . '/' . $key, (string) time(), LOCK_EX);

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

function storeValue(string $file, string $value): string
{
    $key = bin2hex(random_bytes(16)); // 32 hex chars, matches /^[a-f0-9]{32,128}$/i

    $fp = @fopen($file, 'c+');

    if (!$fp || !flock($fp, LOCK_EX)) {
        if ($fp) {
            fclose($fp);
        }
        diePage(renderForm('<em>The vault is busy. Please try again.</em>'));
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
        diePage(renderForm('<em>Vault is full (500 entries max). Please retry later.</em>'));
    }

    $data[$key] = [
        'value' => $value,
        'ts' => $now,
    ];

    rewind($fp);
    ftruncate($fp, 0);

    fwrite(
        $fp,
        json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL
    );

    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);

    return $key;
}


function baseUrl(): string
{
    $host = $_SERVER['HTTP_HOST'] ?? '';

    if ($host === '' || filter_var($host, FILTER_VALIDATE_IP)) {
        return 'https://wdscare1time.wdsdns.net';
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

    <h2>Add to Vault</h2>

    <p>
        Enter the secret value to store.
        A one-time link valid for only 10 days will be generated for it.
    </p>

    {$errorBlock}

    <form method="post" action="pwcreate.php">
        <input type="text" name="company" id="company" class="company" tabindex="-1" autocomplete="off" aria-hidden="true">
        <textarea name="value" placeholder="Secret value to store ..." autofocus required></textarea>
        <button type="submit">Add To Vault</button>
    </form>

    <script>
        document.getElementById('company').style.display = 'none';
    </script>

    <p class="form-hint">
        Every visit starts a fresh entry. Values are stored until
        their one-time link is revealed, then permanently deleted.
        Unrevealed links expire automatically after 10 days.
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

const linkText = {$jsLink};

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
        await navigator.clipboard.writeText(linkText);
    } catch (err) {
        const ta = document.createElement('textarea');
        ta.value = linkText;
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