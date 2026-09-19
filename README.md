# PW One-Time Secret Vault

A minimal PHP single-page secret keeper. Three scripts:

- **`index.php`** — browser verification gate; the public entry point.
- **`pwcreate.php`** — create a secret, get a one-time secure link (requires passing the gate).
- **`pw1time.php`** — the recipient opens that link, confirms, and the secret is revealed and permanently destroyed (intentionally ungated so arbitrary email-link recipients can open it).

Produces links like `https://pw1time.presswizards.com/pw1time.php?key=<32-hex>`.

## Features

- **One-time reveal** — a secret can be viewed exactly once. The reveal destroys it so it can never be shown again.
- **10-day expiry** — every entry carries a timestamp; secrets not revealed within 10 days are automatically purged.
- **500 entry cap** — the vault refuses new entries once it holds 500 live secrets (expired ones are purged first, so they don't count).
- **4000 character limit** — values longer than 4000 bytes are rejected at creation time.
- **Email-scanner safe** — a plain GET on a link only shows a confirmation page; it never consumes the secret, so link previews / security scanners can't burn it.
- **PRG (Post/Redirect/Get)** — the create and reveal flows redirect after POST, so refreshing never re-submits and never shows a browser "resubmit form" prompt.
- **Browser verification gate** — `index.php` issues a stateless HMAC-signed challenge (token + 5-min expiry) that real-browser JS submits after capability checks (DOM, Web Crypto, cookies, screen) and a ~1.5s delay. Passing sets a signed `browser_verified` cookie (Secure, HttpOnly, SameSite=Strict, 30 min). `pwcreate.php` requires the cookie on both the form GET and the creation POST. Blocks curl, scanners, and blind form-POST bots; no CAPTCHA, no sessions, no stored tokens.
- **Zero-knowledge encryption** — secrets are encrypted in the browser with AES-256-GCM (Web Crypto, random 256-bit key + 12-byte IV per secret) before sending. The server stores only ciphertext + IV and never sees plaintext or the key. The key travels in the URL fragment (`?key=ID#KEY`), which browsers never send to the server, and is never stored in cookies/localStorage/sessionStorage. Legacy plaintext records keep working unchanged.
- **Honeypot anti-spam** — the create form includes an off-screen, JS-hidden field real humans never fill; any value there returns HTTP 403 before anything is stored.
- **Rolling decrypt animation** — the revealed secret resolves left-to-right through random characters over ~2 seconds, with a synced progress bar.
- **Copy button** — icon+text `Copy` button that flips to a checkmark `Copied` for 3 seconds. On the created-link page the link is auto-copied on load (with a graceful "use the Copy button" fallback when the browser blocks clipboard access).
- **Refresh-proof** — all pages send `Cache-Control: no-store`, excluding them from the back/forward bfcache so Back/Forward cannot resurface a revealed secret.

## How it works

### Create (`pwcreate.php`, requires the gate cookie)

1. Browser generates an AES-256-GCM key + IV, encrypts the secret, and POSTs only `enc` + `iv` (base64url) to `?action=store`. Plaintext submissions are rejected.
2. `storeCipher()` locks `pw1time.json`, purges expired entries, enforces the 500 cap, then writes `{ "<32-hex-key>": { "enc": ..., "iv": ..., "ts": <unix-time> } }`, and returns the key as JSON.
3. The browser navigates to `?created=<key>#<decryption-key>` (fragment never touches the server). A one-time `.pending/<key>` marker is consumed on first view, so the full link renders exactly once.

### Reveal (`pw1time.php`, ungated by design)

5. GET `?key=...#...` — the fragment never reaches the server. The confirm page captures it into a JS variable, strips it from the visible URL, and warns if an encrypted record's link arrived without one. Key regex-checked, vault read-only (email-scanner safe).
6. Reveal click — the browser fetch-POSTs the confirmation (`?action=reveal`), the entry is removed under lock and stashed to `.revealed/<key>` (tagged `ENC1:` envelope for ciphertext, raw text for legacy), and the browser navigates itself to `?key=...&revealed=1#...`, re-attaching the fragment client-side. Plain form POSTs still get the classic 303.
7. `?revealed=1` — the stash is read, displayed, then deleted. Encrypted stashes are decrypted in-browser (AES-GCM with the fragment key) and animated; legacy stashes render as before. Reload → 404.

Concurrency is handled with exclusive file locks; `pw1time.json` must be writable by the PHP-FPM user.

## Storage, escaping & XSS

- **At rest** — secrets live in a single JSON file (`pw1time.json`), written with `json_encode`. Keys are always 32–128 hex chars validated by regex.
- **Into JavaScript** — the reveal page embeds the value as `json_encode($value, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT)`, so `<`, `>`, `&`, `"`, and `'` become `\uXXXX` escapes. A value containing `</script>` cannot break out of the inline script.
- **Into the DOM** — the revealed value is rendered only via `textContent`, never `innerHTML`, so it is always displayed as plain text, never parsed as HTML.
- **Never echoed** — the user-supplied value is never interpolated back into any HTML outside the JSON-encoded script context.
- **File permissions** — PHP scripts are `700` to the FPM user; the vault JSON is `600` to the FPM user; `.pending/` and `.revealed/` are `0700`.

## Security headers

Sent on every page:

```
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Cache-Control: no-store, no-cache, must-revalidate, max-age=0
Pragma: no-cache
Expires: 0
```

Notes:

- `connect-src 'self'` — the create and reveal pages use `fetch()` to same-origin endpoints (encrypted store, fragment-preserving reveal); no third-party calls. The clipboard API is unaffected.
- `frame-ancestors 'none'` — clickjacking protection.
- `Referrer-Policy: no-referrer` — the one-time link carries the secret key in the query string; this stops it leaking via the `Referer` header.
- `no-store` — keeps the reveal page out of the back/forward cache.

## Data model

`pw1time.json` is a flat object keyed by the secret key (32–128 hex chars). New entries are zero-knowledge ciphertext; legacy plaintext entries keep working and are never migrated:

```json
{
    "cf8120a47e724c34a92cbba913bf9321": {
        "enc": "base64url AES-256-GCM ciphertext (plaintext + 16-byte tag)",
        "iv": "base64url 12-byte nonce",
        "ts": 1789796835
    },
    "legacy-example-key": {
        "value": "the secret text (pre-encryption format, still readable)",
        "ts": 1789796000
    }
}
```

- `value` — the stored secret (legacy format only, max 4000 bytes).
- `enc` / `iv` — AES-256-GCM ciphertext + nonce, base64url (current format; server validates ≤4096 ct bytes / exactly 12 iv bytes and rejects plaintext).
- `ts` — unix timestamp of creation; entries older than 10 days (`ENTRY_TTL = 10 * 86400`) are purged.
- Legacy plain-string values (pre-timestamp format) are still readable and are never treated as expired.

See `pw1time.json.example` for a full example.

## Limits summarized

| Limit | Value | Where enforced |
|---|---|---|
| Secret length | 4000 bytes plaintext max (enforced in-browser; server caps ciphertext at 4096 bytes) | create form JS + `pwcreate.php` POST handler |
| Entries | 500 max | `storeCipher()` in `pwcreate.php` |
| Expiry | 10 days | `ENTRY_TTL` constant, pruned on every create/reveal |
| Key format | `/^[a-f0-9]{32,128}$/i` | both scripts, before any path/URL use |

## Deployment summary

- PHP 8.x, PHP-FPM.
- Place `index.php`, `pw1time.php`, `pwcreate.php`, and `logo-extra.png` in `public_html/`.
- Keep `pw1time.json` one level above `public_html/` (path is `dirname(__DIR__) . '/pw1time.json'`), owned by the FPM user, mode `600`.
- The gate secret (`.gate-secret`) is auto-generated on first hit at the same level, mode `600`; pre-create it with `php -r "echo bin2hex(random_bytes(32)), PHP_EOL;"` for a known value.
- Own the `.php` files `700` to the FPM user.