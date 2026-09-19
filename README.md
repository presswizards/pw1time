# Watchdog One-Time Secret Vault

A minimal PHP single-page secret keeper. Two scripts:

- **`wdscreate.php`** — create a secret, get a one-time secure link.
- **`wdscare.php`** — the recipient opens that link, confirms, and the secret is revealed and permanently destroyed.

Produces links like `https://wdscare1time.wdsdns.net/wdscare.php?key=<32-hex>`.

## Features

- **One-time reveal** — a secret can be viewed exactly once. The reveal destroys it so it can never be shown again.
- **10-day expiry** — every entry carries a timestamp; secrets not revealed within 10 days are automatically purged.
- **500 entry cap** — the vault refuses new entries once it holds 500 live secrets (expired ones are purged first, so they don't count).
- **4000 character limit** — values longer than 4000 bytes are rejected at creation time.
- **Email-scanner safe** — a plain GET on a link only shows a confirmation page; it never consumes the secret, so link previews / security scanners can't burn it.
- **PRG (Post/Redirect/Get)** — the create and reveal flows redirect after POST, so refreshing never re-submits and never shows a browser "resubmit form" prompt.
- **Honeypot anti-spam** — the create form includes an off-screen, JS-hidden field real humans never fill; any value there returns HTTP 403 before anything is stored.
- **Rolling decrypt animation** — the revealed secret resolves left-to-right through random characters over ~2 seconds, with a synced progress bar.
- **Copy button** — icon+text `Copy` button that flips to a checkmark `Copied` for 3 seconds. On the created-link page the link is auto-copied on load (with a graceful "use the Copy button" fallback when the browser blocks clipboard access).
- **Refresh-proof** — all pages send `Cache-Control: no-store`, excluding them from the back/forward bfcache so Back/Forward cannot resurface a revealed secret.

## How it works

### Create (`wdscreate.php`)

1. POST the secret value.
2. `storeValue()` locks `wdscare.json` (exclusive `flock`), purges any entries older than 10 days, rejects the request if the vault is at the 500 cap, then writes `{ "<32-hex-key>": { "value": ..., "ts": <unix-time> } }`.
3. A one-time `.pending/<key>` marker is written.
4. `303` redirect to `?created=<key>` — the link page consumes the marker and renders the link exactly once; any later visit shows the form again.

### Reveal (`wdscare.php`)

5. GET `?key=...` — key regex-checked (`/^[a-f0-9]{32,128}$/i`) against path/URL use, then the vault is read to confirm the key exists. *Not* consumed (email scanners get no side effects).
6. POST confirmation — the file is locked, expired entries are purged, the entry is removed from the JSON and its value is stashed to `.revealed/<key>`.
7. `303` redirect to `?key=...&revealed=1` — the stash is read, displayed once via the animation, then deleted. A reload shows "Invalid URL" (HTTP 404).

Concurrency is handled with exclusive file locks; `wdscare.json` must be writable by the PHP-FPM user.

## Storage, escaping & XSS

- **At rest** — secrets live in a single JSON file (`wdscare.json`), written with `json_encode`. Keys are always 32–128 hex chars validated by regex.
- **Into JavaScript** — the reveal page embeds the value as `json_encode($value, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT)`, so `<`, `>`, `&`, `"`, and `'` become `\uXXXX` escapes. A value containing `</script>` cannot break out of the inline script.
- **Into the DOM** — the revealed value is rendered only via `textContent`, never `innerHTML`, so it is always displayed as plain text, never parsed as HTML.
- **Never echoed** — the user-supplied value is never interpolated back into any HTML outside the JSON-encoded script context.
- **File permissions** — PHP scripts are `700 wdscare11:wdscare11`; the vault JSON is `600 wdscare11:wdscare11`; `.pending/` and `.revealed/` are `0700`.

## Security headers

Sent on every page:

```
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Cache-Control: no-store, no-cache, must-revalidate, max-age=0
Pragma: no-cache
Expires: 0
```

Notes:

- `connect-src 'none'` — the app makes no `fetch`/XHR calls (the clipboard API is unaffected).
- `frame-ancestors 'none'` — clickjacking protection.
- `Referrer-Policy: no-referrer` — the one-time link carries the secret key in the query string; this stops it leaking via the `Referer` header.
- `no-store` — keeps the reveal page out of the back/forward cache.

## Data model

`wdscare.json` is a flat object keyed by the secret key (32–128 hex chars):

```json
{
    "cf8120a47e724c34a92cbba913bf9321": {
        "value": "the secret text",
        "ts": 1789796835
    }
}
```

- `value` — the stored secret (max 4000 bytes).
- `ts` — unix timestamp of creation; entries older than 10 days (`ENTRY_TTL = 10 * 86400`) are purged.
- Legacy plain-string values (pre-timestamp format) are still readable and are never treated as expired.

See `wdscare.json.example` for a full example.

## Limits summarized

| Limit | Value | Where enforced |
|---|---|---|
| Secret length | 4000 bytes max | `wdscreate.php` POST handler |
| Entries | 500 max | `storeValue()` in `wdscreate.php` |
| Expiry | 10 days | `ENTRY_TTL` constant, pruned on every create/reveal |
| Key format | `/^[a-f0-9]{32,128}$/i` | both scripts, before any path/URL use |

## Deployment summary

- PHP 8.x, PHP-FPM (scripts run as the `wdscare11` user on the Enhance server).
- Place `wdscare.php`, `wdscreate.php`, and `logo-extra.png` in `public_html/`.
- Keep `wdscare.json` one level above `public_html/` (path is `dirname(__DIR__) . '/wdscare.json'`), owned by the FPM user, mode `600`.
- Own the `.php` files `700` to the FPM user.