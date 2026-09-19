#!/usr/bin/env python3
"""End-to-end regression test for the zero-knowledge secret flow.

Simulates a browser: passes the index.php gate, encrypts with AES-256-GCM,
stores ciphertext, then exercises fetch -> decrypt -> consume, proving that
a missing/wrong key or failed authentication never burns the record.

Usage:
    python3 tests/e2e.py https://example.com
    E2E_BASE_URL=https://example.com python3 tests/e2e.py
    python3 tests/e2e.py https://example.com --create wdscreate.php --reveal wdscare.php

The test creates one throwaway secret and consumes it, leaving the vault
exactly as it found it. Requires: python3 + cryptography package.
Exit code 0 when all checks pass, 1 otherwise.
"""
import argparse
import base64
import json
import os
import re
import sys
import time
import urllib.request
import urllib.parse
import urllib.error

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

UA = {"User-Agent": "Mozilla/5.0"}
jar = {}
fails = []


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_opener = urllib.request.build_opener(NoRedirect)


def req(base, method, path, data=None, headers=None):
    r = urllib.request.Request(
        base + path,
        data=urllib.parse.urlencode(data).encode() if data else None,
        method=method,
        headers={**UA, **(headers or {})},
    )
    if jar:
        r.add_header("Cookie", "; ".join(f"{k}={v}" for k, v in jar.items()))
    try:
        with _opener.open(r) as resp:
            out, status = resp.read().decode(), resp.status
            redir, hdrs = resp.headers.get("Location"), resp.headers
    except urllib.error.HTTPError as e:
        out, status = e.read().decode(errors="replace"), e.code
        hdrs = e.headers
        redir = hdrs.get("Location") if hdrs else None
    for h in (hdrs.get_all("Set-Cookie") if hdrs else []) or []:
        m = re.match(r"([^=]+)=([^;]+)", h)
        if m:
            jar[m.group(1)] = urllib.parse.unquote(m.group(2))
    return status, out, redir


def check(name, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + name, extra)
    if not cond:
        fails.append(name)


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64url(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def main() -> int:
    ap = argparse.ArgumentParser(description="Zero-knowledge flow regression test.")
    ap.add_argument("base_url", nargs="?", default=os.environ.get("E2E_BASE_URL"),
                    help="Site base URL, e.g. https://example.com (or E2E_BASE_URL env)")
    ap.add_argument("--create", default="pwcreate.php", help="Creation page filename")
    ap.add_argument("--reveal", default="pw1time.php", help="Reveal page filename")
    args = ap.parse_args()

    if not args.base_url:
        ap.error("base URL required as argument or E2E_BASE_URL environment variable")
    base = args.base_url.rstrip("/")
    create, reveal = args.create, args.reveal

    # --- gate: fetch challenge, verify ---
    s, html, _ = req(base, "GET", "/index.php")
    tok = re.search(r'const token = "([0-9a-f]+)";', html).group(1)
    exp = re.search(r'const exp = "(\d+)";', html).group(1)
    sig = re.search(r'const sig = "([0-9a-f]+)";', html).group(1)
    s, _, redir = req(base, "POST", "/index.php?action=verify",
                      {"token": tok, "exp": exp, "sig": sig, "sw": "1920", "sh": "1080"})
    check("gate verify", s == 303, s)

    # --- store ciphertext (as an encrypting browser would) ---
    secret = f"E2E regression probe {int(time.time())} (throwaway, auto-consumed)"
    raw_key = AESGCM.generate_key(bit_length=256)
    iv = os.urandom(12)
    ct = AESGCM(raw_key).encrypt(iv, secret.encode(), None)
    s, out, _ = req(base, "POST", f"/{create}?action=store",
                    {"enc": b64url(ct), "iv": b64url(iv)},
                    {"Accept": "application/json"})
    key = json.loads(out)["key"]
    check("store ok", s == 200, key)

    # --- consume the one-time link-display marker so no trace remains ---
    s, _, _ = req(base, "GET", f"/{create}?created={key}")
    check("link marker consumed", s == 200, s)

    # --- 1. fetch must NOT consume ---
    s, out, _ = req(base, "GET", f"/{reveal}?key={key}&action=fetch",
                    {}, {"Accept": "application/json"})
    env = json.loads(out)
    check("fetch ok", s == 200 and env.get("ok") is True, out[:100])
    check("fetch returns ciphertext only", "enc" in env and "iv" in env and "value" not in out)

    # --- 2. wrong key: decrypt fails, record must survive ---
    try:
        AESGCM(AESGCM.generate_key(bit_length=256)).decrypt(
            unb64url(env["iv"]), unb64url(env["enc"]), None)
        check("wrong key rejected", False, "DECRYPTED (BAD)")
    except InvalidTag:
        check("wrong key rejected", True)
    s, out, _ = req(base, "GET", f"/{reveal}?key={key}&action=fetch",
                    {}, {"Accept": "application/json"})
    check("record SURVIVES wrong-key attempt", s == 200 and json.loads(out).get("ok") is True, s)

    # --- 3. plaintext posts are rejected, never stored ---
    s, out, _ = req(base, "POST", f"/{create}?action=store", {"value": "plaintext-attempt"})
    check("plaintext POST rejected", s == 400, s)

    # --- 4. right key: decrypt, then consume ---
    pt = AESGCM(raw_key).decrypt(unb64url(env["iv"]), unb64url(env["enc"]), None).decode()
    check("decrypt roundtrip", pt == secret, repr(pt))
    s, out, _ = req(base, "POST", f"/{reveal}?key={key}&action=consume",
                    {}, {"Accept": "application/json"})
    check("consume ok", s == 200 and json.loads(out).get("ok") is True, out[:100])
    check("consume returns no secret", secret not in out and "enc" not in out)
    s, out, _ = req(base, "GET", f"/{reveal}?key={key}&action=fetch",
                    {}, {"Accept": "application/json"})
    check("record GONE after consume", s == 404, s)

    # --- 5. double consume is a clean 404 ---
    s, out, _ = req(base, "POST", f"/{reveal}?key={key}&action=consume",
                    {}, {"Accept": "application/json"})
    check("double consume 404", s == 404, s)

    print()
    print("FAILURES:", fails if fails else "none")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
