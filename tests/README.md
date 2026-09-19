# E2E regression tests

`e2e.py` exercises the live zero-knowledge flow end to end: gate challenge,
encrypted store, fetch-without-burn, wrong-key survival, plaintext
rejection, decrypt roundtrip, consume, and double-consume. It creates one
throwaway secret and consumes it, leaving the vault as it found it.

Requirements: `python3` + the `cryptography` package
(`pip install cryptography`).

Run against a deployment (base URL as argument or env var):

```bash
python3 tests/e2e.py https://example.com
E2E_BASE_URL=https://example.com python3 tests/e2e.py
```

Page filenames default to this project's (`pwcreate.php` / `pw1time.php`);
override for other deployments:

```bash
python3 tests/e2e.py https://example.com --create wdscreate.php --reveal wdscare.php
```

Exit code is 0 when all checks pass, 1 otherwise. Never bakes in a
hostname, credential, token, path, or real secret — everything dynamic
comes from the target site at runtime.
