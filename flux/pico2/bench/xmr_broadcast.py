#!/usr/bin/env python3
"""Broadcast a raw tx (extracted from a signed blob) to the local monerod.

Usage: python3 xmr_broadcast.py [raw_tx_file]
  default raw_tx_file = /tmp/p64_tx_from_device.bin

Produce raw_tx_file first:
  cargo test --release --test p64_xmr_multi_input -- --ignored --nocapture \
      extract_tx_for_broadcast      (P64_BLOB_PATH / view key via env)

Endpoint notes (monerod v0.18.5.1):
- The /send_raw_transaction handler is MAP_URI_AUTO_JON2 = `load_t_from_json`:
  the body MUST be JSON (`{"tx_as_hex": "<hex>"}`); a form-encoded body gets
  HTTP 400 with an empty response.
- The unrestricted RPC needs HTTP digest auth. Python's urllib digest is NOT
  compatible with epee's server here (401s); `requests.HTTPDigestAuth` and
  curl --digest both work (verified).
- Credentials come from the environment (never hardcode).

Response semantics: status OK + not_relayed=false = freshly accepted;
status OK + not_relayed=true ("Not relayed") = the network already knows the
tx (duplicate submission). Any failing check field is a rejection verdict.
"""
import json
import os
import subprocess
import sys

RAW = sys.argv[1] if len(sys.argv) > 1 else "/tmp/p64_tx_from_device.bin"
URL = os.environ.get("MONERO_RPC_URL", "http://127.0.0.1:18085/send_raw_transaction")
USER = os.environ.get("MONERO_RPC_USER", "")
PASS = os.environ.get("MONERO_RPC_PASS", "")

tx = open(RAW, "rb").read()
print(f"raw tx: {len(tx)} bytes")
body = json.dumps({"tx_as_hex": tx.hex()})

resp = None
try:
    import requests
    from requests.auth import HTTPDigestAuth

    r = requests.post(
        URL,
        data=body,
        headers={"Content-Type": "application/json"},
        auth=HTTPDigestAuth(USER, PASS) if USER else None,
        timeout=90,
    )
    resp = json.loads(r.text) if r.status_code == 200 else None
    if resp is None:
        print("HTTP", r.status_code, r.text[:300])
except Exception as e:
    print("requests path failed:", e)

if resp is None:
    # curl fallback (proven against epee digest)
    cmd = ["curl", "-s", "--max-time", "90"]
    if USER:
        cmd += ["--digest", "-u", f"{USER}:{PASS}"]
    cmd += ["-X", "POST", URL, "-H", "Content-Type: application/json",
            "--data-binary", "@-"]
    p = subprocess.run(cmd, input=body.encode(), capture_output=True)
    try:
        resp = json.loads(p.stdout.decode())
    except Exception:
        print("curl path failed:", p.stdout.decode()[:300], p.stderr.decode()[:200])
        sys.exit(1)

print(json.dumps(resp, indent=2))
checks = ["double_spend", "invalid_input", "invalid_output", "overspend",
          "sanity_check_failed", "low_mixin", "fee_too_low"]
bad = [c for c in checks if resp.get(c)]
if resp.get("status") == "OK" and not bad:
    if resp.get("not_relayed"):
        print("ALREADY KNOWN to the network (duplicate submission, OK)")
    else:
        print("ACCEPTED by the daemon (full validation passed)")
else:
    print("REJECTED:", bad or resp.get("reason") or resp.get("status"))
    sys.exit(1)
