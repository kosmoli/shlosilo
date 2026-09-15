#!/usr/bin/env python3
"""Fresh end-to-end: A' → device sign → monero submit_transfer → on-chain.
Archived 2026-09-15 after the first successful fresh run (tx 2d2c40d1…).

NOTE on wallet freshness: the CLI does not always refresh on open — refresh
the watch-only via RPC (then close to SAVE) right before the CLI transfer,
and pre-flush new wallets with a harmless CLI run ('printf \\'\\nNo\\nexit\\n\\'').
The full state-discipline notes live in skill xmr-wallet-testing.

Spends the freshly funded A' UTXO, generates a new unsigned txset via the
watch-only wallet, feeds it to the device (new firmware), takes the signed
blob, and submits it through stock monero (submit_transfer) for the real
broadcast. Verifies receipt on the p2in side.

Run after wait_fund.py reports FUND_READY.
"""
import json
import os
import re
import subprocess
import sys
import time
import urllib.request

RPC = "http://127.0.0.1:18091/json_rpc"
CLI = "monero-wallet-cli"
DAEMON = ["--daemon-address", "127.0.0.1:18085", "--daemon-login", "komo:lixinying0115", "--trusted-daemon"]
WORK = "/tmp/p64run"
P2IN = "489yTDD88yiPuwTWTEwvYX7jqQbfmBp496rqiYwmuEtXithY5mAsXmsPJCc9xU8MFr66c7Yv91KgcGZAgddZ75Xs93qBWLM"
AMOUNT = "0.0006"

os.makedirs(WORK, exist_ok=True)


def rpc(method, params=None, timeout=240):
    req = urllib.request.Request(
        RPC,
        data=json.dumps({"jsonrpc": "2.0", "id": "0", "method": method, "params": params or {}}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def step(n, msg):
    print(f"\n=== step {n}: {msg} ===", flush=True)


# 0. close RPC wallet (file lock) and refresh the watch-only via CLI implicitly
step(0, "close RPC wallet")
try:
    print(json.dumps(rpc("close_wallet", timeout=60))[:120])
except Exception as e:
    print("close:", e)
time.sleep(1)

# 1. generate the unsigned txset (watch-only wallet; outputs unsigned_monero_tx in CWD)
step(1, f"generate unsigned: {AMOUNT} XMR -> p2in")
p = subprocess.run(
    "printf '\\nYes\\nYes\\n' | " + " ".join(
        [CLI, "--wallet-file", "/home/komo/sh_dev_correct", "--password", "''", *DAEMON,
         "transfer", P2IN, AMOUNT]
    ),
    shell=True, cwd=WORK, capture_output=True, text=True, timeout=240,
)
tail = "\n".join(p.stdout.splitlines()[-6:])
print(tail)
unsigned = os.path.join(WORK, "unsigned_monero_tx")
if not os.path.exists(unsigned):
    sys.exit("FAIL: no unsigned_monero_tx produced")
print("unsigned:", os.path.getsize(unsigned), "bytes")

# 2. encode fountain frames
step(2, "encode UR frames")
env = dict(os.environ)
env["P64_ENC_PATH"] = unsigned
env["P64_FRAMES_OUT"] = f"{WORK}/frames.txt"
p = subprocess.run(
    ["cargo", "test", "--release", "--test", "p64_xmr_multi_input", "--", "--ignored", "--nocapture", "encode_ur_frames"],
    cwd="/home/komo/works/shlosilo-poc4", capture_output=True, text=True, timeout=600, env=env,
)
print("\n".join(l for l in p.stdout.splitlines() if "fragment" in l or "wrote" in l))
frames = f"{WORK}/frames.txt"
if not os.path.exists(frames):
    sys.exit("FAIL: no frames produced")

# 3. device sign (reuse the bring-up driver; it reads /tmp/xmr_2in_frames.txt)
step(3, "device signing")
os.system(f"cp {frames} /tmp/xmr_2in_frames.txt")
os.system("cp /tmp/p64_device_run.py /tmp/p64_device_run_fresh.py")
p = subprocess.run(
    ["python3", "/tmp/p64_device_run_fresh.py"],
    capture_output=True, text=True, timeout=900,
)
out = p.stdout
print("\n".join(out.splitlines()[-8:]))
m = re.search(r"SIGNED: (\d+) bytes in (\d+)s", out)
if not m:
    sys.exit("FAIL: device signing did not complete (see output above)")
blob_size = int(m.group(1))
print(f"signed blob: {blob_size} bytes")

# 4. submit via stock monero
step(4, "submit_transfer (stock monero)")
os.system("cp /tmp/xmr_2in_device.bin " + WORK + "/signed_monero_tx")
p = subprocess.run(
    "printf 'Yes\\n' | " + " ".join(
        [CLI, "--wallet-file", "/home/komo/sh_dev_check", "--password", "''", *DAEMON,
         "--log-file", WORK + "/submit.log", "--log-level", "1", "submit_transfer"]
    ),
    shell=True, cwd=WORK, capture_output=True, text=True, timeout=300,
)
tail = "\n".join(l for l in p.stdout.splitlines() if "Loaded" in l or "submitted" in l or "Error" in l)
print(tail)
mt = re.search(r"Transaction successfully submitted, transaction <([0-9a-f]{64})>", p.stdout + p.stderr)
if not mt:
    # maybe relayed already known
    log = open(WORK + "/submit.log", errors="replace").read()
    mt2 = re.search(r"txid[: ]+([0-9a-f]{64})", log)
    if mt2:
        mt = mt2
if not mt:
    sys.exit("FAIL: submit did not report a txid")
txid = mt.group(1) if mt.lastindex else mt.group(0)
print("TXID:", txid)
json.dump({"txid": txid, "blob": blob_size}, open(f"{WORK}/fresh_tx.json", "w"), indent=2)
print("\nPIPELINE DONE — txid:", txid)
