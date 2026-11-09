#!/usr/bin/env python3
"""Build a PSBT fixture whose change output is a TAPROOT output of ours.

Why this exists
---------------
The review page decides "change vs payment" from the derivation record a wallet
puts on an output: field 0x02 for legacy/segwit, field 0x16 for taproot. A build
that only reads 0x02 labels a P2TR change output as a payment, so the operator
sees their own money leaving as if it were a new spend, and the address prefix
(bech32m vs bech32) is the only hint anything is different. The genuine wallet
case is proven on device; this fixture pins the parser and the labelling in CI.

What it produces
----------------
`sparrow_signet_taproot_change.psbt`, derived from the real Sparrow signet
fixture by:

  1. replacing output 1's scriptPubKey with `OP_1 <32-byte x-only key>`, so the
     change output really is a P2TR output of ours (address rendering gets
     exercised too);
  2. dropping output 1's segwit derivation record (0x02) and giving it a taproot
     one instead: `0x16 || x_only -> 0x00 (no leaf hashes) || f3b9960b ||
     m/86'/1'/0'/1/0` (chain/index = 1, i.e. change).

That is what a taproot wallet really emits, and it means the `change` label in the
test can only come from the 0x16 path. Output 0 (the payment to a foreign address)
is left exactly as Sparrow wrote it.

Nothing else is touched: input records, the payment output (output 1 keeps the
foreign address) and every other field stay byte-identical to the Sparrow
fixture, and the generator re-parses what it writes before saving.

Run: python3 tools/make_taproot_change_fixture.py <64-hex-x-only-pubkey>
"""

import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]
SRC = REPO / "tests/fixtures/sparrow_signet_12k.psbt"
DST = REPO / "tests/fixtures/sparrow_signet_taproot_change.psbt"

MASTER_FP = bytes.fromhex("f3b9960b")
# m/86'/1'/0'/0/0 - the receive key the (rewritten) P2TR input spends from
RECV_X_ONLY = "94b210025b91946244762f232d2da923e110c4902ecb734ab281f4e01c9ef89f"
# m/86'/1'/0'/1/0 - taproot BIP-44 chain 1 (change)
PATH = [0x80000056, 0x80000001, 0x80000000, 0x00000001, 0x00000000]


def read_cs(buf, pos):
    n = buf[pos]
    if n < 0xFD:
        return n, pos + 1
    if n == 0xFD:
        return int.from_bytes(buf[pos + 1 : pos + 3], "little"), pos + 3
    if n == 0xFE:
        return int.from_bytes(buf[pos + 1 : pos + 5], "little"), pos + 5
    return int.from_bytes(buf[pos + 1 : pos + 9], "little"), pos + 9


def write_cs(n):
    if n < 0xFD:
        return bytes([n])
    return b"\xfd" + n.to_bytes(2, "little")


def parse_map(buf, pos):
    """Return (records, pos_after_terminator)."""
    records = []
    while True:
        keylen, pos = read_cs(buf, pos)
        if keylen == 0:
            return records, pos
        key = bytes(buf[pos : pos + keylen])
        pos += keylen
        vallen, pos = read_cs(buf, pos)
        value = bytes(buf[pos : pos + vallen])
        pos += vallen
        records.append((key, value))


def encode_map(records):
    out = b""
    for key, value in records:
        out += write_cs(len(key)) + key + write_cs(len(value)) + value
    return out + b"\x00"


def tx_output_spk_offsets(tx):
    """(offset, length) of scriptPubKey for every output of a serialized tx."""
    pos = 4
    if tx[pos : pos + 2] == b"\x00\x01":
        pos += 2
    vin, pos = read_cs(tx, pos)
    for _ in range(vin):
        pos += 36
        sl, pos = read_cs(tx, pos)
        pos += sl + 4
    vout, pos = read_cs(tx, pos)
    spans = []
    for _ in range(vout):
        pos += 8  # value
        sl, pos = read_cs(tx, pos)
        spans.append((pos, sl))
        pos += sl
    return spans


def main():
    if len(sys.argv) != 2 or len(sys.argv[1]) != 64:
        sys.exit("usage: make_taproot_change_fixture.py <64-hex x-only pubkey>")
    x_only = bytes.fromhex(sys.argv[1])
    assert len(x_only) == 32

    raw = bytearray(SRC.read_bytes())
    assert raw[:5] == b"psbt\xff"
    global_records, pos = parse_map(raw, 5)

    # find + rewrite the unsigned transaction: output 0 becomes a P2TR output of ours
    tx_idx = next(i for i, (k, _) in enumerate(global_records) if k == b"\x00")
    tx = bytearray(global_records[tx_idx][1])
    spans = tx_output_spk_offsets(tx)
    off, old_len = spans[1]
    new_spk = b"\x51\x20" + x_only
    # The scriptPubKey carries a compact-size length prefix; replacing 22 bytes
    # with 34 without rewriting it leaves the transaction self-inconsistent and
    # every honest parser (including ours) rejects it - which is how this bug was
    # found. Rebuild from the prefix instead of patching in place.
    assert old_len < 0xFD, "expected a single-byte length prefix"
    prefix_at = off - 1
    assert tx[prefix_at] == old_len, "length prefix does not match the script span"
    tx = tx[:prefix_at] + write_cs(len(new_spk)) + new_spk + tx[off + old_len :]
    global_records[tx_idx] = (b"\x00", bytes(tx))
    new_tx = bytes(tx)

    # input count from the tx
    p = 4
    if new_tx[p : p + 2] == b"\x00\x01":
        p += 2
    vin, p = read_cs(new_tx, p)
    inputs = []
    for _ in range(vin):
        records, pos = parse_map(raw, pos)
        inputs.append(records)
    # outputs: read all, then rewrite output 0's map
    outputs = []
    for _ in range(len(spans)):
        records, pos = parse_map(raw, pos)
        outputs.append(records)
    assert pos == len(raw), "trailing bytes after the last map"

    # Input: a taproot input records its path under 0x16 too (PSBT_IN_TAP_BIP32_
    # DERIVATION). Build the realistic shape: P2TR witness UTXO + 0x16 only, with
    # no non_witness_utxo (a taproot spend does not need the full prevout).
    wu_idx = next(i for i, (k, _) in enumerate(inputs[0]) if k == b"\x01")
    amount = inputs[0][wu_idx][1][:8]
    recv_x_only = bytes.fromhex(RECV_X_ONLY)
    new_wu = amount + write_cs(len(b"\x51\x20" + recv_x_only)) + b"\x51\x20" + recv_x_only
    in_path = [0x80000056, 0x80000001, 0x80000000, 0x00000000, 0x00000000]
    # Drop the segwit-side records the taproot spend does not carry: 0x00
    # (non_witness_utxo), 0x06 (plain derivation - the input twin of the output's
    # 0x02), 0x07/0x08 (final scriptSig/witness). Keeping 0x06 would let a broken
    # network inference still pass, which is exactly what the first version of this
    # fixture did.
    inputs[0] = [
        r for r in inputs[0]
        if r[0] not in (b"\x00", b"\x06", b"\x07", b"\x08", b"\x01")
        and r[0][:1] != b"\x06"
    ] + [
        (b"\x01", new_wu),
        (
            b"\x16" + recv_x_only,
            b"\x00" + MASTER_FP + b"".join(e.to_bytes(4, "little") for e in in_path),
        ),
    ]

    outputs[1] = [r for r in outputs[1] if not r[0][:1] in (b"\x02", b"\x16")] + [
        (
            b"\x16" + x_only,
            b"\x00" + MASTER_FP + b"".join(e.to_bytes(4, "little") for e in PATH),
        )
    ]

    out = b"psbt\xff" + encode_map(global_records)
    for records in inputs:
        out += encode_map(records)
    for records in outputs:
        out += encode_map(records)

    # re-parse what we are about to write: same structure, output 0 is P2TR + 0x16
    assert out[:5] == b"psbt\xff"
    gr, gp = parse_map(out, 5)
    tx2 = next(v for k, v in gr if k == b"\x00")
    spk2 = tx2[tx_output_spk_offsets(tx2)[1][0] :][:34]
    assert spk2 == new_spk, "output 1 scriptPubKey rewrite lost"
    vin2, pp = read_cs(tx2, 4 if tx2[4:6] != b"\x00\x01" else 6)
    for _ in range(vin2):
        _, gp = parse_map(out, gp)
    _, gp = parse_map(out, gp)  # output 0 untouched
    om1, _ = parse_map(out, gp)
    assert any(k[:1] == b"\x16" and k[1:] == x_only for k, _ in om1), "0x16 record missing"
    assert not any(k[:1] == b"\x02" for k, _ in om1), "the 0x02 record must be gone"

    DST.write_bytes(out)
    print(f"wrote {DST} ({len(out)} bytes, source {len(raw)})")
    print(f"output 1: P2TR OP_1 <{x_only.hex()}> + 0x16 derivation m/86'/1'/0'/1/0 (change)")


if __name__ == "__main__":
    main()
