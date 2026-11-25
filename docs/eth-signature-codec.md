# `ur:eth-signature` codec — contract (E-0)

Scope: the outbound container a device returns after signing an `eth-sign-request`.
This document is the contract for `forms/ur/codec/eth_signature.rs` plus the
`eth-sign-request` parse additions it needs. It does **not** cover the sign path
change (E-1) or hardware acceptance (E-2).

## Authority

Container layout is taken from `@keystonehq/bc-ur-registry-eth` `ETHSignature`
(gold vector and decode call below are copied from
`keystone-sdk-web/src/__tests__/ethereum.test.ts`, which reaches the SDK through
`ETHSignature.fromCBOR(ur.cbor)` — i.e. the UR **message is the CBOR map itself,
not a byte-string shell**).

## Wire layout

CBOR map, exactly three keys, canonically ordered 1, 2, 3:

| key | CBOR type | content |
|---|---|---|
| 1 | tag(37) + bytes(16) | `requestId`, **echoed from the request** (`eth-sign-request` key 1) |
| 2 | bytes(65..=72) | `r ‖ s ‖ v` — r 32 B, s 32 B, v 1..=8 B |
| 3 | text (optional) | `origin`, echoed from the request (key 7) |

`v` is **opaque** to this container: 1..=8 bytes, no 27 offset added, no range check.
Chain semantics belong to the signer and are pinned there (E-1):

| path | v | bytes on the wire |
|---|---|---|
| EIP-1559 (`0x02`) | `0` / `1` (yParity) | 1 |
| legacy unprotected (6-item) | *refused* (`FeatureNotImplemented`) — no replay protection | — |
| legacy EIP-155 (9-item) | `chain_id*2 + 35 + {0,1}` ⇒ `37`/`38` on chain 1, `309`/`310` on 137, `22310257`/`22310258` on 11155111 | 1 / 2 / 4 |
| EIP-191 `personal_sign` / EIP-712 | `27` / `28` | 1 |

### Why `v` is variadic (E-1, 2026-11-25)

`v` was one byte while the only wired-up schemes were EIP-1559 and EIP-191. EIP-155
makes `v = chain_id * 2 + 35 + y_parity`, a `u64`: mainnet fits in one byte, Polygon
(137 → 309) needs two, Sepolia (11155111 → 22310257) needs four. A fixed 65-byte
signature could not carry a Sepolia `v` at all, so key 2 is now 65..=72 bytes and the
`v` segment is written **big-endian, minimal** (leading zero bytes dropped; `v == 0` is
a single `0x00` byte) — byte for byte what keystone's reference implementation does in
`rust/apps/ethereum/src/structs.rs::EthereumSignature::serialize`.

That minimal form is also what makes the container canonical: `v = 309` has exactly one
encoding (`01 35`). Accepting `00 01 35` as well would give one signature two byte
strings, so a padded `v` is rejected on both sides.

Sizes: 99 B for an 8-char origin and a 65-byte signature. Worst case with the origin cap
below is 163 B (72-byte signature + 64-byte origin); `ETH_SIGNATURE_CBOR_MAX_LEN = 168`
leaves margin.

## Gold vector (byte-exact target)

```
a3 01 d82550 9b1deb4d3b7d4bad9bdd2b0d7b3dcb6d
   02 5841 d4f0a7bcd95bba1fbb1051885054730e3f47064288575aacc102fbbf6a9a14d
            aa066991e360d3e3406c20c00a40973eff37c7d641e5b351ec4a99bfe86f335f713
   03 686b657973746f6e65
```

Decodes to `requestId = 9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d`,
`signature = d4f0…f713`, `origin = "keystone"`. Our encoder must reproduce these
bytes exactly for those three fields.

## API

```rust
pub const ETH_SIGNATURE_CBOR_MAX_LEN: usize = 168;
/// Shortest `r ‖ s ‖ v`: 64 + a one-byte v.
pub const SIGNATURE_MIN_LEN: usize = 65;
/// Longest: 64 + a full-width 8-byte v (EIP-155's v is a u64).
pub const SIGNATURE_MAX_LEN: usize = 72;
// The origin cap is shared with the inbound `eth-sign-request` key 7, so it
// lives in `forms/types/caps.rs` — neither layer-E codec imports its sibling.
// pub const ETH_UR_ORIGIN_MAX_LEN: usize = 64;

pub struct EthSignature<'a> {
    pub request_id: [u8; 16],
    /// Only the first `signature_len` bytes are on the wire.
    pub signature: [u8; SIGNATURE_MAX_LEN],
    /// 65..=72 (64 + the width of v).
    pub signature_len: usize,
    pub origin: Option<&'a str>,
}

impl EthSignature<'_> {
    /// The `r ‖ s ‖ v` bytes that go on the wire (empty if `signature_len` is
    /// out of range — every encode refuses that shape anyway).
    pub fn signature_bytes(&self) -> &[u8];
}

/// CBOR message only (no UR wrapper), into the caller's buffer.
/// Zero-alloc: writes structurally through `encoding::cbor::CborWriter`.
pub fn encode_eth_signature_into(sig: &EthSignature<'_>, out: &mut [u8]) -> Result<usize>;

/// Borrowed decode of the CBOR message.
pub fn parse_eth_signature(payload: &[u8]) -> Result<EthSignature<'_>>;

/// Full `ur:eth-signature/...` string (test/transitional shell only).
#[cfg(any(feature = "alloc-fallback", test))]
pub fn encode_eth_signature_ur(sig: &EthSignature<'_>) -> Result<UrEncoded>;
```

The `v` byte itself is produced by `forms/chain/eth/eip155.rs::write_v_be` (minimal
big-endian, keystone's rule) and is the only producer of that segment.

## Strictness rules (each gets a pin)

Encode:
- missing required field cannot happen by construction; `origin` over
  `ETH_UR_ORIGIN_MAX_LEN` is an error, not a truncation;
- `signature_len` outside 65..=72, or a multi-byte `v` whose first byte is `0x00`, is
  `EncodingInvalidFormat` — the encoder never mints a non-canonical container;
- buffer under-capacity returns `BufferTooSmall` with the required length in the
  error context — never a partial write reported as success.

Parse (fail closed, no silent defaulting):
- non-map payload → `EncodingInvalidFormat`;
- key 1 absent or not `tag(37)` over exactly 16 bytes → error (uuid tag is
  whitelisted, not "any tag");
- key 2 absent or shorter than 65 bytes → error (a 64-byte `r‖s` must not be
  accepted and short-filled);
- key 2 longer than 72 bytes → error (no `v` is wider than 8 bytes);
- key 2 wider than 65 bytes whose `v` segment starts with `0x00` → error (only the
  minimal big-endian form is canonical; see above);
- key 3 present but not text, or longer than the cap → error;
- trailing garbage after the single top-level item → error (the shared
  `encoding::cbor::decode` already enforces this — do not add a second parser).

## `UrTypeTag` wiring

Add `UrTypeTag::EthSignature`:
- `from_name`: `"eth-signature"` (case-folded, same path as the rest);
- `type_name` / `type_name_cstr`: `"eth-signature"` (the existing pin asserts the
  two agree for every tag);
- `message_is_cbor_item`: **include it** — the peer decodes the message as the
  map (`ETHSignature.fromCBOR(ur.cbor)`), so a byte-string shell would break
  every consumer. Pin this explicitly: a shell-shaped `eth-signature` is the
  exact failure the `crypto-hdkey` / `eth-sign-request` rows were added for;
- `from_bytes` (legacy first-byte inference): **do not** add a row. That
  inference is a legacy-FFI compatibility path keyed on payload first byte; a new
  outbound-only type has no inbound legacy encoding.

## `eth-sign-request` parse additions

`EthSignRequest` gains:

```rust
pub request_id: Option<[u8; 16]>,  // key 1: tag(37) + 16 B, validated when present
pub origin: Option<&'a str>,       // key 7: text, bounded by the origin cap
```

Absent remains `None` (existing fixtures build maps without key 1; the E-1 exit
requires it before it can echo an id). Malformed present values are errors.

## Pins

1. `eth_signature_gold_vector_decodes` — gold bytes → fields as above.
2. `eth_signature_encode_matches_gold_vector_byte_exact` — encode(gold fields) ==
   gold bytes.
3. `eth_signature_round_trip_through_ur` — `encode_eth_signature_ur` → decode →
   `parse_eth_signature` → fields equal, and the UR type tag survives.
4. `eth_signature_echoes_request_id_no_regeneration` — two different ids produce
   two different encodings and each parses back to its own id (the container never
   mints an id).
5. `eth_signature_rejects_64_byte_signature`
6. `eth_signature_rejects_unwrapped_uuid` — key 1 as plain 16-byte string (no tag
   37) → error.
7. `eth_signature_rejects_oversized_origin`
8. `eth_signature_rejects_trailing_garbage`
9. `eth_signature_and_eth_sign_request_are_cbor_items` — `message_is_cbor_item`
   true for both, false for `xmr-txsigned`.
10. `eth_sign_request_exposes_request_id_and_origin` — official ur-registry
    `test_encode` vector (already in `eth_sign_request.rs`) yields
    `request_id = 9b1deb4d-…` and `origin = "metamask"`.
11. `eth_sign_request_rejects_bad_uuid_tag` — key 1 with tag 999 → error.

## Non-goals for E-0

- `ur:eth-batch-signature` (`ETHBatchSignature`) — deferred, no consumer yet.
- Any change to the sign path, output type name selection (`ur::type_table`) or
  the FFI surface — those are E-1.

## E-1: the exit path (what the signer must change)

The current ETH exit writes the **signed raw transaction** (`0x02 ‖ rlp([...])`,
`forms/chain/eth/eip1559.rs`) into the output buffer, and
`tests`/`forms/ffi/c_abi.rs` pin exactly that (`out == expected.tx_bytes`). No
wallet in this dialect consumes a signed raw tx: the wallet assembles and
broadcasts, the device returns `eth-signature`. So E-1 is a **split plus a
rewire**, not a wrapper:

1. **Split `eip1559`** — `pub struct Eip1559Signature { signing_hash, r, s, y_parity }`
   and `pub fn sign_eip1559_parts(input) -> Result<Eip1559Signature>` (hash → ECDSA
   → low-s flip, i.e. today's steps 1–2.5). `sign_eip1559_into` becomes *parts then
   serialize* and keeps its `written`-carrying outcome, so the single production
   caller in `business/sign.rs` and the allocating test convenience `sign_eip1559`
   are untouched. Leaving the tx serialization in the exit path would compute RLP
   bytes nobody sends and size the buffer for a tx instead of 156 B.
2. **`business::sign::sign_eth`** stops returning tx bytes: it parses the request,
   signs, assembles `r ‖ s ‖ v` with **v = y_parity (0/1)** for EIP-1559, and calls
   `encode_eth_signature_into` into the caller's buffer. `request_id` is required
   here: a reply without the id cannot be correlated by the sender, so a request
   that omits key 1 fails with `EncodingInvalidFormat` instead of producing an
   orphan signature. `request_id` is echoed, never minted; `origin` is echoed when
   present.
3. **`ur::type_table::reply_type`** answers `eth-signature` for `eth-sign-request`
   (one row), plus the `static_cstr` closed-set member — the existing table test
   asserts every reply name round-trips, so a missed member is red, not silent.
   Flux needs no change: it already asks `shlosilo_ur_type_reply_ffi` and hands the
   payload to the frame encoder, and the container fits any output buffer.
4. **Rewrite the three pins that assert tx bytes** (`business/sign.rs`
   `sign_eth_end_to_end`, `sign_eth_uses_request_derivation_path`, and
   `forms/ffi/c_abi.rs::ffi_sign_ur_eth_end_to_end`): compare the container's r/s/v
   against the independent `sign_eip1559` oracle, assert the output no longer starts
   with `0x02`, and add key 1 to the request fixtures so the echo has a value.
5. **New pins**: request id reaches the wire and equals the request's; v is 0/1 for
   1559 and the byte layout is `r‖s‖v` (a 1559 signature must not be 27-offset);
   `reply_type("eth-sign-request") == "eth-signature"`.

Deliberately **not** in E-1: legacy (EIP-155) dispatch, EIP-712
containerization, and the software/hardware acceptance gate (E-2).

## E-1b: personal_sign (EIP-191) is wired

`data_type` 3 signs now. What it took, and what it pins:

1. **Zero-alloc digest.** `personal_signing_hash` used `alloc::format!` plus a
   concatenated `Vec`, which cannot sit on the device sign path (the no-alloc probes
   exist for exactly this). `personal_signing_hash_bytes` renders
   `\x19Ethereum Signed Message:\n<len>` into a fixed stack buffer (the length is
   formatted by hand; the bound is `head + 20` digits) and absorbs head and message
   into one `KeccakSink` — no allocation for a message of any length.
   `personal_sign_bytes(&[u8], &SecretBytes<32>)` signs a **borrowed** message;
   `PersonalSignInput` / `personal_sign` stay as the allocating convenience and are
   now `cfg(alloc-fallback, test)`.
2. **The module is no longer cfg-gated out of device builds.** `eth::personal_sign`
   was `cfg(alloc-fallback, test)`, so the production path could not name it. The
   gate moved inside the module (owning API only), which is what keeps the sign path
   compiling on the bare-metal faces.
3. **`v` = 27/28**, the EIP-191 convention an `ecrecover` consumer expects — the
   opposite of the 1559 yParity rule. The container codec stays opaque to `v`; the
   scheme owns it (`sign_eth`).
4. **Review shows the message.** The pre-wiring screen said "cannot display on this
   screen", which was honest only while the scheme was refused. Signing a message the
   operator cannot read is a blind signature, so the review renders the bytes:
   printable ASCII kept, every other byte as `.` (a raw newline or escape sequence
   would display as something other than what is signed), wrapped, capped at six
   lines with an explicit `..truncated`, and the true byte length always printed.
5. **External anchor, byte-exact**: `eth_personal_sign_matches_keystone_signature_vector`
   reproduces keystone's published 65 bytes (`b836ae2b…810e1b`) both directly and
   through the UR exit, and the exit pin (`sign_eth_personal_message_signs_with_27_28_v`)
   compares against an independent `personal_sign_bytes` call and asserts the 27/28
   domain.

EIP-712 (`data_type` 2) stays refused with `ChainKindUnsupported` and its review
screen still says it cannot be displayed — that scheme is not signed, so the honest
label is still honest.

## E-2 anchors: external signature oracles (no hardware needed)

`~/codebases/keystone3-firmware` (tag 3.2.2) carries three fixtures signed by the
**same test key** every keystone ETH test uses — seed
`5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4`,
path `m/44'/60'/0'/0/0`, address `0x9858EfFD232B4033E47d90003D41EC34EcaEda94`:

| anchor | source | what it pins |
|---|---|---|
| `personal_sign` 65-byte signature `b836ae2b…810e1b` | `rust/apps/ethereum/src/lib.rs::test_sign_personal_message` | EIP-191 digest + **v = 27** + our RFC6979/low-s output matching keystone byte-for-byte |
| EIP-712 typed-data 65-byte signature `042fd021…87531b` | `lib.rs::test_sign_typed_data` | 712 digest + **v = 27** |

Why the byte-equality is legitimate rather than a coincidence: both sides sign the
same sighash with the same key using deterministic ECDSA (RFC 6979) and both
normalize to low-s, so `r`/`s` are unique; `yParity` then follows from the key and
the sighash. Any drift in our digest, key derivation, low-s handling or v semantics
shows up as a mismatch.

**Correction (2026-11-24, same day):** an earlier version of this section claimed a
third anchor — "a real signed EIP-1559 tx in `lib.rs::test_parse_tx`". That is
wrong. That fixture is the **unsigned** 9-field payload (chain_id … access_list, no
`0x02` byte, no signature), and the test's `from` address comes from the **pubkey
passed in**, not from recovery. There is no signed-1559 fixture anywhere in the
keystone tree (only internal legacy encode/decode round-trips). So the EIP-1559
signature itself has **no external byte anchor** in the reference implementation;
its oracles are instead:

1. **a real mainnet EIP-1559 transaction** (published signed bytes + published
   sender): re-derive its sighash with our code, recover the signer from
   `(r‖s‖yParity)`, and the recovered address must equal the sender. This pins our
   digest and `v` semantics against consensus **without needing anyone's private
   key**, and it is the strongest check available for this path;
2. an independent implementation (ethers/web3, addable to the dev-only
   `tools/sdk-gate` package) re-signing the same tx with the same key — deterministic
   ECDSA makes `r`/`s` comparable byte-for-byte;
3. the EIP-1559 spec's own preimage vector, which we already pin
   (`tests/eth_keystone_cross_validation.rs::eth_eip1559_signing_preimage_structure`).

## Wire-shape finding: `data_type` selects the scheme, and our fixtures lied

`rust_c/src/ethereum/mod.rs::eth_sign_tx_dynamic` (the production path) dispatches
on **`data_type` first**, then on the first payload byte:

| `data_type` | meaning | payload shape | keystone behaviour |
|---|---|---|---|
| 1 | `Transaction` → **legacy** | bare RLP list, **no type byte** | `sign_legacy_tx` (6-field unprotected or 9-field EIP-155) |
| 4 | `TypedTransaction` | **`0x02`-prefixed** | first byte `0x02` → 1559; any other first byte → `UnsupportedTransaction` |
| 3 | `PersonalMessage` | raw message bytes | EIP-191, v = 27/28 |
| 2 | `TypedData` | EIP-712 JSON | 712, v = 27/28 |

Our code accepts `data_type` 1 **and** 4 and routes both into
`from_rlp::parse_eip1559_raw`, which requires the `0x02` prefix. Two consequences:

1. A real **1559** request (`data_type` 4) signs correctly.
2. A real **legacy** request (`data_type` 1, bare RLP) is rejected as
   `EncodingInvalidFormat` — fail-closed, and the reason pool item #68 ("legacy 接
   dispatch") is not merely wiring: the `data_type` → scheme mapping itself has to
   become explicit.
3. Every ETH fixture in this repo pairs `data_type` **1** with a `0x02`-prefixed
   payload — a combination no wallet emits. The fixtures must move to
   `data_type` 4 for 1559 before they count as acceptance evidence, and the dispatch
   should mirror keystone: `data_type` 1 → legacy path (rejected until implemented),
   4 → first-byte dispatch.

**Status (2026-11-25 — the analysis above is the finding, not the current code).**
The dispatch now mirrors keystone (`768896d`): `data_type` 1 → `FeatureNotImplemented`
(the refusal code, not a parse failure), 4 → first-byte dispatch with `0x01`/`0x03`/
`0x04` refused as `FeatureNotImplemented` and an unknown first byte as
`EncodingInvalidFormat`, 3 → EIP-191 personal_sign, 2 → refused pending E-3. A bare-RLP
legacy request therefore gets a *stable code* today; actually **signing** legacy
(and the two audit defects that become reachable the moment it does — F-8's
`chain_id*2+35+parity` overflow and F-7-legacy's `u128`→`u64` silent truncation) is
pool item #68 / batch E-1.

That gives E-2 a **hardware-free, machine-judged acceptance gate** for the signature
bytes. A real wallet (keystone 3 Pro / imToken / Rabby) still adds flow-level
evidence — that it accepts the `ur:eth-signature` frames and shows the right
review — but it is no longer the only way to prove the signature is correct.

## E-6: batch signing (40404 / 40405) is refused by policy

`eth-batch-sign-request` is UR type **40404**, `eth-batch-signature` is **40405**
(`ur-registry` 1.0.8/1.0.9 `RegistryType`; a keystone private extension with no public
spec). The payload adds nothing wire-wise — it is a packed list,
`{1: [tagged(401) eth-sign-request, …]}` — so the whole question is *admission policy*,
not parsing.

**Decision (2026-11-25): not supported, and said out loud.** The device used to fall
through to `unknown code`, which reads like a damaged QR and invites a pointless retry.
Now the classification table answers `unsupported` for the `eth-batch` prefix and the
product flow shows three fixed phrases — `no batch signing` / `not supported` /
`scan another` — while scanning keeps running. The payload is never parsed: the refusal
happens at the type, not at the transaction, so a malformed batch and a well-formed one
are refused identically.

Why not the "minimal subset": keystone's admission rule
(`apps/ethereum/src/batch_tx_rules.rs::rule_swap`, 42 lines) accepts 1–3 legs where the
first N−1 are ERC-20 `approve`-shaped and **the last leg is never inspected**. The link
between the approved spender and the contract actually executed lives entirely in their
built-in ABI/address allow-list (875 entries / 92 addresses). Copying the rule copies
that review hole; doing it right means maintaining an approve↔execution-contract
allow-list this project does not have (E-2 stops at the selector). There is also no
third-party sender to validate against — MetaMask and Rabby emit single
`eth-sign-request` legs.

Pins live in `tests/ur_type_table.rs`: both 40404 and 40405 through the same prefix,
upper-cased UR shapes, `unsupported ⇒ !is_sign`, the phrase staying inside the closed
screen vocabulary, and `eth-sign-request` not being swallowed by the `eth-batch` row.
The generator can emit the real thing — `node tools/ur-inject/gen.mjs --kind batch`
builds `{1: [tagged(401), tagged(401)]}` from two *valid, signable* 1559 transfers, so
a future regression that starts signing one leg shows up as a signature rather than as
a parse error.


