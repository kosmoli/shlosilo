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
| 2 | bytes(65) | `r ‖ s ‖ v` — r 32 B, s 32 B, v 1 B |
| 3 | text (optional) | `origin`, echoed from the request (key 7) |

`v` is **opaque** to this container: 1 byte, no 27 offset added, no range check.
Chain semantics belong to the signer and are pinned there (E-1):

| path | v |
|---|---|
| EIP-1559 (`0x02`) | `0` / `1` (yParity) |
| legacy unprotected (6-item) | `27` / `28` |
| legacy EIP-155 (9-item) | `chain_id*2 + 8 + {0,1}` ⇒ `37` / `38` on chain 1 |
| EIP-191 `personal_sign` / EIP-712 | `27` / `28` |

Sizes: 99 B for an 8-char origin. Worst case with the origin cap below is 156 B;
`ETH_SIGNATURE_CBOR_MAX_LEN = 160` leaves margin.

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
pub const ETH_SIGNATURE_CBOR_MAX_LEN: usize = 160;
// The origin cap is shared with the inbound `eth-sign-request` key 7, so it
// lives in `forms/types/caps.rs` — neither layer-E codec imports its sibling.
// pub const ETH_UR_ORIGIN_MAX_LEN: usize = 64;

pub struct EthSignature<'a> {
    pub request_id: [u8; 16],
    pub signature: [u8; 65],
    pub origin: Option<&'a str>,
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

## Strictness rules (each gets a pin)

Encode:
- missing required field cannot happen by construction; `origin` over
  `ETH_UR_ORIGIN_MAX_LEN` is an error, not a truncation;
- buffer under-capacity returns `BufferTooSmall` with the required length in the
  error context — never a partial write reported as success.

Parse (fail closed, no silent defaulting):
- non-map payload → `EncodingInvalidFormat`;
- key 1 absent or not `tag(37)` over exactly 16 bytes → error (uuid tag is
  whitelisted, not "any tag");
- key 2 absent or not exactly 65 bytes → error (a 64-byte `r‖s` must not be
  accepted and short-filled);
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

Deliberately **not** in E-1: legacy (EIP-155) dispatch, `personal_sign` wiring
(today `EthSignDataType::PersonalMessage` returns `ChainKindUnsupported` and
`forms/chain/eth/personal_sign.rs` has no production caller), EIP-712
containerization, and the software/hardware acceptance gate (E-2).

