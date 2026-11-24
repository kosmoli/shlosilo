//! Real mainnet EIP-1559 transactions as an external oracle for our sighash and
//! `v` semantics.
//!
//! No reference-implementation fixture pins the EIP-1559 **signature** — keystone's
//! `test_parse_tx` payload is unsigned, and its `from` comes from the pubkey passed
//! in, not from recovery (see `docs/eth-signature-codec.md`, "E-2 anchors"). So the
//! oracle here is consensus itself: take a transaction that mainnet accepted,
//! recompute its signing hash with **our** implementation, recover the signer from
//! its published `(r, s, yParity)` with **our** recovery path, and require the
//! recovered address to equal the published `from`. A wrong digest, a wrong yParity
//! convention or a wrong field order in the preimage all break that equality, and no
//! private key is needed.
//!
//! Provenance: `tests/fixtures/eth_mainnet_1559_raw.json` (fetched from
//! `ethereum-rpc.publicnode.com`, `eth_getTransactionByHash` /
//! `eth_getRawTransactionByHash`; the JSON also carries each transaction's raw
//! signed bytes, and the field values below were checked against those bytes with an
//! independent RLP decoder). Block numbers are recorded per vector.
//!
//! What this does **not** cover: that our signature is accepted by a wallet, and the
//! `ur:eth-signature` container shape — those are pinned in
//! `forms/ur/codec/eth_signature.rs` and the business-layer pins.
#![cfg(feature = "alloc-fallback")]

extern crate alloc;

use shlosilo::address::eth as eth_address;
use shlosilo::chain::eth::{eip1559, sign as eth_sign};
use shlosilo::encoding::keccak256;

/// One published mainnet transaction, split into the unsigned fields plus its
/// signature. `access_list` is empty for both vectors, which matches the wire model
/// (`Eip1559Transaction` carries no access-list field because the wire always writes
/// an empty list).
struct Vector {
    name: &'static str,
    tx_hash: &'static str,
    block: u64,
    chain_id: u64,
    nonce: u64,
    max_priority_fee_per_gas: u128,
    max_fee_per_gas: u128,
    gas_limit: u64,
    to_hex: &'static str,
    amount: u128,
    data_hex: &'static str,
    y_parity: u8,
    r_hex: &'static str,
    s_hex: &'static str,
    from_hex: &'static str,
}

/// `0xf8c78e68c15e4311edd542b20eda40cb4f290f7dfa459d02a210ebab53cd1846` (block 26482969), calldata transfer.
const TX_A: Vector = Vector {
    name: "TX_A",
    tx_hash: "0xf8c78e68c15e4311edd542b20eda40cb4f290f7dfa459d02a210ebab53cd1846",
    block: 26482969,
    chain_id: 1,
    nonce: 226434,
    max_priority_fee_per_gas: 0,
    max_fee_per_gas: 147264626,
    gas_limit: 473170,
    to_hex: "0000000aa232009084bd71a5797d089aa4edfad4",
    amount: 0,
    data_hex: "09c5eabe0000000000000000000000000000000000000000000000000000000000000020\
        00000000000000000000000000000000000000000000000000000000000002a90000cca0\
        b86991c6218b36c1d19d4a2e9eb0ce3606eb480000000000000000000000000000000000\
        00000000000000000000000000038c00000000000000000000000000a7ef11c02aaa39b2\
        23fe8d0a0e5c4f27ead9083c756cc200000000000000000000000010e853010000000000\
        0000000016ec54d983ae0600000000000000000000000000000000dac17f958d2ee523a2\
        206206994597c13d831ec700000000000000000000000000000000000000000000000000\
        0000000000000000000000000000000000000000000ddf00004c00000001000000000000\
        0000000000000000000000000070debe3d370a7b5a352db4fc8327110001000200010000\
        0000000000000000000000000000000000000000000017b4803690e62468000066030000\
        00000000000000000000000000a7eb850000000000000000000000000000038c00000000\
        000000000007a607ed97a45602000100000000000000000000000000000ddf0000000000\
        000000000000001220047800000000000000000000006221793fe200011c0e0000000000\
        0000000000000000a7ef1100000000000000000016ea70acd02b30000000000000000000\
        000000000f4a8800000000000000000000000000000000000073d53553ee552c1f2a9722\
        e6407d43e41e19593f1c35984a24574fd8c1e3d8956ba260e87d3ec92972c1c5bbe5c576\
        eb3093a79c284e6de9abd551a4388b5184357d69836ff9e0386bc7d78f7e8b638eb4c28b\
        fa560900000000000000000000000000000ddf0000000000000000000001e40e0e760000\
        000000000000000000000004efb3f800000000000000000000000004634aa300011b4b7e\
        6f5e77470346cce8c381b0103d2706dfc0cb419a31310ae393366bc5a0b475e2e282c053\
        89030800286f8278d8f64b82f5a2a99c9e6c00f9b27e3acd82ea00000000000000000000\
        00000000000000000000000000000000",
    y_parity: 1,
    r_hex: "e7d9dc31eabc6995eb75c3f0901c2167f325a44c48308e3baf46b33c48b211c7",
    s_hex: "0ece60f06d18d89e2b1f2f49dad28d24bcff77f6b8af6464fa9081ff9e519b55",
    from_hex: "5875db54cd9ae2b2a875e09bb731772297ae9d92",
};

/// `0xaf1a2574224d75820419a310ac6dbbab87734614d8eb38c515decb7d684b48ae` (block 26482969), plain transfer.
const TX_B: Vector = Vector {
    name: "TX_B",
    tx_hash: "0xaf1a2574224d75820419a310ac6dbbab87734614d8eb38c515decb7d684b48ae",
    block: 26482969,
    chain_id: 1,
    nonce: 197195,
    max_priority_fee_per_gas: 2500000000,
    max_fee_per_gas: 2604816581,
    gas_limit: 21000,
    to_hex: "4e2401e90e88a7d3df382c04e9cdc634fb00ec82",
    amount: 259317029429688,
    data_hex: "",
    y_parity: 0,
    r_hex: "21e602f8c5f9a7b93e92f9bd179827b0de160bb88cd90eb7f9150dfd3943b8af",
    s_hex: "3b1cccca2f5f784ab5cf1c982b315d256cc13091cefd45c9395e9301f607e41b",
    from_hex: "0668c9bf6a6936b9eb5a19f61c663070beff2f9b",
};

/// The device-signed acceptance transaction (2026-11-24, forgebox `2c16949`).
///
/// Kosmo signed this on the hardware wallet through MetaMask and it landed on
/// mainnet in block 26485426 (status success). Keeping it here means the exact
/// bytes this device produced are re-verified by our own digest and recovery on
/// every gate run — a regression in the EIP-1559 preimage or in `yParity` would
/// make this vector stop recovering to its published sender.
const TX_C: Vector = Vector {
    name: "TX_C",
    tx_hash: "0x3ba8e61d6df1f84f8ddb2b1ddf8df8b001e92d572e436c5c1462824a08df00d8",
    block: 26485426,
    chain_id: 1,
    nonce: 0,
    max_priority_fee_per_gas: 2_000_000_000,
    max_fee_per_gas: 2_289_017_607,
    gas_limit: 31_500,
    to_hex: "d00387de9f68c9642e25d4c194d6e1ce233633c0",
    amount: 227_895_945_379_500,
    data_hex: "",
    y_parity: 1,
    r_hex: "5fc723a08410302360e1090a113825f4f253e49be608c84498b4eccc93228b01",
    s_hex: "63a675a74e396bc2647fcff42dcdfc9523c8c98aa564cd6a93f2cab10aaadc7c",
    from_hex: "0988a7fe9d0eb483b89040e238a1d0afe5a7a736",
};

/// The device-signed **ERC-20** acceptance transaction (2026-11-24, forgebox
/// `2f758e0`): a 1.0 USDC `transfer` through MetaMask, landed on mainnet in block
/// 26485853 (status success). Same EIP-1559 path as `TX_C` with 68 bytes of
/// calldata, so it also pins that the digest covers `data` — a preimage that dropped
/// or mis-ordered the calldata field would stop recovering to the sender.
const TX_D: Vector = Vector {
    name: "TX_D",
    tx_hash: "0x4b267146d3f7600b369cd124a3a84a86f0672c5ca75be1e25c37208ccb98c9a2",
    block: 26485853,
    chain_id: 1,
    nonce: 1,
    max_priority_fee_per_gas: 100_000,
    max_fee_per_gas: 921_746_503,
    gas_limit: 94_548,
    to_hex: "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
    amount: 0,
    data_hex: "a9059cbb000000000000000000000000d00387de9f68c9642e25d4c194d6e1ce233633c000000000000000000000000000000000000000000000000000000000000f4240",
    y_parity: 0,
    r_hex: "cab6e06f67052858832ae302eb1bad38371ff52f1bf8eb9337ba0983f7648958",
    s_hex: "76bfe4b6738bc070c6a60501f866e064bd705950821ca5eb86893cc6a62425a0",
    from_hex: "0988a7fe9d0eb483b89040e238a1d0afe5a7a736",
};

/// Provenance label for assertion messages: every failure names the transaction it
/// came from, so a red run points at the source of the vector rather than at "TX_A".
fn label(v: &Vector) -> alloc::string::String {
    alloc::format!("{} {} (mainnet block {})", v.name, v.tx_hash, v.block)
}

fn hex_decode(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex in fixture");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("fixture hex"))
        .collect()
}

fn fixed<const N: usize>(s: &str) -> [u8; N] {
    let v = hex_decode(s);
    assert_eq!(v.len(), N, "fixture hex length");
    let mut out = [0u8; N];
    out.copy_from_slice(&v);
    out
}

/// The transaction as our model sees it — the unsigned fields only.
fn as_transaction(v: &Vector) -> eip1559::Eip1559Transaction<'static> {
    eip1559::Eip1559Transaction {
        chain_id: v.chain_id,
        nonce: v.nonce,
        max_priority_fee_per_gas: v.max_priority_fee_per_gas,
        max_fee_per_gas: v.max_fee_per_gas,
        gas_limit: v.gas_limit,
        destination: Some(fixed::<20>(v.to_hex)),
        amount: v.amount,
        data: hex_decode(v.data_hex).into(),
    }
}

/// Recover the sender from `(r, s, yParity)` over **our** signing hash.
fn recover_sender(v: &Vector, y_parity: u8) -> [u8; 20] {
    let tx = as_transaction(v);
    let sighash = eip1559::signing_hash(&tx).expect("signing hash");
    // `ecdsa_recover` takes the EIP-191/legacy convention (v = 27 + yParity); the
    // 1559 wire byte is the bare yParity, so the offset is applied here only for
    // the recovery call.
    let mut sig65 = [0u8; 65];
    sig65[..32].copy_from_slice(&fixed::<32>(v.r_hex));
    sig65[32..64].copy_from_slice(&fixed::<32>(v.s_hex));
    sig65[64] = 27 + y_parity;
    let pubkey = eth_sign::ecdsa_recover(&sighash, &sig65).expect("recover");
    let h = keccak256::hash(&pubkey).expect("keccak");
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&h[12..]);
    addr
}

fn assert_recovers_to_published_sender(v: &Vector) {
    let expected: [u8; 20] = fixed::<20>(v.from_hex);
    let got = recover_sender(v, v.y_parity);
    assert_eq!(
        got,
        expected,
        "{}: recovering over our sighash must yield the published sender",
        label(v)
    );
    // The same address in the product's EIP-55 rendering, so a drift in the encoder
    // also shows up here rather than only in the address pins.
    let rendered = eth_address::encode_bytes(&expected).expect("EIP-55 encode");
    let want = alloc::format!("0x{}", v.from_hex);
    assert_eq!(
        rendered.as_ref().to_ascii_lowercase(),
        want,
        "{}: EIP-55 rendering must be the published sender",
        label(v)
    );
}

/// Mainnet accepted these signatures, so recovering over our sighash must land on
/// the published sender. This is the EIP-1559 digest + yParity pin.
#[test]
fn mainnet_1559_signature_recovers_to_the_published_sender() {
    assert_recovers_to_published_sender(&TX_A);
    assert_recovers_to_published_sender(&TX_B);
    assert_recovers_to_published_sender(&TX_C);
    assert_recovers_to_published_sender(&TX_D);
}

/// Poison pill: the recovery above must be discriminating, not accidentally true.
/// Flipping the yParity byte has to change the recovered address — if it does not,
/// the pin is blind to our `v` convention (the exact thing it exists to guard).
#[test]
fn flipping_y_parity_changes_the_recovered_address() {
    for v in [&TX_A, &TX_B, &TX_C, &TX_D] {
        let expected: [u8; 20] = fixed::<20>(v.from_hex);
        let flipped = recover_sender(v, v.y_parity ^ 1);
        assert_ne!(
            flipped,
            expected,
            "{}: flipping yParity must NOT recover the same sender",
            label(v)
        );
    }
}

/// Both vectors differ in yParity (one 0, one 1), so the pin covers both recovery
/// ids rather than only the common one.
#[test]
fn the_vectors_cover_both_y_parity_values() {
    let parities = [TX_A.y_parity, TX_B.y_parity];
    assert!(
        parities.contains(&0) && parities.contains(&1),
        "fixtures must cover yParity 0 and 1, got {parities:?}"
    );
}

/// EIP-2 low-s: every transaction mainnet accepts has `s <= n/2`. Pinning it here
/// documents why our signer normalizes to low-s, and it would catch a fixture that
/// silently stopped being a real mainnet transaction.
#[test]
fn mainnet_signatures_are_low_s() {
    // secp256k1 group order n
    const N: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x41,
    ];
    fn cmp_be(a: &[u8; 32], b: &[u8; 32]) -> core::cmp::Ordering {
        for i in 0..32 {
            match a[i].cmp(&b[i]) {
                core::cmp::Ordering::Equal => continue,
                other => return other,
            }
        }
        core::cmp::Ordering::Equal
    }
    // n/2 (floor) = n >> 1, computed byte-wise
    let mut half = [0u8; 32];
    let mut carry = 0u16;
    for i in (0..32).rev() {
        let word = (u16::from(N[i]) >> 1) | (carry << 7);
        half[i] = (word & 0xff) as u8;
        carry = u16::from(N[i] & 1);
    }

    for v in [&TX_A, &TX_B, &TX_C, &TX_D] {
        let s = fixed::<32>(v.s_hex);
        assert_eq!(
            cmp_be(&s, &half),
            core::cmp::Ordering::Less,
            "{}: mainnet only accepts low-s",
            label(v)
        );
    }
}

/// The review screen's address casing must be the EIP-55 checksum of the bytes on
/// the wire — not `toLowerCase()`, not an arbitrary choice. Pinned against the exact
/// string the device displayed for the acceptance transaction (photo, 2026-11-24).
#[test]
fn the_acceptance_screen_address_is_the_eip55_rendering() {
    let rendered = eth_address::encode_bytes(&fixed::<20>(TX_C.to_hex)).expect("EIP-55 encode");
    assert_eq!(
        rendered.as_ref(),
        "0xd00387de9f68C9642e25d4c194d6e1cE233633C0",
        "the screen showed this exact casing; the encoder must produce it"
    );
}
