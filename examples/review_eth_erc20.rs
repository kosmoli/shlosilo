#![cfg(feature = "alloc-fallback")]
//! This harness builds EIP-1559 fixtures with the alloc-gated RLP encoder, so it exists
//! only on the host face; the no-alloc (device) face skips it.
//! NOTE: this harness builds EIP-1559 fixtures with the alloc-gated RLP encoder, so it
//! Render the ETH confirmation page for an ERC-20 payment, exactly as the review layer
//! produces it — used to eyeball the ETH-10 fix (the page used to say only
//! `call erc20 transfer`).
//!
//! Run: `cargo run --example review_eth_erc20 --features alloc-fallback`
//!
//! The rows printed here are the `out_lines` the platform layer receives from
//! `shlosilo_review_ffi` and draws verbatim; the only thing this binary adds is the
//! 48-column frame the device has.

use shlosilo::business::review;

fn hex20(h: &str) -> [u8; 20] {
    let mut out = [0u8; 20];
    for i in 0..20 {
        out[i] = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).expect("hex");
    }
    out
}

/// ERC-20 `transfer(address,uint256)` call data.
fn transfer_calldata(to: [u8; 20], amount: [u8; 32]) -> Vec<u8> {
    let mut d = Vec::with_capacity(68);
    d.extend_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]); // selector
    d.extend_from_slice(&[0u8; 12]); // address padding
    d.extend_from_slice(&to);
    d.extend_from_slice(&amount);
    d
}

/// ERC-20 `approve(address,uint256)` call data.
fn approve_calldata(spender: [u8; 20], amount: [u8; 32]) -> Vec<u8> {
    let mut d = Vec::with_capacity(68);
    d.extend_from_slice(&[0x09, 0x5e, 0xa7, 0xb3]);
    d.extend_from_slice(&[0u8; 12]);
    d.extend_from_slice(&spender);
    d.extend_from_slice(&amount);
    d
}

/// EIP-1559 raw transaction with the given `to` and call data.
fn eip1559_raw(to: [u8; 20], value: u128, data: &[u8]) -> Vec<u8> {
    use shlosilo::chain::eth::rlp::{encode_bytes, encode_list, encode_uint};
    let fields = vec![
        encode_uint(1),             // chain id
        encode_uint(0),             // nonce
        encode_uint(1_000_000_000), // max priority fee
        encode_uint(2_000_000_000), // max fee
        encode_uint(100_000),       // gas limit
        encode_bytes(&to),          // to = the token contract
        encode_uint(value),         // native value (0 for an ERC-20 payment)
        encode_bytes(data),         // calldata
        encode_list(&[]),           // access list
        // The request carries the SIGNED shape: parse_eip1559_raw wants 12 fields and only
        // structurally validates y_parity/r/s (the device is asked to produce them).
        encode_uint(0),
        encode_uint(0),
        encode_uint(0),
    ];
    let mut raw = vec![0x02u8];
    raw.extend_from_slice(&encode_list(&fields));
    raw
}

/// eth-sign-request CBOR: {2: sign_data, 3: data_type=4 (TypedTransaction)}.
fn eth_sign_request(sign_data: &[u8]) -> Vec<u8> {
    let mut out = vec![0xa2u8, 0x02];
    assert!(
        sign_data.len() < 256,
        "fixture is small; keep the 1-byte length form"
    );
    out.push(0x58); // byte string, 1-byte length
    out.push(sign_data.len() as u8);
    out.extend_from_slice(sign_data);
    out.extend_from_slice(&[0x03, 0x04]); // data_type = TypedTransaction
    out
}

fn show(title: &str, payload: &[u8]) {
    println!("\n=== {title} ===");
    match review::build_eth(payload) {
        Ok(view) => {
            let lines: Vec<&str> = view.lines().iter().map(|l| l.as_str()).collect();
            println!("rows={} flags=0x{:04x}", lines.len(), view.flags);
            // 48-column frame: what the device actually draws.
            println!("+{}+", "-".repeat(48));
            for l in &lines {
                println!("|{:<48}|", l);
            }
            println!("+{}+", "-".repeat(48));
        }
        Err(e) => println!("build_eth error: {:?}", e.kind),
    }
}

fn main() {
    // A token contract, a recipient, and a spender.
    let token = hex20("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"); // USDC contract
    let recipient = hex20("1111111111111111111111111111111111111111");
    let spender = hex20("2222222222222222222222222222222222222222");

    let mut one_usdc = [0u8; 32];
    one_usdc[31] = 1; // raw integer 1 (token decimals are NOT guessed)
    let unlimited = [0xffu8; 32];

    show(
        "ERC-20 transfer (1 raw unit)",
        &eth_sign_request(&eip1559_raw(
            token,
            0,
            &transfer_calldata(recipient, one_usdc),
        )),
    );
    show(
        "ERC-20 transfer to a DIFFERENT recipient",
        &eth_sign_request(&eip1559_raw(
            token,
            0,
            &transfer_calldata(spender, one_usdc),
        )),
    );
    show(
        "ERC-20 approve (unlimited)",
        &eth_sign_request(&eip1559_raw(
            token,
            0,
            &approve_calldata(spender, unlimited),
        )),
    );
    show(
        "plain ETH transfer (no calldata)",
        &eth_sign_request(&eip1559_raw(recipient, 1_000_000_000_000_000, &[])),
    );
}
