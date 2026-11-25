#!/usr/bin/env node
// Synthetic `eth-sign-request` injector — the test channel for request shapes no
// wallet will produce for us.
//
// The device only ever sees QR frames, so any request we can encode is a request we
// can test: build the CBOR ourselves, wrap it as a UR, and put the frames on a
// computer screen for the device camera. That covers the negative matrix (EIP-2930 /
// 4844 / 7702 / legacy / pre-signed / bad chain id) and the wallet-independent
// positive one (personal_sign) without a wallet, without gas, and repeatably.
//
// Usage:
//   node tools/ur-inject/gen.mjs --kind <kind> [--out file.html] [--frag 200]
//   node tools/ur-inject/gen.mjs --list
//
// Kinds (device behaviour is what the firmware pins say; the page prints it too):
//   1559      data_type 4, 0x02 || rlp(9)   → review + sign (a valid transfer)
//   personal  data_type 3, raw message      → review shows the text, signs, v=27/28
//   712       data_type 2, JSON blob        → refused (no fixed-size container yet)
//   legacy    data_type 1, bare RLP         → refused (FeatureNotImplemented)
//   2930      data_type 4, 0x01 || rlp      → refused (FeatureNotImplemented)
//   4844      data_type 4, 0x03 || rlp      → refused (FeatureNotImplemented)
//   7702      data_type 4, 0x04 || rlp      → refused (FeatureNotImplemented)
//   unknown   data_type 4, 0x99 || rlp      → refused (EncodingInvalidFormat)
//   presigned data_type 4, 0x02 || rlp(12)  → refused (carries a signature)
//   badchain  data_type 4, 1559 on chain 5 vs tx chain 1 → refused (network)
//   batch     ur:eth-batch-sign-request (40404), {1: [tagged 1559, tagged 1559]}
//                                           → refused: fixed "no batch signing"
//
// Only `batch` is not an `eth-sign-request`: it is the keystone batch extension
// this device deliberately does not implement, and the point of injecting it is
// that the screen must say so ("no batch signing") rather than "unknown code".
//
// The frames are rendered by the same bc-ur implementation the wallets use
// (`@ngraveio/bc-ur`, already present under tools/sdk-gate/node_modules), so the
// device decodes what a real peer would have sent.

import fs from 'node:fs'
import path from 'node:path'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const { UR, UREncoder } = require('@ngraveio/bc-ur')
const QRCode = require('qrcode')

// ── minimal canonical RLP ────────────────────────────────────────────────────
const encBytes = (b) => {
  if (b.length === 0) return Buffer.from([0x80])
  if (b.length === 1 && b[0] < 0x80) return Buffer.from([b[0]])
  if (b.length < 56) return Buffer.concat([Buffer.from([0x80 + b.length]), b])
  const len = beBytes(b.length)
  return Buffer.concat([Buffer.from([0xb7 + len.length]), len, b])
}
const encUint = (v) => {
  if (v === 0n || v === 0) return Buffer.from([0x80])
  return encBytes(beBytes(v))
}
const beBytes = (v) => {
  let n = BigInt(v)
  const out = []
  while (n > 0n) {
    out.unshift(Number(n & 0xffn))
    n >>= 8n
  }
  return Buffer.from(out.length ? out : [0])
}
const encList = (items) => {
  const body = Buffer.concat(items)
  if (body.length < 56) return Buffer.concat([Buffer.from([0xc0 + body.length]), body])
  const len = beBytes(body.length)
  return Buffer.concat([Buffer.from([0xf7 + len.length]), len, body])
}

// ── CBOR for the eth-sign-request map ────────────────────────────────────────
const cborUint = (n) => {
  if (n < 24) return Buffer.from([n])
  if (n <= 0xff) return Buffer.from([0x18, n])
  throw new Error('cborUint: only small keys/values needed here')
}
const cborBytes = (b) => {
  if (b.length < 24) return Buffer.concat([Buffer.from([0x40 + b.length]), b])
  if (b.length <= 0xff) return Buffer.concat([Buffer.from([0x58, b.length]), b])
  return Buffer.concat([Buffer.from([0x59, b.length >> 8, b.length & 0xff]), b])
}
const cborText = (s) => {
  const b = Buffer.from(s, 'utf8')
  if (b.length < 24) return Buffer.concat([Buffer.from([0x60 + b.length]), b])
  if (b.length <= 0xff) return Buffer.concat([Buffer.from([0x78, b.length]), b])
  return Buffer.concat([Buffer.from([0x79, b.length >> 8, b.length & 0xff]), b])
}
const cborTag = (tag, inner) => {
  if (tag < 24) return Buffer.concat([Buffer.from([0xc0 + tag]), inner])
  if (tag <= 0xff) return Buffer.concat([Buffer.from([0xd8, tag]), inner])
  return Buffer.concat([Buffer.from([0xd9, tag >> 8, tag & 0xff]), inner])
}
const cborMap = (pairs) => {
  const n = pairs.length
  if (n >= 24) throw new Error('cborMap: small maps only')
  return Buffer.concat([Buffer.from([0xa0 + n]), ...pairs.flat()])
}

/** m/44'/60'/0'/0/0 as a BCR-2020-006 crypto-keypath (tag 304). */
const keypath = () => {
  const components = [[44, true], [60, true], [0, true], [0, false], [0, false]]
  const flat = []
  for (const [idx, hardened] of components) {
    flat.push(cborUint(idx), hardened ? Buffer.from([0xf5]) : Buffer.from([0xf4]))
  }
  const inner = cborMap([
    [cborUint(1), Buffer.concat([Buffer.from([0x80 + flat.length]), ...flat])],
    [cborUint(2), cborUint(5)],
  ])
  return cborTag(304, inner)
}

const UUID = Buffer.from('9b1deb4d3b7d4bad9bdd2b0d7b3dcb6d', 'hex')


/** The 1559 field list for `approve(spender, amount)` against USDC. */
const approveTx = (amount) => {
  const selector = Buffer.from('095ea7b3', 'hex')
  const spender = Buffer.concat([Buffer.alloc(12), Buffer.from('d00387de9f68c9642e25d4c194d6e1ce233633c0', 'hex')])
  const amountWord = Buffer.from(amount.toString(16).padStart(64, '0'), 'hex')
  const data = Buffer.concat([selector, spender, amountWord])
  return encList([
    encUint(1),                  // chain_id
    encUint(8),                  // nonce
    encUint(1_500_000_000),      // max_priority_fee_per_gas
    encUint(30_000_000_000),     // max_fee_per_gas
    encUint(60_000),             // gas_limit (approve costs ~46k)
    encBytes(Buffer.from('a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48', 'hex')), // USDC
    encUint(0),                  // value
    encBytes(data),              // calldata
    encList([]),                 // access_list
  ])
}

/** A plain 1559 transfer as the signing preimage: 0x02 || rlp([9 fields]). */
const transfer1559 = () => {
  const fields = [
    encUint(1),                  // chain_id
    encUint(7),                  // nonce
    encUint(1_500_000_000),      // max_priority_fee_per_gas
    encUint(30_000_000_000),     // max_fee_per_gas
    encUint(21_000),             // gas_limit
    encBytes(Buffer.alloc(20, 0x11)), // to
    encUint(10_000_000_000_000_000),  // value (0.01 ETH)
    encBytes(Buffer.alloc(0)),   // data
    encList([]),                 // access_list
  ]
  return encList(fields)
}

/**
 * One `eth-sign-request` as a batch carries it: CBOR tag 401 (`ETH_SIGN_REQUEST`)
 * around the usual map, wrapping a valid 1559 transfer. `n` only varies the
 * requestId, so the legs are two distinct requests rather than a copy.
 */
const ethSignRequest = (n) => {
  const id = Buffer.from(UUID)
  id[id.length - 1] = n
  return cborTag(
    401,
    cborMap([
      [cborUint(1), cborTag(37, cborBytes(id))],
      [cborUint(2), cborBytes(Buffer.concat([Buffer.from([0x02]), transfer1559()]))],
      [cborUint(3), cborUint(4)], // data_type 4 = EIP-1559 transaction
      [cborUint(4), cborUint(1)], // chain_id 1
      [cborUint(5), keypath()],
    ]),
  )
}

const KINDS = {
  1559: () => ({
    signData: Buffer.concat([Buffer.from([0x02]), transfer1559()]),
    dataType: 4,
    chainId: 1,
    expect: 'review: eth send request (chain 1, to 0x1111…, value 10000000000000000 wei, max cost …) then SIGN → ur:eth-signature',
  }),
  personal: () => ({
    signData: Buffer.from('Example `personal_sign` message', 'utf8'),
    dataType: 3,
    chainId: null,
    expect: 'review: eth message sign / message 31 bytes / the message text, then SIGN with v = 27/28',
  }),
  // ERC-20 approve: what MetaMask's in-app Swap refuses to do with a QR hardware
  // account is still a plain EIP-1559 transaction, so the device path is identical to
  // a transfer — only the calldata differs. USDC + a spender of our own address.
  approve: () => ({
    signData: Buffer.concat([Buffer.from([0x02]), approveTx(1_000_000n)]),
    dataType: 4,
    chainId: 1,
    expect: 'review: erc20 approve / spender 0xd003… / allowance 1000000 (decimal, raw units), then SIGN',
  }),
  'approve-unlimited': () => ({
    signData: Buffer.concat([Buffer.from([0x02]), approveTx((1n << 256n) - 1n)]),
    dataType: 4,
    chainId: 1,
    expect: 'review: erc20 approve / spender 0xd003… / allowance unlimited, then SIGN',
  }),
  712: () => ({
    signData: Buffer.from(JSON.stringify({ types: {}, primaryType: 'Mail', domain: {}, message: {} }), 'utf8'),
    dataType: 2,
    chainId: null,
    expect: 'review: eth typed data / data <N> bytes / cannot display → REFUSED (code -10)',
  }),
  legacy: () => ({
    signData: encList([encUint(7), encUint(30_000_000_000), encUint(21_000), encBytes(Buffer.alloc(20, 0x11)), encUint(0), encBytes(Buffer.alloc(0)), encUint(1), encBytes(Buffer.alloc(0)), encBytes(Buffer.alloc(0))]),
    dataType: 1,
    chainId: 1,
    expect: 'REFUSED: legacy data_type is not implemented (code -14)',
  }),
  2930: () => ({
    signData: Buffer.concat([Buffer.from([0x01]), transfer1559()]),
    dataType: 4,
    chainId: 1,
    expect: 'REFUSED: EIP-2930 first byte 0x01 (code -14)',
  }),
  4844: () => ({
    signData: Buffer.concat([Buffer.from([0x03]), transfer1559()]),
    dataType: 4,
    chainId: 1,
    expect: 'REFUSED: EIP-4844 first byte 0x03 (code -14)',
  }),
  7702: () => ({
    signData: Buffer.concat([Buffer.from([0x04]), transfer1559()]),
    dataType: 4,
    chainId: 1,
    expect: 'REFUSED: EIP-7702 first byte 0x04 (code -14)',
  }),
  unknown: () => ({
    signData: Buffer.concat([Buffer.from([0x99]), transfer1559()]),
    dataType: 4,
    chainId: 1,
    expect: 'REFUSED: unknown type byte 0x99 (code -21)',
  }),
  presigned: () => ({
    signData: Buffer.concat([
      Buffer.from([0x02]),
      encList([
        encUint(1), encUint(7), encUint(1_500_000_000), encUint(30_000_000_000), encUint(21_000),
        encBytes(Buffer.alloc(20, 0x11)), encUint(10_000_000_000_000_000), encBytes(Buffer.alloc(0)),
        encList([]), encUint(1), encBytes(Buffer.alloc(32, 0x11)), encBytes(Buffer.alloc(32, 0x22)),
      ]),
    ]),
    dataType: 4,
    chainId: 1,
    expect: 'REFUSED: payload already carries a signature (code -21)',
  }),
  badchain: () => ({
    signData: Buffer.concat([Buffer.from([0x02]), transfer1559()]),
    dataType: 4,
    chainId: 5,
    expect: 'REFUSED: request chain_id 5 vs transaction chain 1 (code -12)',
  }),
  // eth-batch-sign-request — UR type 40404, a keystone private extension, payload
  // `{1: [tagged eth-sign-request, …]}`. Both legs are *valid, signable* 1559
  // transfers on chain 1, so what this exercises is the device's POLICY, not a
  // malformed request: the whole batch is refused with a fixed phrase and the scan
  // keeps running. If the device ever started signing one leg, this kind would show
  // it -- which is why the legs are real requests rather than filler bytes.
  batch: () => ({
    urType: 'eth-batch-sign-request',
    cbor: cborMap([
      [cborUint(1), Buffer.concat([Buffer.from([0x82]), ethSignRequest(1), ethSignRequest(2)])],
    ]),
    expect: 'device refuses the whole batch with a fixed phrase',
  }),
}

const DEFAULT_UR_TYPE = 'eth-sign-request'

function request(kind) {
  const spec = KINDS[kind]()
  // A kind may bring its own container: `batch` is a different UR type with a
  // different payload shape, and hardcoding the type here would have shipped it as
  // an `eth-sign-request` (the device would then never see the batch type at all).
  const urType = spec.urType || DEFAULT_UR_TYPE
  if (spec.cbor) return { cbor: spec.cbor, urType, expect: spec.expect }
  const pairs = [
    [cborUint(1), cborTag(37, cborBytes(UUID))],
    [cborUint(2), cborBytes(spec.signData)],
    [cborUint(3), cborUint(spec.dataType)],
  ]
  if (spec.chainId !== null) pairs.push([cborUint(4), cborUint(spec.chainId)])
  pairs.push([cborUint(5), keypath()])
  return { cbor: cborMap(pairs), urType, expect: spec.expect }
}

const qrSvg = async (text) =>
  (await QRCode.toString(text, {
    type: 'svg',
    errorCorrectionLevel: 'm',
    margin: 2,
  })).replace(/<\?xml.*?\?>/s, '')

function page({ urType, frames, kind, expect }) {
  const imgs = frames
    .map((f) => `data:image/svg+xml;utf8,${encodeURIComponent(f)}`)
    .join('","')
  return `<!doctype html>
<meta charset="utf-8">
<title>ur-inject ${kind}</title>
<style>
  body{margin:0;background:#000;color:#0f0;font:14px/1.4 monospace;display:flex;
       flex-direction:column;align-items:center;justify-content:center;height:100vh}
  #qr{background:#fff;padding:16px;border-radius:8px}
  #meta{max-width:900px;text-align:center;margin-top:14px;white-space:pre-wrap}
</style>
<div id="qr"></div>
<div id="meta"></div>
<script>
  const frames = ["${imgs}"];
  const meta = ${JSON.stringify({ urType, kind, frames: frames.length, expect })};
  document.getElementById('meta').textContent =
    'kind: ' + meta.kind + '\\nur type: ' + meta.urType + '\\nframes: ' + meta.frames +
    '\\nexpected on device:\\n' + meta.expect;
  let i = 0;
  const img = new Image();
  img.style.width = 'min(70vh, 70vw)';
  document.getElementById('qr').appendChild(img);
  const tick = () => { img.src = frames[i % frames.length]; i++; };
  tick();
  if (frames.length > 1) setInterval(tick, 350);
</script>`
}

export { KINDS, request, transfer1559, encList, encUint, encBytes }

const isCli = process.argv[1] && process.argv[1].endsWith('gen.mjs')
const args = isCli ? process.argv.slice(2) : ['--list']
if (!isCli) {
  // imported as a module: nothing to run
} else if (args.includes('--list') || args.length === 0) {
  console.log('kinds:')
  for (const k of Object.keys(KINDS)) console.log(`  ${k.padEnd(18)} ${KINDS[k]().expect}`)
  process.exit(0)
}
if (!isCli) {
  // fall through for importers
}
if (isCli) {
const kind = args[args.indexOf('--kind') + 1]
if (!KINDS[kind]) {
  console.error(`unknown kind: ${kind} (try --list)`)
  process.exit(2)
}
const frag = args.includes('--frag') ? Number(args[args.indexOf('--frag') + 1]) : 200
const out = args.includes('--out') ? args[args.indexOf('--out') + 1] : `/tmp/ur-inject-${kind}.html`

const { cbor, urType, expect } = request(kind)
const ur = new UR(cbor, urType)
const enc = new UREncoder(ur, frag, 0)
const frames = []
for (;;) {
  const part = enc.nextPart()
  if (!frames.includes(part)) frames.push(part)
  if (frames.length >= enc.fragmentsLength) break
}
console.log(`kind=${kind} cbor=${cbor.length}B ur=${ur.type} frames=${frames.length}`)
for (const f of frames) console.log(`  ${f}`)
console.log(`expect: ${expect}`)
const svgs = []
for (const f of frames) svgs.push(await qrSvg(f))
fs.writeFileSync(out, page({ urType, frames: svgs, kind, expect }))
console.log(`page: ${out}  (open it fullscreen, then scan with the device)`)
}
