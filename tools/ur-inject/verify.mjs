#!/usr/bin/env node
// Verify a signature the device produced for an **injected** request — the closing
// half of the injector, and the reason an approve can be checked without a wallet.
//
// Flow:
//   node tools/ur-inject/gen.mjs --kind approve-unlimited      # frames on screen
//   <device scans, reviews, signs → shows ur:eth-signature>    # photograph it
//   node tools/ur-inject/verify.mjs --kind approve-unlimited --image photo.jpg
//
// What it does with the photographed container:
//  1. decodes the QR (`zbarimg`) and the container's CBOR (requestId, r‖s‖v);
//  2. rebuilds the **same** unsigned transaction the injector sent for that kind;
//  3. recovers the signer from (sighash, r, s, yParity) and checks it against the
//     expected device address — the same arithmetic a node applies before accepting;
//  4. assembles the signed raw transaction and prints it, so it can be broadcast
//     later if someone decides to spend gas on it.
//
// A PASS here means: the device signed *this exact request* with *its own key*, and
// the bytes are a well-formed EIP-1559 transaction. It does not mean the chain ran it.
//
// Usage:
//   --kind <k>           the kind that produced the request (required)
//   --image <file>       photo/screenshot of the QR (uses zbarimg)
//   --ur <string>        the UR text directly (skips decoding)
//   --expect-from <addr> expected signer (default: the account that signed the two
//                        mainnet acceptance transactions)
//   --json               machine-readable output

import { execFileSync } from 'node:child_process'
import { createRequire } from 'node:module'
import { KINDS } from './gen.mjs'

const require = createRequire(import.meta.url)
const { URDecoder } = require('@ngraveio/bc-ur')
const { ecrecover } = require('@ethereumjs/util')
const { keccak256 } = require('ethereum-cryptography/keccak.js')
const { RLP } = require('@ethereumjs/rlp')

const argv = process.argv.slice(2)
const arg = (n, d = null) => {
  const i = argv.indexOf(n)
  return i >= 0 ? argv[i + 1] : d
}
const kind = arg('--kind')
const image = arg('--image')
const urText = arg('--ur')
const expectFrom = (arg('--expect-from') || '0x0988a7fe9d0eb483b89040e238a1d0afe5a7a736').toLowerCase()
const asJson = argv.includes('--json')

if (!kind || !KINDS[kind]) {
  console.error('usage: verify.mjs --kind <k> (--image <file> | --ur <string>) [--expect-from 0x…]')
  process.exit(2)
}

// ── 1. get the UR text ───────────────────────────────────────────────────────
let uri = urText
if (!uri) {
  if (!image) {
    console.error('need --image or --ur')
    process.exit(2)
  }
  // zbarimg prints `QR-Code:<text>` lines; multi-frame photos may carry several.
  const out = execFileSync('zbarimg', ['--raw', '-q', image], { encoding: 'utf8' })
  const frames = out
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.startsWith('ur:'))
  if (frames.length === 0) {
    console.error('no ur: payload found in the image (zbarimg saw nothing)')
    process.exit(1)
  }
  useFrames(frames)
} else {
  useFrames([uri])
}

function useFrames(frames) {
  const dec = new URDecoder()
  for (const f of frames) dec.receivePart(f)
  if (!dec.isComplete()) {
    console.error(`incomplete UR: have ${frames.length} frame(s), need more`)
    process.exit(1)
  }
  const ur = dec.resultUR()
  if (ur.type !== 'eth-signature') {
    console.error(`expected eth-signature, got ${ur.type}`)
    process.exit(1)
  }
  const cbor = ur.cbor
  const { requestId, signature } = parseContainer(cbor)
  verify(requestId, signature)
}

/** Minimal CBOR read of {1: tag(37) uuid, 2: bytes(65)[, 3: text]}. */
function parseContainer(buf) {
  let i = 0
  const head = buf[i++]
  if (head !== 0xa2 && head !== 0xa3) throw new Error('container is not a 2- or 3-key map')
  // key 1 → tag(37) + bytes(16)
  if (buf[i++] !== 0x01) throw new Error('key 1 missing')
  if (buf[i++] !== 0xd8 || buf[i++] !== 0x25) throw new Error('key 1 is not the uuid tag (37)')
  if (buf[i++] !== 0x50) throw new Error('uuid is not 16 bytes')
  const requestId = buf.subarray(i, i + 16)
  i += 16
  // key 2 → bytes(65)
  if (buf[i++] !== 0x02) throw new Error('key 2 missing')
  if (buf[i++] !== 0x58) throw new Error('signature is not a 1-byte-length byte string')
  const sigLen = buf[i++]
  if (sigLen !== 65) throw new Error(`signature is ${sigLen} bytes, expected 65 (r||s||v)`)
  const signature = buf.subarray(i, i + 65)
  return { requestId, signature }
}

// ── 2. rebuild the unsigned transaction the injector sent ────────────────────
function verify(requestId, signature) {
  const spec = KINDS[kind]()
  const signData = spec.signData
  if (signData[0] !== 0x02) {
    console.error(`${kind} is not an EIP-1559 request; this verifier only handles 0x02`)
    process.exit(1)
  }
  const fields = RLP.decode(signData.subarray(1))
  // The 9 fields are what gets signed; a 12-field payload repeats the first nine.
  const nine = fields.slice(0, 9)

  const r = signature.subarray(0, 32)
  const s = signature.subarray(32, 64)
  const yParity = signature[64]
  if (yParity > 1) {
    console.error(`v = ${yParity}: an EIP-1559 container must carry the bare yParity`)
    process.exit(1)
  }

  const sighash = keccak256(Buffer.concat([Buffer.from([0x02]), RLP.encode(nine)]))
  // @ethereumjs ecrecover returns the 64-byte x||y key (no 0x04 prefix), so the
  // address is keccak256 over all 64 bytes — dropping the first byte here would
  // silently hash a bogus key.
  const pub = ecrecover(sighash, BigInt(yParity), r, s)
  const addr = '0x' + Buffer.from(keccak256(pub).subarray(12)).toString('hex')

  const signedTx = Buffer.concat([
    Buffer.from([0x02]),
    RLP.encode([...nine, yParity === 0 ? Buffer.alloc(0) : Buffer.from([1]), r, s]),
  ])

  const ok = addr === expectFrom
  const report = {
    kind,
    requestId: requestId.toString('hex'),
    yParity,
    recoveredSender: addr,
    expectedSender: expectFrom,
    signerMatches: ok,
    signedTxHex: '0x' + signedTx.toString('hex'),
    note: 'PASS = the device signed this exact request with the expected key. Broadcasting (gas) is a separate decision.',
  }
  if (asJson) {
    console.log(JSON.stringify(report, null, 2))
  } else {
    console.log(`kind            : ${report.kind}`)
    console.log(`requestId       : ${report.requestId}`)
    console.log(`yParity         : ${report.yParity}`)
    console.log(`recovered sender: ${report.recoveredSender}`)
    console.log(`expected sender : ${report.expectedSender}`)
    console.log(`signer matches  : ${ok ? 'YES' : 'NO'}`)
    console.log(`signed raw tx   : ${report.signedTxHex}`)
    console.log(report.note)
  }
  process.exit(ok ? 0 : 1)
}
