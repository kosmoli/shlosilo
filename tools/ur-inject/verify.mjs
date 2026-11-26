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
//  2. rebuilds the **same** preimage the injector sent for that kind, per scheme:
//     `data_type` 4 → EIP-1559 sighash, 1 → EIP-155 legacy preimage, 2 → the EIP-712
//     digest (domain separator + hashStruct, computed here rather than copied from the
//     device, so the two sides are independent implementations);
//  3. recovers the signer from (digest, r, s, parity) and checks it against the
//     expected device address — the same arithmetic a node applies before accepting;
//  4. for the two transaction schemes, assembles the signed raw transaction and prints
//     it, so it can be broadcast later if someone decides to spend gas on it.
//
// A PASS here means: the device signed *this exact request* with *its own key*, and the
// bytes are well formed for that scheme. It does not mean the chain ran it.
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
  // key 2 → bytes(65..=72): 64 bytes of r‖s plus a 1..=8 byte big-endian v (E-1)
  if (buf[i++] !== 0x02) throw new Error('key 2 missing')
  if (buf[i++] !== 0x58) throw new Error('signature is not a 1-byte-length byte string')
  const sigLen = buf[i++]
  if (sigLen < 65 || sigLen > 72) {
    throw new Error(`signature is ${sigLen} bytes, expected 65..=72 (r||s||v)`)
  }
  const signature = buf.subarray(i, i + sigLen)
  return { requestId, signature }
}

// ── 2. rebuild the preimage the injector sent, per scheme ───────────────────
function verify(requestId, signature) {
  const spec = KINDS[kind]()
  switch (spec.dataType) {
    case 4:
      return verify1559(requestId, signature, spec)
    case 1:
      return verifyLegacy(requestId, signature, spec)
    case 2:
      return verify712(requestId, signature, spec)
    default:
      console.error(`${kind}: data_type ${spec.dataType} has no verifier`)
      process.exit(1)
  }
}

function verify1559(requestId, signature, spec) {
  const signData = spec.signData
  if (signData[0] !== 0x02) {
    console.error(`${kind} is not an EIP-1559 request; this verifier only handles 0x02`)
    process.exit(1)
  }
  const fields = RLP.decode(signData.subarray(1))
  // The 9 fields are what gets signed; a 12-field payload repeats the first nine.
  const nine = fields.slice(0, 9)

  if (signature.length !== 65) {
    console.error(`signature is ${signature.length} bytes: an EIP-1559 container carries 1-byte yParity`)
    process.exit(1)
  }
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

// ── scheme: EIP-155 legacy (data_type 1) ────────────────────────────────────
//
// The injected payload is the nine-item PREIMAGE, so item 6 is the chain id and items 7/8
// are empty. The reply carries `v = chain_id*2 + 35 + parity` as minimal big-endian bytes,
// which is why the signature slot is 1..=8 bytes wide here and 1 byte on mainnet only.
function verifyLegacy(requestId, signature, spec) {
  const nine = RLP.decode(spec.signData)
  if (nine.length !== 9) {
    console.error(`legacy preimage has ${nine.length} items, expected 9 (EIP-155 signed shape)`)
    process.exit(1)
  }
  const chainId = BigInt('0x' + Buffer.from(nine[6]).toString('hex') || '0x0')
  const sighash = keccak256(RLP.encode(nine))

  const r = signature.subarray(0, 32)
  const s = signature.subarray(32, 64)
  const vBytes = signature.subarray(64)
  const v = bytesToBigInt(vBytes)
  const base = chainId * 2n + 35n
  const parity = v - base
  if (parity !== 0n && parity !== 1n) {
    console.error(
      `v = ${v} is not ${base} or ${base + 1n} (chain ${chainId}): the reply does not carry an EIP-155 v`,
    )
    process.exit(1)
  }

  const addr = recoverAddress(sighash, parity, r, s)
  // The signed transaction repeats the first six items and then carries v/r/s, so the
  // chain-id item and the two zero items must NOT survive into it.
  // `RLP.encode` returns a Uint8Array; Buffer.from is what makes `.toString('hex')` mean hex
  // (on a Uint8Array it silently prints comma-joined byte values).
  const signedTx = Buffer.from(RLP.encode([...nine.slice(0, 6), toMinimalBE(v), r, s]))
  const ok = addr === expectFrom
  report({
    kind,
    scheme: 'eip-155 legacy',
    requestId: requestId.toString('hex'),
    chainId: Number(chainId),
    v: Number(v),
    parity: Number(parity),
    signatureBytes: signature.length,
    recoveredSender: addr,
    expectedSender: expectFrom,
    signerMatches: ok,
    signedTxHex: '0x' + signedTx.toString('hex'),
    note: 'PASS = the device signed this exact legacy preimage with the expected key.',
  })
  process.exit(ok ? 0 : 1)
}

// ── scheme: EIP-712 typed data (data_type 2) ───────────────────────────────
//
// The digest is computed HERE from the document (domain separator + hashStruct), not
// copied from the device, so a wrong type string, wrong encoding or wrong domain would
// recover to a different address instead of agreeing with itself.
//
// Scope: flat structs of string / uintN / intN / address / bool / bytesN plus arrays of
// those. A document outside that scope is refused rather than hashed approximately — an
// approximating verifier would "pass" a request the device signed differently.
function verify712(requestId, signature, spec) {
  const doc = JSON.parse(spec.signData.toString('utf8'))
  const digest = eip712Digest(doc)

  if (signature.length !== 65) {
    console.error(`signature is ${signature.length} bytes: EIP-712 carries 1-byte v (27/28)`)
    process.exit(1)
  }
  const r = signature.subarray(0, 32)
  const s = signature.subarray(32, 64)
  const v = signature[64]
  if (v !== 27 && v !== 28) {
    console.error(`v = ${v}: typed data must carry 27/28, not a bare parity`)
    process.exit(1)
  }

  const addr = recoverAddress(digest, BigInt(v - 27), r, s)
  const ok = addr === expectFrom
  report({
    kind,
    scheme: 'eip-712 typed data',
    requestId: requestId.toString('hex'),
    primaryType: doc.primaryType,
    domainChainId: doc.domain.chainId,
    digest: '0x' + Buffer.from(digest).toString('hex'),
    v,
    signatureBytes: signature.length,
    recoveredSender: addr,
    expectedSender: expectFrom,
    signerMatches: ok,
    signedTxHex: null,
    note: 'PASS = the device signed this document with the expected key (a message signature, nothing to broadcast).',
  })
  process.exit(ok ? 0 : 1)
}

// ── shared helpers ──────────────────────────────────────────────────────────

function recoverAddress(digest, parity, r, s) {
  // @ethereumjs ecrecover returns the 64-byte x||y key (no 0x04 prefix), so the address is
  // keccak256 over all 64 bytes — dropping the first byte would hash a bogus key.
  const pub = ecrecover(digest, parity, r, s)
  return '0x' + Buffer.from(keccak256(pub).subarray(12)).toString('hex')
}

function bytesToBigInt(bytes) {
  if (bytes.length === 0 || bytes.length > 8) throw new Error(`v is ${bytes.length} bytes`)
  if (bytes[0] === 0) throw new Error('v carries a leading zero byte (not minimal)')
  return BigInt('0x' + Buffer.from(bytes).toString('hex'))
}

function toMinimalBE(n) {
  if (n === 0n) return Buffer.alloc(0)
  let hex = n.toString(16)
  if (hex.length % 2) hex = '0' + hex
  return Buffer.from(hex, 'hex')
}

function word(b, n) {
  const out = Buffer.alloc(32)
  Buffer.from(b).copy(out, 32 - b.length)
  return out
}

function keccakStr(str) {
  return Buffer.from(keccak256(Buffer.from(str, 'utf8')))
}

/** A type's canonical string plus every struct type it references, alphabetically. */
function encodeType(primary, types, seen = new Set()) {
  const fields = types[primary]
  if (!fields) throw new Error(`type ${primary} is not declared`)
  const deps = new Set()
  for (const f of fields) {
    const base = f.type.replace(/(\[\d*\])+$/, '')
    if (!isAtom(base)) deps.add(base)
  }
  let out = `${primary}(${fields.map((f) => `${f.type} ${f.name}`).join(',')})`
  const order = [...deps].filter((d) => !seen.has(d)).sort()
  if (order.length) {
    const next = new Set([...seen, primary, ...order])
    for (const d of order) out += encodeType(d, types, next)
  }
  return out
}

function isAtom(t) {
  return /^(u?int\d*|address|bool|bytes\d*|string)$/.test(t)
}

/** hashStruct for one struct value. */
function hashStruct(typeName, value, types) {
  const fields = types[typeName]
  if (!fields) throw new Error(`type ${typeName} is not declared`)
  const parts = [keccakStr(encodeType(typeName, types))]
  for (const f of fields) parts.push(encodeField(f.type, value[f.name], types))
  return Buffer.from(keccak256(Buffer.concat(parts)))
}

function encodeField(type, val, types) {
  if (type.endsWith(']')) {
    const m = type.match(/^(.*)\[(\d*)\]$/)
    if (!m) throw new Error(`unparsable array type ${type}`)
    const [, base, count] = m
    const items = val || []
    if (count && Number(count) !== items.length) {
      throw new Error(`${type} declares ${count} items, value has ${items.length}`)
    }
    const inner = items.map((v) => encodeField(base, v, types))
    return Buffer.from(keccak256(Buffer.concat(inner)))
  }
  if (!isAtom(type)) {
    // Nested struct: hashStruct of the referenced type.
    return hashStruct(type, val, types)
  }
  if (type === 'string') return keccakStr(String(val))
  if (type === 'bytes') {
    const b = typeof val === 'string' ? stripHex(val) : Buffer.from(val)
    return Buffer.from(keccak256(b))
  }
  if (type === 'address') {
    const b = typeof val === 'string' ? stripHex(val) : Buffer.from(val)
    if (b.length !== 20) throw new Error(`address is ${b.length} bytes`)
    return word(b, 20)
  }
  if (type === 'bool') return word([val === true || val === 'true' ? 1 : 0], 1)
  if (type.startsWith('bytes') && type !== 'bytes') {
    const n = Number(type.slice(5))
    const b = typeof val === 'string' ? stripHex(val) : Buffer.from(val)
    if (b.length !== n) throw new Error(`${type} is ${b.length} bytes`)
    // bytesN sits at the START of its word (right-padded), unlike int/address.
    const out = Buffer.alloc(32)
    Buffer.from(b).copy(out, 0)
    return out
  }
  if (/^u?int\d*$/.test(type)) {
    const n = BigInt(typeof val === 'string' ? val : String(val))
    return word(toMinimalBE(n < 0n ? (1n << 256n) + n : n), 32)
  }
  throw new Error(`unsupported field type ${type}`)
}

function stripHex(s) {
  return Buffer.from(s.startsWith('0x') || s.startsWith('0X') ? s.slice(2) : s, 'hex')
}

/** EIP-712 digest: keccak256(0x19 0x01 ‖ domainSeparator ‖ hashStruct(primaryType)). */
function eip712Digest(doc) {
  const types = doc.types
  if (!types.EIP712Domain) throw new Error('no EIP712Domain declaration')
  const domain = hashStruct('EIP712Domain', doc.domain, types)
  const message = hashStruct(doc.primaryType, doc.message, types)
  return Buffer.from(keccak256(Buffer.concat([Buffer.from([0x19, 0x01]), domain, message])))
}

function report(r) {
  if (asJson) {
    console.log(JSON.stringify(r, null, 2))
    return
  }
  for (const [k, v] of Object.entries(r)) console.log(`${k.padEnd(16)}: ${v ?? '-'}`)
}
