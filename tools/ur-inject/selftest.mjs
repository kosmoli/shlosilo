#!/usr/bin/env node
// Self-test for verify.mjs — the tool that decides whether a device signature is
// valid. A verifier nobody verified is worse than none, so this signs the injector's
// own payloads with a known key and drives the real CLI end to end.
//
// Run: node tools/ur-inject/selftest.mjs
import { execFileSync } from 'node:child_process'
import { createRequire } from 'node:module'
import path from 'node:path'
import { KINDS } from './gen.mjs'

const require = createRequire(import.meta.url)
const { UR, UREncoder } = require('@ngraveio/bc-ur')
const { ecsign, privateToAddress } = require('@ethereumjs/util')
const { keccak256 } = require('ethereum-cryptography/keccak.js')
const { RLP } = require('@ethereumjs/rlp')

const HERE = path.dirname(new URL(import.meta.url).pathname)
const VERIFY = path.join(HERE, 'verify.mjs')

// A fixed test key: the address is derived, not typed, so a wrong derivation shows up.
const KEY = Buffer.from('4646464646464646464646464646464646464646464646464646464646464646', 'hex')
const ADDR = '0x' + Buffer.from(privateToAddress(KEY)).toString('hex')

const word32 = (n) => {
  const b = Buffer.alloc(32)
  let hex = BigInt(n).toString(16)
  if (hex.length % 2) hex = '0' + hex
  Buffer.from(hex, 'hex').copy(b, 32 - Buffer.from(hex, 'hex').length)
  return b
}

/**
 * The EIP-712 digest of the injector's `712-permit` document, computed from type strings
 * hardcoded HERE rather than derived by `verify.mjs`. That is the point: if the verifier's
 * type-string derivation or field encoding is wrong, the two disagree and the recovered
 * address stops matching. Values mirror `gen.mjs`'s `permitJson()`.
 */
function permitDigest() {
  const domainType =
    'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'
  const permitType =
    'Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)'
  const addrWord = (h) => {
    const b = Buffer.alloc(32)
    Buffer.from(h.replace(/^0x/, ''), 'hex').copy(b, 12)
    return b
  }
  const domainSep = Buffer.from(
    keccak256(
      Buffer.concat([
        Buffer.from(keccak256(Buffer.from(domainType, 'utf8'))),
        Buffer.from(keccak256(Buffer.from('USD Coin', 'utf8'))),
        Buffer.from(keccak256(Buffer.from('2', 'utf8'))),
        word32(1n),
        addrWord('0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48'),
      ]),
    ),
  )
  const struct = Buffer.from(
    keccak256(
      Buffer.concat([
        Buffer.from(keccak256(Buffer.from(permitType, 'utf8'))),
        addrWord('0x1111111111111111111111111111111111111111'),
        addrWord('0x2222222222222222222222222222222222222222'),
        word32(1_000_000n),
        word32(0n),
        word32(1_700_000_000n),
      ]),
    ),
  )
  return Buffer.from(keccak256(Buffer.concat([Buffer.from([0x19, 0x01]), domainSep, struct])))
}

/** The digest each scheme signs, rebuilt from the injector's own request. */
function digestOf(spec) {
  if (spec.dataType === 4) {
    const nine = RLP.decode(spec.signData.subarray(1)).slice(0, 9)
    return { digest: Buffer.from(keccak256(Buffer.concat([Buffer.from([0x02]), RLP.encode(nine)]))), chain: null }
  }
  if (spec.dataType === 1) {
    const nine = RLP.decode(spec.signData)
    const chain = BigInt('0x' + Buffer.from(nine[6]).toString('hex'))
    return { digest: Buffer.from(keccak256(RLP.encode(nine))), chain }
  }
  if (spec.dataType === 2) {
    return { digest: permitDigest(), chain: 1n }
  }
  throw new Error(`selftest has no digest for data_type ${spec.dataType}`)
}

function container(kind, corrupt = false) {
  const spec = KINDS[kind]()
  const { digest, chain } = digestOf(spec)
  const { r, s, v } = ecsign(digest, KEY)
  const parity = Number(v - 27n)
  let vBytes
  if (spec.dataType === 4) vBytes = Buffer.from([parity]) // yParity, bare
  else if (spec.dataType === 1) vBytes = minimalBE(chain * 2n + 35n + BigInt(parity)) // EIP-155
  else vBytes = Buffer.from([27 + parity]) // EIP-712

  let sig = Buffer.concat([r, s, vBytes])
  if (corrupt) sig[0] ^= 0x01
  const id = Buffer.from('9b1deb4d3b7d4bad9bdd2b0d7b3dcb6d', 'hex')
  // The container's signature slot is 65..=72 bytes (E-1), so its CBOR length byte varies.
  const cbor = Buffer.concat([
    Buffer.from([0xa2, 0x01, 0xd8, 0x25, 0x50]),
    id,
    Buffer.from([0x02, 0x58, sig.length]),
    sig,
  ])
  const enc = new UREncoder(new UR(cbor, 'eth-signature'), 200, 0)
  return enc.nextPart()
}

function minimalBE(n) {
  if (n === 0n) return Buffer.alloc(0)
  let hex = n.toString(16)
  if (hex.length % 2) hex = '0' + hex
  return Buffer.from(hex, 'hex')
}

function run(kind, uri, expectFrom) {
  try {
    const out = execFileSync(
      process.execPath,
      [VERIFY, '--kind', kind, '--ur', uri, '--expect-from', expectFrom, '--json'],
      { encoding: 'utf8' },
    )
    return { code: 0, out }
  } catch (e) {
    return { code: e.status ?? 1, out: String(e.stdout || '') }
  }
}

let failures = 0
const check = (cond, msg) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} - ${msg}`)
  if (!cond) failures++
}

console.log(`test key address: ${ADDR}`)
for (const kind of ['approve', 'approve-unlimited', '1559', 'legacy', 'legacy-sepolia', '712-permit']) {
  const uri = container(kind)
  const { code, out } = run(kind, uri, ADDR)
  let report = null
  try {
    report = JSON.parse(out)
  } catch {
    /* leave null */
  }
  check(code === 0, `${kind}: verify.mjs accepts a valid signature`)
  check(report?.signerMatches === true, `${kind}: recovered sender equals the expected address`)
  const spec = KINDS[kind]()
  if (spec.dataType === 4) {
    check(
      typeof report?.signedTxHex === 'string' && report.signedTxHex.startsWith('0x02'),
      `${kind}: a signed 0x02 transaction is assembled`,
    )
    check(report?.yParity === 0 || report?.yParity === 1, `${kind}: yParity is the bare 0/1 byte`)
  } else if (spec.dataType === 1) {
    const chain = BigInt(spec.chainId)
    check(
      report?.v === Number(chain * 2n + 35n) || report?.v === Number(chain * 2n + 36n),
      `${kind}: v carries chain_id*2+35+parity (${report?.v})`,
    )
    check(
      typeof report?.signedTxHex === 'string' && /^0x[0-9a-f]+$/.test(report.signedTxHex),
      `${kind}: a signed legacy list is assembled (${String(report?.signedTxHex).slice(0, 18)}…)`,
    )
    // The chain id is item 6 of the PREIMAGE; the signed form carries v there instead and
    // must still be a 9-item list (nonce…data, v, r, s).
    const signed = RLP.decode(Buffer.from(String(report?.signedTxHex).slice(2), 'hex'))
    check(signed.length === 9, `${kind}: signed legacy list has 9 items`)
    check(
      signed.length === 9 &&
        BigInt('0x' + Buffer.from(signed[6]).toString('hex') || '0x0') === BigInt(report.v),
      `${kind}: item 6 of the signed list is v`,
    )
  } else {
    check(report?.v === 27 || report?.v === 28, `${kind}: v is 27/28, not a bare parity`)
    check(report?.signedTxHex === null, `${kind}: a typed-data signature has nothing to broadcast`)
    check(
      /^0x[0-9a-f]{64}$/.test(report?.digest || ''),
      `${kind}: the verifier recomputed a 32-byte digest`,
    )
  }
}

// The verifier must reject a signature it cannot validate.
{
  const uri = container('approve', true)
  const { code } = run('approve', uri, ADDR)
  check(code !== 0, 'corrupted signature is rejected')
}
// …and a valid signature from the wrong key.
{
  const uri = container('approve')
  const { code } = run('approve', uri, '0x0988a7fe9d0eb483b89040e238a1d0afe5a7a736')
  check(code !== 0, 'signature from an unexpected key is rejected')
}

console.log(failures === 0 ? '\nSELFTEST PASS' : `\nSELFTEST FAIL (${failures})`)
process.exit(failures === 0 ? 0 : 1)
