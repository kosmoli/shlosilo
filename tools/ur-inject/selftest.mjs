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

function container(kind, corrupt = false) {
  const spec = KINDS[kind]()
  const nine = RLP.decode(spec.signData.subarray(1)).slice(0, 9)
  const sighash = keccak256(Buffer.concat([Buffer.from([0x02]), RLP.encode(nine)]))
  const { r, s, v } = ecsign(sighash, KEY)
  const sig = Buffer.concat([r, s, Buffer.from([Number(v - 27n)])])
  if (corrupt) sig[0] ^= 0x01
  const id = Buffer.from('9b1deb4d3b7d4bad9bdd2b0d7b3dcb6d', 'hex')
  const cbor = Buffer.concat([
    Buffer.from([0xa2, 0x01, 0xd8, 0x25, 0x50]),
    id,
    Buffer.from([0x02, 0x58, 0x41]),
    sig,
  ])
  const enc = new UREncoder(new UR(cbor, 'eth-signature'), 200, 0)
  return enc.nextPart()
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
for (const kind of ['approve', 'approve-unlimited', '1559']) {
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
  check(
    typeof report?.signedTxHex === 'string' && report.signedTxHex.startsWith('0x02'),
    `${kind}: a signed 0x02 transaction is assembled`,
  )
  check(report?.yParity === 0 || report?.yParity === 1, `${kind}: yParity is the bare 0/1 byte`)
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
