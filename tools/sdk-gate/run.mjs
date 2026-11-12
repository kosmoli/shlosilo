// Decode shlosilo artifacts with the keystone SDK and assert what a wallet needs.
//
// The SDK is the parser real wallets use and it is strict: a missing field
// throws instead of defaulting. Nothing here goes through our own decoders, so a
// shape mistake on our side cannot pass by being symmetric with our own reader.
//
// Usage: node run.mjs <artifact-dir>
//   artifacts come from `cargo run --example dump_sdk_artifacts -- <dir>`

import fs from 'node:fs'
import path from 'node:path'
// The SDK ships CommonJS; destructure from the default export (named ESM imports
// throw at link time: "Named export 'parseAccount' not found").
import sdkPkg from '@keystonehq/keystone-sdk'
const { KeystoneSDK, URDecoder } = sdkPkg
// `parseHDKey` / `parseAccount` live in the package's wallet layer but are not
// re-exported from its root (the published entry point exposes only KeystoneSDK,
// the per-chain SDKs and the UR primitives). They are the parsers a wallet uses -
// including the account-path allowlist and the "HDKey is invalid" throw - so the
// gate imports them from their dist path. The version is pinned in package.json,
// and a moved path fails loudly here instead of silently skipping the check.
const { parseHDKey } = await import('@keystonehq/keystone-sdk/dist/wallet/hdKey.js')
const { parseAccount } = await import('@keystonehq/keystone-sdk/dist/wallet/account.js')
// A single-frame UR string becomes a UR object through the one-shot decoder.
const UR = { fromString: s => URDecoder.decode(s) }

const dir = process.argv[2]
if (!dir) {
  console.error('usage: node run.mjs <artifact-dir>')
  process.exit(2)
}

const read = f => fs.readFileSync(path.join(dir, f), 'utf8').trim()
const readJson = f => JSON.parse(read(f))

let checks = 0
function ok (cond, msg) {
  if (!cond) {
    console.error(`FAIL: ${msg}`)
    process.exit(1)
  }
  checks++
  console.log(`ok - ${msg}`)
}

const sdk = new KeystoneSDK()

// --- 1. the signed PSBT, under the registry name ------------------------------
// This is the artifact a wallet scans back: the SDK must get the very bytes we
// signed out of it.
{
  const ur = UR.fromString(read('psbt_signed.ur.txt'))
  const got = sdk.btc.parsePSBT(ur).toLowerCase()
  const want = read('psbt_signed.hex').toLowerCase()
  ok(got.length === want.length, `parsePSBT returns ${got.length / 2} bytes`)
  ok(got === want, 'parsePSBT returns exactly the PSBT we signed')
}

// --- 2. crypto-hdkey (BIP-84 account) -----------------------------------------
{
  const want = readJson('hdkey84.expected.json')
  const account = parseHDKey(UR.fromString(read('hdkey84.ur.txt')))

  ok(
    account.xfp === want.fingerprint,
    `hdkey xfp ${account.xfp} == our master fingerprint`
  )
  ok(account.path === want.path, `hdkey path ${account.path} == ${want.path}`)
  ok(
    account.chainCode === want.xpub.slice(26, 90),
    'hdkey chain code matches the xpub we exported'
  )
  ok(
    account.publicKey === want.xpub.slice(90),
    'hdkey public key matches the xpub we exported'
  )
  ok(
    account.extendedPublicKey !== undefined &&
      account.extendedPublicKey.startsWith('xpub'),
    'hdkey exposes an xpub (parent fingerprint + chain code both present)'
  )
  ok(account.chain === 'BTC', `hdkey chain resolved to ${account.chain}`)
}

// --- 3. crypto-account (BIP-84 + BIP-49) --------------------------------------
{
  const want = readJson('account.expected.json')
  const account = parseAccount(UR.fromString(read('account.ur.txt')))

  ok(
    account.masterFingerprint === want.fingerprint,
    'account master fingerprint matches'
  )
  ok(account.keys.length === 2, `account carries ${account.keys.length} keys`)
  const byPath = Object.fromEntries(account.keys.map(k => [k.path, k]))
  ok(
    byPath["m/84'/0'/0'"] !== undefined,
    'account carries the BIP-84 descriptor'
  )
  ok(
    byPath["m/49'/0'/0'"] !== undefined,
    'account carries the BIP-49 descriptor'
  )
  ok(
    byPath["m/84'/0'/0'"].chainCode === want.xpub84.slice(26, 90),
    'BIP-84 descriptor chain code matches'
  )
  ok(
    byPath["m/49'/0'/0'"].chainCode === want.xpub49.slice(26, 90),
    'BIP-49 descriptor chain code matches'
  )
}

// --- 4. the Cake-family short name is NOT a keystone-SDK name -----------------
// Documented boundary: `psbt` (what Cupcake speaks) carries the same payload but
// the keystone parser is type-gated, so a wallet on that side needs the alias
// and this SDK needs the registry name. Pinning the rejection keeps the two
// conventions from being confused for each other later.
{
  let threw = ''
  try {
    sdk.btc.parsePSBT(UR.fromString(read('psbt_alias.ur.txt')))
  } catch (e) {
    threw = String(e.message || e)
  }
  ok(threw === 'type not match', `psbt alias is refused by the SDK ("${threw}")`)
}

console.log(`\nSDK gate: ${checks} checks passed`)

// --- 5. the six account-export shapes -----------------------------------------
// Each shape is checked with the consumer's own parser where one is available:
// the keystone SDK for the three BC-UR shapes, plain JSON for the two Monero
// shapes (Feather parses them with QJsonDocument, i.e. no schema beyond the
// field names).
{
  const read = f => fs.readFileSync(path.join(dir, f), 'utf8').trim()

  // 1: crypto-account must expose the four BTC account descriptors
  const acc = parseAccount(UR.fromString(read('export_0.txt')))
  ok(acc.keys.length === 4, `crypto-account carries ${acc.keys.length} descriptors`)
  const paths = acc.keys.map(k => k.path)
  for (const p of ["m/84'/0'/0'", "m/49'/0'/0'", "m/44'/0'/0'", "m/86'/0'/0'"]) {
    ok(paths.includes(p), `crypto-account carries ${p}`)
  }

  // 2: the Cake-shaped static URI
  const uri = read('export_1.txt')
  ok(uri.startsWith('bitcoin:?xpub='), 'bitcoin: URI carries an xpub')
  ok(uri.includes('&label='), 'bitcoin: URI carries a label')
  const xpub = uri.split('xpub=')[1].split('&')[0]
  ok(xpub.startsWith('xpub'), `xpub is a mainnet account key (${xpub.slice(0, 8)}…)`)

  // 3: crypto-hdkey for ETH - the SDK must resolve coin type 60
  const eth = parseHDKey(UR.fromString(read('export_2.txt')))
  ok(eth.path === "m/44'/60'/0'", `ETH hdkey path ${eth.path}`)
  ok(eth.chain === 'ETH', `ETH hdkey chain resolved to ${eth.chain}`)

  // 4: keystone-shaped Monero JSON (Feather reads primaryAddress/privateViewKey)
  const ks = JSON.parse(read('export_3.txt'))
  ok(ks.version === 0, 'keystone JSON version 0')
  ok(typeof ks.primaryAddress === 'string' && ks.primaryAddress.startsWith('4'), 'keystone JSON primaryAddress')
  ok(/^[0-9a-f]{64}$/.test(ks.privateViewKey), 'keystone JSON privateViewKey is 64 hex')
  ok(ks.restoreHeight === 0, 'keystone JSON restoreHeight is the hardcoded 0')
  ok(ks.source === 'Keystone', 'keystone JSON source')
  ok(ks.encrypted === false, 'keystone JSON plaintext variant')

  // 5: cupcake-shaped Monero JSON (Cake pairing leg)
  const cp = JSON.parse(read('export_4.txt'))
  ok(typeof cp.label === 'string' && cp.label.length > 0, 'cupcake JSON carries a label')
  ok(/^[0-9a-f]{64}$/.test(cp.privateViewKey), 'cupcake JSON privateViewKey is 64 hex')
  ok(!('encrypted' in cp) && !('source' in cp), 'cupcake JSON has no encrypted/source')
  ok(cp.version === 0, 'cupcake JSON version 0')
}
