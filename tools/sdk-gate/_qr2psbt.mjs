import fs from 'node:fs'
import { URDecoder } from '@ngraveio/bc-ur'
const frames = fs.readFileSync(process.argv[2], 'utf8').split('\n').map(s => s.trim()).filter(Boolean)
const outPath = process.argv[3]
const dec = new URDecoder()
for (const f of frames) {
  dec.receivePart(f)
  if (dec.isComplete()) break
}
if (!dec.isComplete() || !dec.isSuccess()) {
  console.error(`incomplete: ${(dec.estimatedPercentComplete() * 100).toFixed(0)}% of the message`)
  process.exit(2)
}
const ur = dec.resultUR()
fs.writeFileSync(outPath, Buffer.from(ur.cbor))
console.log(`type=${ur.type} psbt=${ur.cbor.length} bytes -> ${outPath}`)
