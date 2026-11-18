// Лаборатория установщика: копия собранного пакета с другой версией, подписанная ключом релиза или чужим ключом.
//   node tools/lab/resign.mjs <исходный каталог пакета> <новый каталог> <версия> [<ключ.pem>|--foreign]
import { createPrivateKey, createPublicKey, generateKeyPairSync, sign } from 'node:crypto'
import { cpSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

const [src, dst, version, keyArg] = process.argv.slice(2)
rmSync(dst, { recursive: true, force: true })
cpSync(src, dst, { recursive: true })
const m = JSON.parse(readFileSync(join(dst, 'manifest.json'), 'utf8'))
m.version = version
const priv = keyArg === '--foreign' ? generateKeyPairSync('ed25519').privateKey : createPrivateKey(readFileSync(keyArg))
m.pubkey = createPublicKey(priv).export({ type: 'spki', format: 'der' }).subarray(-32).toString('hex')
const b = Buffer.from(JSON.stringify(m, null, 1) + '\n')
writeFileSync(join(dst, 'manifest.json'), b)
writeFileSync(join(dst, 'manifest.sig'), sign(null, b, priv).toString('hex') + '\n')
console.log(`${dst}: версия ${version}, ключ ${m.pubkey.slice(0, 16)}…`)
