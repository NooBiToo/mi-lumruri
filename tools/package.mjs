// Установочный пакет mi-trusttunnel для BE7000 (RC06 1.1.38, aarch64): контроллер, панель, движки, сценарии,
// манифест с SHA-256 и подпись Ed25519. Без сети, если кэш .tools уже заполнен; результат воспроизводим (подпись Ed25519
// детерминирована, XZ и tar — без времени и владельцев).
//   node tools/package.mjs [--version X]   →  out/package/mi-trusttunnel-<версия>.tar (+ каталог для проверки)
// Ключ подписи — .tools/keys/release-ed25519.pem (создаётся при первом запуске, в репозиторий не попадает).
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync, copyFileSync } from 'node:fs'
import { basename, dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { gunzipSync } from 'node:zlib'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const args = process.argv.slice(2)
const VERSION = args.includes('--version') ? args[args.indexOf('--version') + 1] : '0.1.0-stage12'
const OUT = args.includes('--out') ? args[args.indexOf('--out') + 1] : join(ROOT, 'out', 'package')
const PKG = join(OUT, 'mi-trusttunnel')
const DL = join(ROOT, '.tools', 'lab', 'dl')
const PY = process.platform === 'win32' ? 'python' : 'python3'
const sha = (b) => createHash('sha256').update(b).digest('hex')

// --- движки ARM64 ---
const MIHOMO_GZ = join(DL, 'mihomo-linux-arm64-v1.19.34.gz')
const MIHOMO_GZ_SHA = 'daaf78a6240a282cdfd75bcbf98fe321f6bd52765cc29e79f344191198f0b50f'
const MIHOMO_SHA = '022da41e03ce70641a2f50c485b4f69ade8f1c7aeeece2cf1ec45c614a029441' // распакованный, по ARCHITECTURE.md
if (!existsSync(MIHOMO_GZ)) {
  execFileSync('curl', ['-sSfL', '--proto', '=https', '-o', MIHOMO_GZ, 'https://github.com/MetaCubeX/mihomo/releases/download/v1.19.34/mihomo-linux-arm64-v1.19.34.gz'])
}
if (sha(readFileSync(MIHOMO_GZ)) !== MIHOMO_GZ_SHA) throw new Error('SHA-256 архива Mihomo arm64 не совпал')
const mihomo = gunzipSync(readFileSync(MIHOMO_GZ))
if (sha(mihomo) !== MIHOMO_SHA) throw new Error(`SHA-256 Mihomo arm64 ${sha(mihomo)} не совпал с ARCHITECTURE.md`)
const DC_TGZ = join(DL, 'dnscrypt-proxy-linux_arm64-2.1.20.tar.gz')
if (sha(readFileSync(DC_TGZ)) !== 'def151a7f7b3bf62129a975e48875861908e05a1e0effb74929c66b8a50c6527') throw new Error('dnscrypt-proxy arm64: SHA-256 архива')
const tmp = join(OUT, 'work'); rmSync(tmp, { recursive: true, force: true }); mkdirSync(tmp, { recursive: true })
execFileSync(PY, ['-I', '-c', 'import sys,tarfile;tarfile.open(sys.argv[1]).extract("linux-arm64/dnscrypt-proxy",sys.argv[2],filter="data")', DC_TGZ, tmp])
const ZAP = join(ROOT, '.tools', 'lab', 'zapret2', 'zapret2-v1.0.7')
if (!existsSync(join(ZAP, 'binaries', 'linux-arm64', 'nfqws2'))) throw new Error('нет zapret2: tools/lab/fetch-zapret.sh')

// --- раскладка ---
rmSync(PKG, { recursive: true, force: true })
for (const d of ['payload/bin', 'payload/engines', 'payload/www', 'payload/scripts', 'payload/defaults']) mkdirSync(join(PKG, d), { recursive: true })
const files = []
function xz(src, rel, unpacked) {
  const dst = join(PKG, rel)
  const [usha, usize] = execFileSync(PY, ['-I', join(ROOT, 'tools', 'xzpack.py'), 'xz', src, dst]).toString().trim().split(' ')
  const b = readFileSync(dst)
  files.push({ path: rel, sha256: sha(b), size: b.length, unpacked, unpacked_sha256: usha, unpacked_size: Number(usize) })
}
function plain(src, rel) {
  copyFileSync(src, join(PKG, rel))
  const b = readFileSync(join(PKG, rel))
  files.push({ path: rel, sha256: sha(b), size: b.length, unpacked: null, unpacked_sha256: null, unpacked_size: null })
}
const T = join(ROOT, 'controller', 'target', 'aarch64-unknown-linux-musl', 'release')
xz(join(T, 'mi-tt-ctl'), 'payload/bin/mi-tt-ctl.xz', 'mi-tt-ctl')
xz(join(T, 'mi-tt-admin'), 'payload/bin/mi-tt-admin.xz', 'mi-tt-admin')
writeFileSync(join(tmp, 'mihomo'), mihomo)
xz(join(tmp, 'mihomo'), 'payload/engines/mihomo.xz', 'mihomo')
xz(join(tmp, 'linux-arm64', 'dnscrypt-proxy'), 'payload/engines/dnscrypt-proxy.xz', 'dnscrypt-proxy')
xz(join(ZAP, 'binaries', 'linux-arm64', 'nfqws2'), 'payload/engines/nfqws2.xz', 'nfqws2')
for (const l of ['zapret-lib.lua.gz', 'zapret-antidpi.lua.gz']) plain(join(ZAP, 'lua', l), `payload/engines/${l}`)
const WWW = join(ROOT, 'panel', 'dist')
for (const f of readdirSync(WWW)) {
  if (statSync(join(WWW, f)).isDirectory()) {
    for (const a of readdirSync(join(WWW, f))) xz(join(WWW, f, a), `payload/www/assets__${a}.xz`, `www/assets/${a}`)
  } else xz(join(WWW, f), `payload/www/${f}.xz`, `www/${f}`)
}
for (const s of readdirSync(join(ROOT, 'package', 'scripts'))) plain(join(ROOT, 'package', 'scripts', s), `payload/scripts/${s}`)
plain(join(ROOT, 'package', 'defaults', 'config.json'), 'payload/defaults/config.json')
copyFileSync(join(ROOT, 'package', 'install.sh'), join(PKG, 'install.sh'))

// --- ключ и подпись ---
const KEYF = args.includes('--key') ? args[args.indexOf('--key') + 1] : join(ROOT, '.tools', 'keys', 'release-ed25519.pem')
if (!existsSync(KEYF)) {
  mkdirSync(dirname(KEYF), { recursive: true })
  const { privateKey } = generateKeyPairSync('ed25519')
  writeFileSync(KEYF, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 })
}
const priv = createPrivateKey(readFileSync(KEYF))
const pubHex = createPublicKey(priv).export({ type: 'spki', format: 'der' }).subarray(-32).toString('hex')
files.sort((a, b) => a.path.localeCompare(b.path))
const manifest = {
  name: 'mi-trusttunnel', version: VERSION, target: 'rc06-1.1.38-aarch64', created: '2026-11-18', pubkey: pubHex, files,
  data_bytes: files.reduce((s, f) => s + f.size, 0), tmp_bytes: files.reduce((s, f) => s + (f.unpacked_size ?? f.size), 0),
}
const mbytes = Buffer.from(JSON.stringify(manifest, null, 1) + '\n')
writeFileSync(join(PKG, 'manifest.json'), mbytes)
writeFileSync(join(PKG, 'manifest.sig'), sign(null, mbytes, priv).toString('hex') + '\n')
rmSync(tmp, { recursive: true, force: true })

const tarPath = join(OUT, `mi-trusttunnel-${VERSION}.tar`)
execFileSync(PY, ['-I', join(ROOT, 'tools', 'xzpack.py'), 'tar', PKG, tarPath])
const tarSize = statSync(tarPath).size
const n = (x) => x.toLocaleString('ru-RU')
const report = { version: VERSION, tar: tarPath, tar_bytes: tarSize, tar_sha256: sha(readFileSync(tarPath)), data_bytes: manifest.data_bytes, tmp_bytes: manifest.tmp_bytes,
  key_fingerprint: sha(Buffer.from(pubHex, 'hex')).slice(0, 16), budget: 20_000_000, headroom: 20_000_000 - tarSize,
  files: files.map((f) => ({ path: f.path, size: f.size, unpacked_size: f.unpacked_size })) }
writeFileSync(join(OUT, `report-${VERSION}.json`), JSON.stringify(report, null, 2) + '\n')
console.log(`пакет: ${tarPath} ${n(tarSize)} Б, sha256 ${report.tar_sha256}`)
console.log(`на /data: ${n(manifest.data_bytes)} Б; в /tmp после распаковки: ${n(manifest.tmp_bytes)} Б; бюджет 20 000 000 Б, запас ${n(report.headroom)} Б`)
console.log(`ключ релиза: ${report.key_fingerprint}`)
for (const f of files) console.log(`  ${f.path.padEnd(42)} ${n(f.size).padStart(12)}${f.unpacked_size ? ` → ${n(f.unpacked_size)}` : ''}`)
