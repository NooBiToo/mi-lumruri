// Установочный пакет Mi Lumruri (mi-lumruri) для BE7000 (RC06 1.1.38, aarch64): контроллер, панель, клиент TrustTunnel, nfqws2, сценарии,
// манифест с SHA-256 и подпись Ed25519. Без сети, если кэш .tools уже заполнен; результат воспроизводим (подпись Ed25519
// детерминирована, XZ и tar — без времени и владельцев).
//   node tools/package.mjs [--version X]   →  out/package/mi-lumruri-<версия>.tar (+ каталог для проверки)
//   и совместимая копия mi-trusttunnel-<версия>.tar (каталог mi-trusttunnel/ внутри) — для обновления из панели 0.4.x
//   и модуль sing-box mitt-mod-sing-box-<версия sing-box>.tar (ставится со страницы «Модули»); его SHA-256 и размеры —
//   в каталоге payload/scripts/modules.json основного пакета. --singbox-bin <файл> — другой sing-box (только лаборатория,
//   x86_64).
// Ключ подписи — .tools/keys/release-ed25519.pem (создаётся при первом запуске, в репозиторий не попадает).
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync, copyFileSync } from 'node:fs'
import { basename, dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { gunzipSync } from 'node:zlib'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const args = process.argv.slice(2)
const VERSION = args.includes('--version') ? args[args.indexOf('--version') + 1] : '0.11.1'
const OUT = args.includes('--out') ? args[args.indexOf('--out') + 1] : join(ROOT, 'out', 'package')
const PKG = join(OUT, 'mi-lumruri')
const DL = join(ROOT, '.tools', 'lab', 'dl')
const PY = process.platform === 'win32' ? 'python' : 'python3'
const sha = (b) => createHash('sha256').update(b).digest('hex')

// --- движки ARM64 ---
// Официальный клиент TrustTunnel (статически собранный aarch64); архив закреплён по SHA-256 релиза v1.3.0.
const TT_VER = 'v1.3.0'
const TT_TGZ = join(DL, `trusttunnel_client-${TT_VER}-linux-aarch64.tar.gz`)
const TT_TGZ_SHA = '837ec64520d546cdf8e7a327614589f64dc6c4f30e408e3788de7bfaef05b52b'
mkdirSync(DL, { recursive: true })
if (!existsSync(TT_TGZ)) {
  execFileSync('curl', ['-sSfL', '--proto', '=https', '-o', TT_TGZ, `https://github.com/TrustTunnel/TrustTunnelClient/releases/download/${TT_VER}/trusttunnel_client-${TT_VER}-linux-aarch64.tar.gz`])
}
if (sha(readFileSync(TT_TGZ)) !== TT_TGZ_SHA) throw new Error('SHA-256 архива trusttunnel_client aarch64 не совпал')
const tmp = join(OUT, 'work'); rmSync(tmp, { recursive: true, force: true }); mkdirSync(tmp, { recursive: true })
execFileSync(PY, ['-I', '-c', 'import sys,tarfile;tarfile.open(sys.argv[1]).extract(sys.argv[3]+"/trusttunnel_client",sys.argv[2],filter="data")', TT_TGZ, tmp, `trusttunnel_client-${TT_VER}-linux-aarch64`])
const TT_BIN = join(tmp, `trusttunnel_client-${TT_VER}-linux-aarch64`, 'trusttunnel_client')
// Официальный sing-box (linux-arm64-musl, статическая: на стоке musl, сборка linux-arm64 требует glibc) — для модуля; архив закреплён по SHA-256 релиза.
const SB_VER = '1.14.4'
const SB_TGZ = join(DL, `sing-box-${SB_VER}-linux-arm64-musl.tar.gz`)
const SB_TGZ_SHA = 'b95e25f921dc5e17a4cf13327243d1177642c7e35425bf5372862c477c359f56'
let SB_BIN = args.includes('--singbox-bin') ? args[args.indexOf('--singbox-bin') + 1] : null
if (!SB_BIN) {
  if (!existsSync(SB_TGZ)) {
    execFileSync('curl', ['-sSfL', '--proto', '=https', '-o', SB_TGZ, `https://github.com/SagerNet/sing-box/releases/download/v${SB_VER}/sing-box-${SB_VER}-linux-arm64-musl.tar.gz`])
  }
  if (sha(readFileSync(SB_TGZ)) !== SB_TGZ_SHA) throw new Error('SHA-256 архива sing-box arm64 не совпал')
  execFileSync(PY, ['-I', '-c', 'import sys,tarfile;tarfile.open(sys.argv[1]).extract(sys.argv[3]+"/sing-box",sys.argv[2],filter="data")', SB_TGZ, tmp, `sing-box-${SB_VER}-linux-arm64-musl`])
  SB_BIN = join(tmp, `sing-box-${SB_VER}-linux-arm64-musl`, 'sing-box')
}
const ZAP = join(ROOT, '.tools', 'lab', 'zapret2', 'zapret2-v1.0.7')
if (!existsSync(join(ZAP, 'binaries', 'linux-arm64', 'nfqws2'))) throw new Error('нет zapret2: tools/lab/fetch-zapret.sh')

// --- раскладка ---
rmSync(PKG, { recursive: true, force: true })
for (const d of ['payload/bin', 'payload/engines', 'payload/www', 'payload/scripts', 'payload/defaults', 'payload/lists']) mkdirSync(join(PKG, d), { recursive: true })
const files = []
function xz(src, rel, unpacked, base = PKG, list = files) {
  const dst = join(base, rel)
  const [usha, usize] = execFileSync(PY, ['-I', join(ROOT, 'tools', 'xzpack.py'), 'xz', src, dst]).toString().trim().split(' ')
  const b = readFileSync(dst)
  list.push({ path: rel, sha256: sha(b), size: b.length, unpacked, unpacked_sha256: usha, unpacked_size: Number(usize) })
}
function plain(src, rel) {
  copyFileSync(src, join(PKG, rel))
  const b = readFileSync(join(PKG, rel))
  files.push({ path: rel, sha256: sha(b), size: b.length, unpacked: null, unpacked_sha256: null, unpacked_size: null })
}
const T = join(ROOT, 'controller', 'target', 'aarch64-unknown-linux-musl', 'release')
// одна программа mi-tt вместо mi-tt-ctl, mi-tt-admin и mi-tt-dns (ссылки создаёт распаковка на роутере, mitt-lib.sh)
xz(join(T, 'mi-tt'), 'payload/bin/mi-tt.xz', 'mi-tt')
xz(TT_BIN, 'payload/engines/trusttunnel_client.xz', 'trusttunnel_client')
xz(join(ZAP, 'binaries', 'linux-arm64', 'nfqws2'), 'payload/engines/nfqws2.xz', 'nfqws2')
for (const l of ['zapret-lib.lua.gz', 'zapret-antidpi.lua.gz', 'zapret-auto.lua.gz']) plain(join(ZAP, 'lua', l), `payload/engines/${l}`)
// Блобы и списки хостов из каталога стратегий лежат рядом с nfqws2 (--chdir); блобы — из zapret2, остальное — из package/zapret
const CAT = JSON.parse(readFileSync(join(ROOT, 'controller', 'data', 'zapret-strategies.json'), 'utf8'))
for (const f of [...Object.values(CAT.blobs), ...Object.values(CAT.hostlists)]) {
  const src = [join(ZAP, 'files', 'fake', f), join(ROOT, 'package', 'zapret', f)].find(existsSync)
  if (!src) throw new Error(`нет файла Zapret «${f}» из каталога стратегий: ни в .tools/lab/zapret2/.../files/fake, ни в package/zapret`)
  plain(src, `payload/engines/${f}`)
}
const WWW = join(ROOT, 'panel', 'dist')
for (const f of readdirSync(WWW)) {
  if (statSync(join(WWW, f)).isDirectory()) {
    for (const a of readdirSync(join(WWW, f))) xz(join(WWW, f, a), `payload/www/assets__${a}.xz`, `www/assets/${a}`)
  } else xz(join(WWW, f), `payload/www/${f}.xz`, `www/${f}`)
}
for (const s of readdirSync(join(ROOT, 'package', 'scripts'))) plain(join(ROOT, 'package', 'scripts', s), `payload/scripts/${s}`)
// Снимок списков сайтов itdoginfo (tools/fetch-lists.sh): payload/lists/<тот же путь, что в package/lists>
const LISTS = join(ROOT, 'package', 'lists')
const walk = (d, rel = '') => readdirSync(join(d, rel), { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1)).flatMap((e) => (e.isDirectory() ? walk(d, `${rel}${e.name}/`) : [`${rel}${e.name}`]))
for (const f of walk(LISTS)) {
  mkdirSync(dirname(join(PKG, 'payload', 'lists', f)), { recursive: true })
  plain(join(LISTS, f), `payload/lists/${f}`)
}
plain(join(ROOT, 'package', 'defaults', 'config.json'), 'payload/defaults/config.json')
copyFileSync(join(ROOT, 'package', 'install.sh'), join(PKG, 'install.sh'))
copyFileSync(join(ROOT, 'NOTICE'), join(PKG, 'NOTICE'))
plain(join(ROOT, 'NOTICE'), 'payload/NOTICE')

// --- ключ и подпись ---
const KEYF = args.includes('--key') ? args[args.indexOf('--key') + 1] : join(ROOT, '.tools', 'keys', 'release-ed25519.pem')
if (!existsSync(KEYF)) {
  mkdirSync(dirname(KEYF), { recursive: true })
  const { privateKey } = generateKeyPairSync('ed25519')
  writeFileSync(KEYF, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 })
}
const priv = createPrivateKey(readFileSync(KEYF))
const pubHex = createPublicKey(priv).export({ type: 'spki', format: 'der' }).subarray(-32).toString('hex')

// --- модуль sing-box: свой манифест и подпись тем же ключом; каталог — в основном пакете ---
const MODDIR = join(OUT, 'module-sing-box', 'module')
rmSync(dirname(MODDIR), { recursive: true, force: true })
mkdirSync(join(MODDIR, 'payload'), { recursive: true })
const mfiles = []
xz(SB_BIN, 'payload/sing-box.xz', 'sing-box', MODDIR, mfiles)
const mman = {
  name: 'mi-lumruri-mod-sing-box', version: SB_VER, target: 'rc06-1.1.38-aarch64', created: '2026-11-24', pubkey: pubHex, files: mfiles,
  data_bytes: mfiles.reduce((s, f) => s + f.size, 0), tmp_bytes: mfiles.reduce((s, f) => s + (f.unpacked_size ?? f.size), 0),
}
const mbytesMod = Buffer.from(JSON.stringify(mman, null, 1) + '\n')
writeFileSync(join(MODDIR, 'manifest.json'), mbytesMod)
writeFileSync(join(MODDIR, 'manifest.sig'), sign(null, mbytesMod, priv).toString('hex') + '\n')
const MOD_TAR = join(OUT, `mitt-mod-sing-box-${SB_VER}.tar`)
execFileSync(PY, ['-I', join(ROOT, 'tools', 'xzpack.py'), 'tar', MODDIR, MOD_TAR, 'module'])
const modTarBytes = readFileSync(MOD_TAR)
const catalog = { modules: [{
  name: 'sing-box', version: SB_VER, title: 'sing-box', protocols: ['VLESS', 'Hysteria2', 'Trojan', 'Shadowsocks'],
  kinds: ['vless', 'hysteria2', 'trojan', 'shadowsocks'], asset: basename(MOD_TAR), tar_sha256: sha(modTarBytes), tar_bytes: modTarBytes.length,
  unpacked_bytes: mman.tmp_bytes,
}] }
writeFileSync(join(PKG, 'payload', 'scripts', 'modules.json'), JSON.stringify(catalog, null, 1) + '\n')
{
  const b = readFileSync(join(PKG, 'payload', 'scripts', 'modules.json'))
  files.push({ path: 'payload/scripts/modules.json', sha256: sha(b), size: b.length, unpacked: null, unpacked_sha256: null, unpacked_size: null })
}
files.sort((a, b) => a.path.localeCompare(b.path))
const manifest = {
  name: 'mi-lumruri', version: VERSION, target: 'rc06-1.1.38-aarch64', created: '2026-11-18', pubkey: pubHex, files,
  data_bytes: files.reduce((s, f) => s + f.size, 0), tmp_bytes: files.reduce((s, f) => s + (f.unpacked_size ?? f.size), 0),
}
const mbytes = Buffer.from(JSON.stringify(manifest, null, 1) + '\n')
writeFileSync(join(PKG, 'manifest.json'), mbytes)
writeFileSync(join(PKG, 'manifest.sig'), sign(null, mbytes, priv).toString('hex') + '\n')
rmSync(tmp, { recursive: true, force: true })

const tarPath = join(OUT, `mi-lumruri-${VERSION}.tar`)
execFileSync(PY, ['-I', join(ROOT, 'tools', 'xzpack.py'), 'tar', PKG, tarPath])
// та же подписанная начинка под прежним именем: сценарий обновления 0.4.x ищет mi-trusttunnel-*.tar с каталогом mi-trusttunnel/
const compatPath = join(OUT, `mi-trusttunnel-${VERSION}.tar`)
execFileSync(PY, ['-I', join(ROOT, 'tools', 'xzpack.py'), 'tar', PKG, compatPath, 'mi-trusttunnel'])
const tarSize = statSync(tarPath).size
const n = (x) => x.toLocaleString('ru-RU')
const report = { version: VERSION, tar: tarPath, tar_bytes: tarSize, tar_sha256: sha(readFileSync(tarPath)), data_bytes: manifest.data_bytes, tmp_bytes: manifest.tmp_bytes,
  key_fingerprint: sha(Buffer.from(pubHex, 'hex')).slice(0, 16), budget: 20_000_000, headroom: 20_000_000 - tarSize,
  files: files.map((f) => ({ path: f.path, size: f.size, unpacked_size: f.unpacked_size })) }
writeFileSync(join(OUT, `report-${VERSION}.json`), JSON.stringify(report, null, 2) + '\n')
// install.py сверяет TAR с SHA256SUMS рядом с ним
writeFileSync(join(OUT, 'SHA256SUMS'), `${report.tar_sha256} *mi-lumruri-${VERSION}.tar\n${sha(readFileSync(compatPath))} *mi-trusttunnel-${VERSION}.tar\n${catalog.modules[0].tar_sha256} *${catalog.modules[0].asset}\n`)
console.log(`модуль: ${MOD_TAR} ${n(modTarBytes.length)} Б, в RAM ${n(mman.tmp_bytes)} Б`)
console.log(`пакет: ${tarPath} ${n(tarSize)} Б, sha256 ${report.tar_sha256}`)
console.log(`на /data: ${n(manifest.data_bytes)} Б; в /tmp после распаковки: ${n(manifest.tmp_bytes)} Б; бюджет 20 000 000 Б, запас ${n(report.headroom)} Б`)
console.log(`ключ релиза: ${report.key_fingerprint}`)
for (const f of files) console.log(`  ${f.path.padEnd(42)} ${n(f.size).padStart(12)}${f.unpacked_size ? ` → ${n(f.unpacked_size)}` : ''}`)
