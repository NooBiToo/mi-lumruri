// Сборка и проверка комплекта среза для BE7000 (без подписи и без установщика).
// 1) проверяет ELF контроллера: 64-bit, little-endian, AArch64, статический (нет PT_INTERP);
// 2) сжимает XZ (preset 6, CRC32 — как в ARCHITECTURE.md), распаковывает обратно и сравнивает SHA-256;
// 3) пишет manifest.json и детерминированный tar; 4) считает бюджет внутренней flash с движками.
// Запуск: node tools/bundle.mjs   (нужны xz и GNU tar в PATH; контроллер и панель собраны заранее)

import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { dirname, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const VERSION = JSON.parse(readFileSync(join(ROOT, 'panel', 'package.json'), 'utf8')).version
const NAME = `mi-trusttunnel-${VERSION}-stage4`
const BIN = join(ROOT, 'controller', 'target', 'aarch64-unknown-linux-musl', 'release', 'mi-tt-ctl')
const ADMIN = join(ROOT, 'controller', 'target', 'aarch64-unknown-linux-musl', 'release', 'mi-tt-admin')
const WWW = join(ROOT, 'panel', 'dist')
const OUT = join(ROOT, 'out', 'bundle')
const STAGE = join(OUT, NAME)
const XZ_ARGS = ['-6', '-T1', '--check=crc32', '-c']
const FIXED_MTIME = '2026-01-01 00:00:00Z'

// Бюджет: ориентир Enodia «около 20 МБ» для ПО на BE7000 (ARCHITECTURE.md). Берём строгое прочтение 20 000 000 байт.
const FLASH_BUDGET = 20_000_000
// Движки измерены ранее и записаны в ARCHITECTURE.md; здесь не пересобираются и не скачиваются.
const ENGINES_DOC = [
  { name: 'Mihomo v1.19.34 (xz)', bytes: 13_865_460, ram: 57_344_126 },
  { name: 'dnscrypt-proxy 2.1.20 (xz)', bytes: 3_343_324, ram: 11_993_248 },
  { name: 'nfqws2 zapret2 v1.0.7 (xz)', bytes: 317_336, ram: 318_196 },
]

// Этап 1 (VERTICAL-SLICE.md): для расчёта прироста размера.
// Этап 3 (захват по IP источника).
const STAGE3 = { ctl_raw: 634_848, ctl_xz: 267_680, admin_raw: 693_768, admin_xz: 289_824, tar: 604_160, tmp: 1_423_307 }
// Этап 2 (до разделения на mi-tt-ctl и mi-tt-admin).
const STAGE2 = { controller_raw: 613_776, controller_xz: 258_388, panel_raw: 94_691, panel_xz: 32_612, tar: 307_200, tmp: 708_467 }
const STAGE1 = { controller_raw: 536_528, controller_xz: 225_544, panel_raw: 90_864, panel_xz: 31_660, tar: 266_240, tmp: 627_392 }

const sha = (b) => createHash('sha256').update(b).digest('hex')
const fail = (m) => { console.error(`ОШИБКА: ${m}`); process.exit(1) }

function checkElf(buf) {
  if (buf.readUInt32BE(0) !== 0x7f454c46) fail('контроллер не ELF')
  const cls = buf[4], data = buf[5]
  if (cls !== 2) fail('ELF не 64-битный')
  if (data !== 1) fail('ELF не little-endian')
  const type = buf.readUInt16LE(16), machine = buf.readUInt16LE(18)
  if (machine !== 183) fail(`e_machine=${machine}, ожидался 183 (AArch64)`)
  const phoff = Number(buf.readBigUInt64LE(32)), phentsize = buf.readUInt16LE(54), phnum = buf.readUInt16LE(56)
  const kinds = []
  for (let i = 0; i < phnum; i++) kinds.push(buf.readUInt32LE(phoff + i * phentsize))
  if (kinds.includes(3)) fail('есть PT_INTERP — бинарник не статический')
  const osabi = buf[7]
  return { class: 'ELF64', endian: 'LE', machine: 'AArch64 (183)', type: type === 2 ? 'EXEC' : type === 3 ? 'DYN (static-pie)' : String(type), interp: 'нет', dynamic: kinds.includes(2), osabi }
}

function walk(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(join(dir, e.name)) : [join(dir, e.name)])).sort()
}

function xzRoundTrip(raw) {
  const packed = execFileSync('xz', XZ_ARGS, { input: raw, maxBuffer: 1 << 28 })
  const back = execFileSync('xz', ['-d', '-c'], { input: packed, maxBuffer: 1 << 28 })
  if (sha(back) !== sha(raw)) fail('XZ: распакованные байты не совпали с исходными')
  return packed
}

const bin = readFileSync(BIN)
const elf = checkElf(bin)
const adminBin = readFileSync(ADMIN)
const elfAdmin = checkElf(adminBin)
const wwwFiles = walk(WWW)
if (!wwwFiles.some((f) => f.endsWith('index.html'))) fail('panel/dist не собран')

rmSync(OUT, { recursive: true, force: true })
mkdirSync(join(STAGE, 'bin'), { recursive: true })

const files = []
function add(rel, raw) {
  const packed = xzRoundTrip(raw)
  const dst = join(STAGE, rel + '.xz')
  mkdirSync(dirname(dst), { recursive: true })
  writeFileSync(dst, packed)
  files.push({ path: rel + '.xz', size: packed.length, sha256: sha(packed), unpacked: { path: rel, size: raw.length, sha256: sha(raw) } })
}
add('bin/mi-tt-ctl', bin)
add('bin/mi-tt-admin', adminBin)
for (const f of wwwFiles) add('www/' + relative(WWW, f).split('\\').join('/'), readFileSync(f))

const manifest = {
  name: NAME,
  version: VERSION,
  target: 'aarch64-unknown-linux-musl (BE7000 RC06, прошивка 1.1.38)',
  compression: 'xz preset 6, CRC32; распаковка штатным BusyBox unxz — на роутере не проверялась',
  signature: null,
  scope: 'этап 4 (захват по MAC/порту моста через tc, метки, запрет IPv6 по метке): mi-tt-ctl (проверка, предпросмотр, сохранение, config.yaml Mihomo; CGI без привилегий) и mi-tt-admin (план, применение, статус, снятие собственных правил маршрутизации). Без установщика, движков и автозапуска',
  files,
}
writeFileSync(join(STAGE, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n')

const tarPath = join(OUT, `${NAME}.tar`)
execFileSync('tar', ['--sort=name', `--mtime=${FIXED_MTIME}`, '--owner=0', '--group=0', '--numeric-owner', '--mode=a=r,u+w,a+X', '--format=ustar', '-cf', relative(OUT, tarPath), NAME], { cwd: OUT })
const tar = readFileSync(tarPath)

const packedTotal = files.reduce((s, f) => s + f.size, 0) + statSync(join(STAGE, 'manifest.json')).size
const unpackedTotal = files.reduce((s, f) => s + f.unpacked.size, 0)
const enginesBytes = ENGINES_DOC.reduce((s, e) => s + e.bytes, 0)
const enginesRam = ENGINES_DOC.reduce((s, e) => s + e.ram, 0)
const total = tar.length + enginesBytes
const report = {
  elf,
  elf_admin: elfAdmin,
  controller: { raw: bin.length, raw_sha256: sha(bin), xz: files[0].size, xz_sha256: files[0].sha256 },
  admin: { raw: adminBin.length, raw_sha256: sha(adminBin), xz: files[1].size, xz_sha256: files[1].sha256 },
  panel: { files: wwwFiles.length, raw: unpackedTotal - bin.length - adminBin.length, xz: packedTotal - files[0].size - files[1].size - statSync(join(STAGE, 'manifest.json')).size },
  bundle: { files_plus_manifest: packedTotal, tar: tar.length, tar_sha256: sha(tar), tmp_after_unpack: unpackedTotal },
  budget: {
    flash_budget: FLASH_BUDGET,
    engines_from_architecture_md: enginesBytes,
    slice_tar: tar.length,
    total,
    headroom: FLASH_BUDGET - total,
    slice_share_percent: +((tar.length / FLASH_BUDGET) * 100).toFixed(2),
    fits: total <= FLASH_BUDGET,
    ram_unpacked_engines_plus_slice: enginesRam + unpackedTotal,
  },
}
report.growth_vs_stage1 = {
  controller_raw: bin.length - STAGE1.controller_raw,
  controller_xz: files[0].size - STAGE1.controller_xz,
  panel_raw: report.panel.raw - STAGE1.panel_raw,
  panel_xz: report.panel.xz - STAGE1.panel_xz,
  tar: tar.length - STAGE1.tar,
  tmp_after_unpack: unpackedTotal - STAGE1.tmp,
}
report.growth_vs_stage3 = {
  ctl_raw: bin.length - STAGE3.ctl_raw,
  ctl_xz: files[0].size - STAGE3.ctl_xz,
  admin_raw: adminBin.length - STAGE3.admin_raw,
  admin_xz: files[1].size - STAGE3.admin_xz,
  tar: tar.length - STAGE3.tar,
  tmp_after_unpack: unpackedTotal - STAGE3.tmp,
}
report.growth_vs_stage2 = {
  controller_raw: bin.length - STAGE2.controller_raw,
  controller_xz: files[0].size - STAGE2.controller_xz,
  admin_raw: adminBin.length,
  admin_xz: files[1].size,
  panel_raw: report.panel.raw - STAGE2.panel_raw,
  panel_xz: report.panel.xz - STAGE2.panel_xz,
  tar: tar.length - STAGE2.tar,
  tmp_after_unpack: unpackedTotal - STAGE2.tmp,
}
writeFileSync(join(OUT, 'report.json'), JSON.stringify(report, null, 2) + '\n')

const n = (x) => x.toLocaleString('ru-RU')
console.log(`ELF: ${elf.class} ${elf.endian} ${elf.machine} ${elf.type}, PT_INTERP: ${elf.interp}`)
console.log(`ELF mi-tt-admin: ${elfAdmin.class} ${elfAdmin.endian} ${elfAdmin.machine} ${elfAdmin.type}, PT_INTERP: ${elfAdmin.interp}`)
console.log(`mi-tt-ctl: ${n(bin.length)} Б → xz ${n(files[0].size)} Б; mi-tt-admin: ${n(adminBin.length)} Б → xz ${n(files[1].size)} Б (round-trip SHA-256 совпал)`)
console.log(`панель: ${wwwFiles.length} файла, ${n(report.panel.raw)} Б → xz ${n(report.panel.xz)} Б`)
console.log(`комплект: ${relative(ROOT, tarPath)} ${n(tar.length)} Б, sha256 ${report.bundle.tar_sha256}`)
console.log(`в /tmp после распаковки: ${n(unpackedTotal)} Б`)
console.log(`бюджет flash ${n(FLASH_BUDGET)} Б: движки (по ARCHITECTURE.md) ${n(enginesBytes)} + срез ${n(tar.length)} = ${n(total)} Б; запас ${n(FLASH_BUDGET - total)} Б → ${report.budget.fits ? 'ПОМЕЩАЕТСЯ' : 'НЕ ПОМЕЩАЕТСЯ'}`)
const g = report.growth_vs_stage1
const sg = (x) => (x >= 0 ? '+' : '') + n(x)
console.log(`прирост к этапу 1: контроллер ${sg(g.controller_raw)} Б (xz ${sg(g.controller_xz)}), панель ${sg(g.panel_raw)} Б (xz ${sg(g.panel_xz)}), tar ${sg(g.tar)} Б, /tmp ${sg(g.tmp_after_unpack)} Б`)
const g2 = report.growth_vs_stage2
console.log(`прирост к этапу 2: mi-tt-ctl ${sg(g2.controller_raw)} Б (xz ${sg(g2.controller_xz)}), новый mi-tt-admin +${n(g2.admin_raw)} Б (xz +${n(g2.admin_xz)}), панель ${sg(g2.panel_raw)} Б, tar ${sg(g2.tar)} Б, /tmp ${sg(g2.tmp_after_unpack)} Б`)
const g3 = report.growth_vs_stage3
console.log(`прирост к этапу 3: mi-tt-ctl ${sg(g3.ctl_raw)} Б (xz ${sg(g3.ctl_xz)}), mi-tt-admin ${sg(g3.admin_raw)} Б (xz ${sg(g3.admin_xz)}), tar ${sg(g3.tar)} Б, /tmp ${sg(g3.tmp_after_unpack)} Б`)
if (!report.budget.fits) process.exit(1)
