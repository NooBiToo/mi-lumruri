#!/usr/bin/env bash
# Пакеты для лаборатории установщика: v1 (сборка), v2 и v5 (та же сборка, другая версия, ключ релиза),
# v3-tampered (подпись верна, файл изменён), v4-foreign (подписан чужим ключом), old040 — настоящий релиз v0.4.0
# (прежняя раскладка /data/mi-trusttunnel, ключ CI) для проверки переноса. Результат — out/package/lab.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"; cd "$ROOT"
L=out/package/lab; rm -rf "$L"; mkdir -p "$L"
node tools/package.mjs --version 0.1.0-stage12 >/dev/null
cp -r out/package/mi-lumruri "$L/v1"
# пакет лаборатории загрузки: модуль sing-box с x86_64-программой (серверы модуля запускаются в namespace)
node tools/package.mjs --version 0.1.0-stage12 --singbox-bin .tools/lab/bin/sing-box --out out/package/boot >/dev/null
K=.tools/keys/release-ed25519.pem
node tools/lab/resign.mjs "$L/v1" "$L/v2" 0.1.1-stage12 "$K" >/dev/null
node tools/lab/resign.mjs "$L/v1" "$L/v5" 0.1.2-stage12 "$K" >/dev/null
node tools/lab/resign.mjs "$L/v1" "$L/v4-foreign" 0.1.3-stage12 --foreign >/dev/null
node tools/lab/resign.mjs "$L/v1" "$L/v3-tampered" 0.1.4-stage12 "$K" >/dev/null
python -I -c 'import sys;p=sys.argv[1];b=bytearray(open(p,"rb").read());b[len(b)//2]^=0x01;open(p,"wb").write(b)' "$L/v3-tampered/payload/engines/nfqws2.xz"
# релиз v0.4.0 с GitHub (кэш .tools/old), SHA-256 по SHA256SUMS релиза
O=.tools/old/v0.4.0; T=mi-trusttunnel-ci-05a1131e08df.tar
[ -f "$O/$T" ] || { mkdir -p "$O"; gh release download v0.4.0 -R NooBiToo/mi-lumruri -D "$O" -p "$T" -p SHA256SUMS --clobber; }
(cd "$O" && grep " \*\?$T\$" SHA256SUMS | sha256sum -c - >/dev/null)
mkdir -p "$L/old040.x" && tar -xf "$O/$T" -C "$L/old040.x" && mv "$L/old040.x/mi-trusttunnel" "$L/old040" && rmdir "$L/old040.x"
ls "$L"
