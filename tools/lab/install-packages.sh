#!/usr/bin/env bash
# Пакеты для лаборатории установщика: v1 (сборка), v2 и v5 (та же сборка, другая версия, ключ релиза),
# v3-tampered (подпись верна, файл изменён), v4-foreign (подписан чужим ключом). Результат — out/package/lab.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"; cd "$ROOT"
L=out/package/lab; rm -rf "$L"; mkdir -p "$L"
node tools/package.mjs --version 0.1.0-stage12 >/dev/null
cp -r out/package/mi-trusttunnel "$L/v1"
K=.tools/keys/release-ed25519.pem
node tools/lab/resign.mjs "$L/v1" "$L/v2" 0.1.1-stage12 "$K" >/dev/null
node tools/lab/resign.mjs "$L/v1" "$L/v5" 0.1.2-stage12 "$K" >/dev/null
node tools/lab/resign.mjs "$L/v1" "$L/v4-foreign" 0.1.3-stage12 --foreign >/dev/null
node tools/lab/resign.mjs "$L/v1" "$L/v3-tampered" 0.1.4-stage12 "$K" >/dev/null
python -I -c 'import sys;p=sys.argv[1];b=bytearray(open(p,"rb").read());b[len(b)//2]^=0x01;open(p,"wb").write(b)' "$L/v3-tampered/payload/engines/nfqws2.xz"
ls "$L"
