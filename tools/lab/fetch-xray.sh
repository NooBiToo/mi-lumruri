#!/usr/bin/env bash
# Сервер VLESS (Xray-core, x86_64 Linux) для лаборатории этапа 8: кэш .tools/lab, повторно не качает.
# SHA-256 архива сверяется с .dgst релиза; распаковка — python zipfile (без unzip).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
D="$ROOT/.tools/lab/dl"; B="$ROOT/.tools/lab/bin"; mkdir -p "$D" "$B"
VER="${XRAY_VERSION:-v26.10.31}"   # v26.6.1 — последняя версия, с которой работает REALITY клиента Mihomo v1.19.34
BASE="https://github.com/XTLS/Xray-core/releases/download/$VER"
Z="$D/Xray-linux-64-$VER.zip"
if [ ! -s "$Z" ]; then
  curl -sSfL --proto '=https' -o "$Z.part" "$BASE/Xray-linux-64.zip"
  curl -sSfL --proto '=https' -o "$D/Xray-linux-64-$VER.zip.dgst" "$BASE/Xray-linux-64.zip.dgst"
  want="$(grep -i 'SHA2-256' "$D/Xray-linux-64-$VER.zip.dgst" | head -1 | awk '{print $NF}')"
  got="$(sha256sum "$Z.part" | cut -d' ' -f1)"
  [ -n "$want" ] && [ "$want" = "$got" ] || { echo "хэш Xray не совпал: $got != $want"; rm -f "$Z.part"; exit 1; }
  mv "$Z.part" "$Z"; (cd "$D" && sha256sum "$(basename "$Z")" >"SHA256SUMS.xray-$VER")
fi
(cd "$D" && sha256sum -c --quiet "SHA256SUMS.xray-$VER")
if [ ! -x "$B/xray-$VER" ]; then
  python3 -I -c 'import sys,zipfile;z=zipfile.ZipFile(sys.argv[1]);open(sys.argv[2],"wb").write(z.read("xray"))' "$Z" "$B/xray-$VER"; chmod +x "$B/xray-$VER"
fi
cat "$D/SHA256SUMS.xray-$VER"
