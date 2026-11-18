#!/usr/bin/env bash
# Сервер Hysteria2 (apernet/hysteria, x86_64 Linux) для лаборатории этапа 7: кэш .tools/lab, повторно не качает.
# Хэш сверяется с hashes.txt того же релиза; после первой загрузки фиксируется в .tools/lab/dl/SHA256SUMS.hysteria.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
D="$ROOT/.tools/lab/dl"; B="$ROOT/.tools/lab/bin"; mkdir -p "$D" "$B"
VER=v2.13.0
BASE="https://github.com/apernet/hysteria/releases/download/app/$VER"
F="$D/hysteria-linux-amd64-$VER"
if [ ! -s "$F" ]; then
  curl -sSfL --proto '=https' -o "$F.part" "$BASE/hysteria-linux-amd64"
  curl -sSfL --proto '=https' -o "$D/hysteria-$VER-hashes.txt" "$BASE/hashes.txt"
  want="$(awk '$2 ~ /(^|\/)hysteria-linux-amd64$/ {print $1}' "$D/hysteria-$VER-hashes.txt")"
  got="$(sha256sum "$F.part" | cut -d' ' -f1)"
  [ -n "$want" ] && [ "$want" = "$got" ] || { echo "хэш hysteria не совпал: $got != $want"; rm -f "$F.part"; exit 1; }
  mv "$F.part" "$F"
  (cd "$D" && sha256sum "$(basename "$F")" >SHA256SUMS.hysteria)
fi
(cd "$D" && sha256sum -c --quiet SHA256SUMS.hysteria)
[ -x "$B/hysteria" ] && cmp -s "$F" "$B/hysteria" || { cp "$F" "$B/hysteria"; chmod +x "$B/hysteria"; }
cat "$D/SHA256SUMS.hysteria"
