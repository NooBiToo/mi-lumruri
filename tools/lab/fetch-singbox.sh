#!/usr/bin/env bash
# Официальный sing-box 1.14.4 для x86_64 (лаборатория: клиент модуля и серверы VLESS/Hysteria2 в «интернете»; в модуль
# пакета идёт linux-arm64 того же релиза). Архив закреплён по SHA-256; распакованный — .tools/lab/bin/sing-box.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
D="$ROOT/.tools/lab/dl/sing-box"; B="$ROOT/.tools/lab/bin"; mkdir -p "$D" "$B"
VER=1.14.4; A="sing-box-$VER-linux-amd64.tar.gz"
WANT=699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968
if [ ! -s "$D/$A" ]; then
  curl -sSfL --proto '=https' -o "$D/$A.part" "https://github.com/SagerNet/sing-box/releases/download/v$VER/$A"
  mv "$D/$A.part" "$D/$A"
fi
echo "$WANT  $D/$A" | sha256sum -c --quiet
if [ ! -x "$B/sing-box" ] || ! "$B/sing-box" version | grep -q "$VER"; then
  tar -xzf "$D/$A" -C "$D"; cp "$D/sing-box-$VER-linux-amd64/sing-box" "$B/"; chmod +x "$B/sing-box"
fi
"$B/sing-box" version | head -3
