#!/usr/bin/env bash
# Скачивает сетевые движки для стенда (x86_64 Linux) в кэш .tools/lab/dl; повторно не качает.
# Хэши фиксируются в .tools/lab/dl/SHA256SUMS после первой загрузки и сверяются при следующих запусках.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
D="$ROOT/.tools/lab/dl"; B="$ROOT/.tools/lab/bin"; mkdir -p "$D" "$B"
get() { local url="$1" f="$D/$(basename "$1")"; [ -s "$f" ] || curl -sSfL --proto '=https' -o "$f.part" "$url" && { [ -f "$f.part" ] && mv "$f.part" "$f" || true; }; }
MIHOMO=https://github.com/MetaCubeX/mihomo/releases/download/v1.19.34/mihomo-linux-amd64-v1-v1.19.34.gz
TT=https://github.com/TrustTunnel/TrustTunnel/releases/download/v1.1.0/trusttunnel-v1.1.0-linux-x86_64.tar.gz
get "$MIHOMO"; get "$TT"
cd "$D"
if [ -f SHA256SUMS ]; then sha256sum -c --quiet SHA256SUMS; else sha256sum *.gz >SHA256SUMS; fi
cat SHA256SUMS
[ -x "$B/mihomo" ] || { gzip -dc "$D/$(basename "$MIHOMO")" >"$B/mihomo"; chmod +x "$B/mihomo"; }
if [ ! -x "$B/trusttunnel_endpoint" ]; then
  rm -rf "$D/tt-x" && mkdir "$D/tt-x" && tar -xzf "$D/$(basename "$TT")" -C "$D/tt-x"
  find "$D/tt-x" -name trusttunnel_endpoint -type f -exec cp {} "$B/" \; ; chmod +x "$B/trusttunnel_endpoint"
fi
ls -l "$B"
