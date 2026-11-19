#!/usr/bin/env bash
# Скачивает сервер TrustTunnel (trusttunnel_endpoint v1.1.0, x86_64 Linux) для лаборатории в кэш .tools/lab/dl;
# повторно не качает. Архив закреплён по SHA-256; распакованный сервер — .tools/lab/bin/trusttunnel_endpoint.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
D="$ROOT/.tools/lab/dl"; B="$ROOT/.tools/lab/bin"; mkdir -p "$D" "$B"
A=trusttunnel-v1.1.0-linux-x86_64.tar.gz
WANT=91c2ea3db7416a01b5258a4c047ec22890490bc55e1b194206031aa75144f0e7
if [ ! -s "$D/$A" ]; then
  curl -sSfL --proto '=https' -o "$D/$A.part" "https://github.com/TrustTunnel/TrustTunnel/releases/download/v1.1.0/$A"
  mv "$D/$A.part" "$D/$A"
fi
echo "$WANT  $D/$A" | sha256sum -c --quiet
if [ ! -x "$B/trusttunnel_endpoint" ]; then
  rm -rf "$D/tt-x" && mkdir "$D/tt-x" && tar -xzf "$D/$A" -C "$D/tt-x"
  find "$D/tt-x" -name trusttunnel_endpoint -type f -exec cp {} "$B/" \; ; chmod +x "$B/trusttunnel_endpoint"
fi
ls -l "$B/trusttunnel_endpoint"
