#!/usr/bin/env bash
# Официальный клиент TrustTunnel v1.1.12 для x86_64 (лаборатория; в пакет идёт aarch64 из того же релиза).
# Архив закреплён по SHA-256; распакованный клиент — .tools/lab/bin/trusttunnel_client.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
D="$ROOT/.tools/lab/dl/tt"; B="$ROOT/.tools/lab/bin"; mkdir -p "$D" "$B"
VER=v1.1.12; A="trusttunnel_client-$VER-linux-x86_64.tar.gz"
WANT=75b7df59351e26462487464de5f3462153e00195f2d40677872fb93a5b44c488
if [ ! -s "$D/$A" ]; then
  curl -sSfL --proto '=https' -o "$D/$A.part" "https://github.com/TrustTunnel/TrustTunnelClient/releases/download/$VER/$A"
  mv "$D/$A.part" "$D/$A"
fi
echo "$WANT  $D/$A" | sha256sum -c --quiet
if [ ! -x "$B/trusttunnel_client" ] || ! "$B/trusttunnel_client" --version | grep -q "${VER#v}"; then
  tar -xzf "$D/$A" -C "$D"; cp "$D/trusttunnel_client-$VER-linux-x86_64/trusttunnel_client" "$B/"; chmod +x "$B/trusttunnel_client"
fi
"$B/trusttunnel_client" --version
