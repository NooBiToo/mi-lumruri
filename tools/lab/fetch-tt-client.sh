#!/usr/bin/env bash
# Официальный клиент TrustTunnel v1.3.0 для x86_64 (лаборатория; в пакет идёт aarch64 из того же релиза).
# Архив закреплён по SHA-256; распакованный клиент — .tools/lab/bin/trusttunnel_client.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
D="$ROOT/.tools/lab/dl/tt"; B="$ROOT/.tools/lab/bin"; mkdir -p "$D" "$B"
VER=v1.3.0; A="trusttunnel_client-$VER-linux-x86_64.tar.gz"
WANT=99e764bb2c080f7a60c441b51ad75fa7ec00e6c8a80afe36030af37201ba32f7
if [ ! -s "$D/$A" ]; then
  curl -sSfL --proto '=https' -o "$D/$A.part" "https://github.com/TrustTunnel/TrustTunnelClient/releases/download/$VER/$A"
  mv "$D/$A.part" "$D/$A"
fi
echo "$WANT  $D/$A" | sha256sum -c --quiet
if [ ! -x "$B/trusttunnel_client" ] || ! "$B/trusttunnel_client" --version | grep -q "${VER#v}"; then
  tar -xzf "$D/$A" -C "$D"; cp "$D/trusttunnel_client-$VER-linux-x86_64/trusttunnel_client" "$B/"; chmod +x "$B/trusttunnel_client"
fi
"$B/trusttunnel_client" --version
