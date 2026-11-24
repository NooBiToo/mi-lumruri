#!/usr/bin/env bash
# amneziawg-go x86_64 для лаборатории (клиент модуля и сервер в «VPN»): тот же закреплённый коммит, что у модуля
# пакета (tools/package.mjs), Go без CGO. Итог — .tools/lab/bin/amneziawg-go. Запуск — там, где есть go (Windows или CI).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"; cd "$ROOT"
REF=08fe3d33bbb116be09a6183d02609311b8b0c9e8; WANT=e33d8a62928222592df23b75356d79e0ea6b590943cbe3a4cfcdf9c357bb416e
A=".tools/lab/dl/amneziawg-go-$REF.tar.gz"; mkdir -p .tools/lab/dl .tools/lab/bin
[ -s "$A" ] || curl -sSfL --proto '=https' -o "$A" "https://codeload.github.com/amnezia-vpn/amneziawg-go/tar.gz/$REF"
[ "$(sha256sum "$A" | cut -c1-64)" = "$WANT" ] || { echo "SHA-256 архива amneziawg-go не совпал"; exit 1; }
T="$(mktemp -d)"; tar -xzf "$A" -C "$T"
G="$ROOT/.tools/go"
(cd "$T/amneziawg-go-$REF" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOPATH="$G" GOCACHE="$G/cache" GOMODCACHE="$G/mod" go build -trimpath -ldflags="-s -w -buildid=" -o "$ROOT/.tools/lab/bin/amneziawg-go" .)
rm -rf "$T"; ls -la .tools/lab/bin/amneziawg-go
