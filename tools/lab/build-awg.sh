#!/usr/bin/env bash
# Peer AmneziaWG для лаборатории этапа 8: amneziawg-go v0.2.19 (MIT), собирается из модуля Go без CGO для linux/amd64.
# Нужен Go на хосте (GOTOOLCHAIN=local). Кэш модулей и сборки — в .tools/go; контрольные суммы модулей проверяет go (sum.golang.org).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
S="$ROOT/.tools/lab/src/awg"; mkdir -p "$S" "$ROOT/.tools/lab/bin"; cd "$S"
G="${GO:-go}"; command -v "$G" >/dev/null || G="/c/Program Files/Go/bin/go.exe"
export GOPATH="$ROOT/.tools/go" GOMODCACHE="$ROOT/.tools/go/mod" GOCACHE="$ROOT/.tools/go/cache" GOTOOLCHAIN=local GOFLAGS=-mod=mod CGO_ENABLED=0 GOOS=linux GOARCH=amd64
[ -f go.mod ] || "$G" mod init mitt-lab/awg >/dev/null
"$G" get github.com/amnezia-vpn/amneziawg-go@v0.2.19
"$G" build -trimpath -o "$ROOT/.tools/lab/bin/amneziawg-go" github.com/amnezia-vpn/amneziawg-go
sha256sum "$ROOT/.tools/lab/bin/amneziawg-go"
