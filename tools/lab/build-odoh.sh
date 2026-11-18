#!/usr/bin/env bash
# ODoH target и relay для лаборатории этапа 10: cloudflare/odoh-server-go v0.1.4 (MIT), сборка из Go-модуля без CGO.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
S="$ROOT/.tools/lab/src/odoh"; mkdir -p "$S" "$ROOT/.tools/lab/bin"; cd "$S"
G="${GO:-go}"; command -v "$G" >/dev/null || G="/c/Program Files/Go/bin/go.exe"
export GOPATH="$ROOT/.tools/go" GOMODCACHE="$ROOT/.tools/go/mod" GOCACHE="$ROOT/.tools/go/cache" GOTOOLCHAIN=local GOFLAGS=-mod=mod CGO_ENABLED=0 GOOS=linux GOARCH=amd64
[ -f go.mod ] || "$G" mod init mitt-lab/odoh >/dev/null
"$G" get github.com/cloudflare/odoh-server-go@v0.1.4
"$G" build -trimpath -o "$ROOT/.tools/lab/bin/odoh-server" github.com/cloudflare/odoh-server-go
sha256sum "$ROOT/.tools/lab/bin/odoh-server"
