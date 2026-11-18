#!/usr/bin/env bash
# zapret2 v1.0.7 (bol-van, MIT): nfqws2 для x86_64 (лаборатория) и aarch64 (комплект) с Lua-библиотеками.
# Архив проверяется по SHA-256 из API релиза (поле digest) и sha256sum.txt релиза; распаковка — в кэш .tools/lab/zapret2.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
D="$ROOT/.tools/lab/dl"; Z="$ROOT/.tools/lab/zapret2"; mkdir -p "$D"
VER=v1.0.7; A="zapret2-$VER-openwrt-embedded.tar.gz"
WANT=d2799bc8dffc03a21f977d3a0e2d8a8626105db630c03d9b99d5164980d5db16
if [ ! -s "$D/$A" ]; then
  curl -sSfL --proto '=https' -o "$D/$A.part" "https://github.com/bol-van/zapret2/releases/download/$VER/$A"
  mv "$D/$A.part" "$D/$A"
fi
echo "$WANT  $D/$A" | sha256sum -c --quiet
if [ ! -d "$Z" ]; then mkdir -p "$Z"; tar -xzf "$D/$A" -C "$Z"; fi
find "$Z" -name nfqws2 -type f | head -20
