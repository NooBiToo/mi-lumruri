#!/usr/bin/env bash
# Бисекция совместимости REALITY Mihomo v1.19.34 ↔ разные версии Xray (только loopback в одноразовом netns).
set -u
R="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"; D=$R/.tools/lab/dl; mkdir -p "$D"
for v in "$@"; do
  f="$D/Xray-linux-64-$v.zip"
  [ -s "$f" ] || curl -sSfL --proto '=https' -o "$f" "https://github.com/XTLS/Xray-core/releases/download/$v/Xray-linux-64.zip"
  mkdir -p "/tmp/xr-$v"
  python3 -I -c 'import sys,zipfile;open(sys.argv[2],"wb").write(zipfile.ZipFile(sys.argv[1]).read("xray"))' "$f" "/tmp/xr-$v/xray"; chmod +x "/tmp/xr-$v/xray"
  echo "== Xray $v"
  # оригинальный probe с бинарником этой версии (без временной копии сценария)
  XRAY="/tmp/xr-$v/xray" TARGET=go MINVER="${MINVER:-}" unshare --user --map-root-user --net bash "$R/tools/lab/reality/reality-probe.sh" 2>&1 | grep -E "→|accepted|x25519" | head -5
done
