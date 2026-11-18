#!/usr/bin/env bash
# Лаборатория установщика (этап 12), часть Linux/WSL: одноразовые user+mount namespace, штатный BusyBox ARM64 под qemu.
# Пакеты готовит tools/lab/install-packages.sh (на хосте с node): PKGS=<каталог с v1, v2, v3-tampered, v4-foreign, v5>.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PKGS="${1:-$ROOT/out/package/lab}"; [ -d "$PKGS/v1" ] || { echo "нет пакетов: tools/lab/install-packages.sh"; exit 2; }
"$ROOT/tools/fw/prepare.sh" >/dev/null
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"; OUT="$ROOT/out/lab/$STAMP-install"; W="$(mktemp -d /tmp/mitt-inst.XXXXXX)"
mkdir -p "$OUT"; : >"$OUT/steps.jsonl"
set +e
ROOT="$ROOT" W="$W" OUT="$OUT" PKGS="$PKGS" unshare --user --map-root-user --mount --propagation private bash "$ROOT/tools/lab/lab-install-inner.sh"
RC=$?
set -e
rm -rf "$W"
python3 -I -X utf8 "$ROOT/tools/lab/check-install.py" "$OUT"; CRC=$?
echo "артефакты: $OUT"
[ $RC -eq 0 ] && [ $CRC -eq 0 ]
