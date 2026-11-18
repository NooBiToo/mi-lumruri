#!/usr/bin/env bash
# Подготовка образа стоковой прошивки RC06 1.1.38 для статической проверки и запуска её ARM64-утилит под qemu-user.
# Скачивает (если нет в кэше .tools/fw) официальный образ, сверяет SHA-256 из ARCHITECTURE.md, разбирает HDR1 → UBI →
# тома kernel/ubi_rootfs, извлекает .config ядра (IKCONFIG) и распаковывает squashfs в /tmp/mitt-fw/rootfs
# (файловая система с учётом регистра: в rootfs есть xt_DSCP.ko и xt_dscp.ko). Ничего не запускает из образа.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FW="$ROOT/.tools/fw"; IMG="$FW/miwifi_rc06_firmware_65d1d_1.1.38.bin"
SHA=77d8bd587418310c12c32922f8af63994079baa12c3a4772891494631bd84d8e
URL=https://cdn.cnbj1.fds.api.mi-img.com/xiaoqiang/rom/rc06/miwifi_rc06_firmware_65d1d_1.1.38.bin
mkdir -p "$FW"
[ -s "$IMG" ] || { curl -sSfL --proto '=https' -o "$IMG.part" "$URL"; mv "$IMG.part" "$IMG"; }
echo "$SHA  $IMG" | sha256sum -c --quiet - || { echo "SHA-256 образа не совпал"; exit 1; }
if [ ! -s "$FW/vol/1_ubi_rootfs.bin" ]; then
  python3 -I - "$IMG" "$FW/root.ubi" <<'PY'
import struct, sys
f = open(sys.argv[1], "rb").read()
for o in struct.unpack_from("<8I", f, 0x10):
    if o and f[o + 16:o + 48].split(b"\0")[0] == b"root.ubi":
        size = struct.unpack_from("<I", f, o + 8)[0]
        open(sys.argv[2], "wb").write(f[o + 48:o + 48 + size])
PY
  python3 -I "$ROOT/tools/fw/ubi_extract.py" "$FW/root.ubi" "$FW/vol"
fi
[ -s "$FW/kernel/config" ] || python3 -I "$ROOT/tools/fw/fit_kernel.py" "$FW/vol/0_kernel.bin" "$FW/kernel"
if [ ! -x /tmp/mitt-fw/rootfs/bin/busybox ]; then
  if [ ! -x "$FW/sqfs/root/usr/bin/unsquashfs" ]; then
    mkdir -p "$FW/sqfs"; (cd "$FW/sqfs" && apt-get download squashfs-tools >/dev/null && for d in squashfs-tools_*.deb; do dpkg-deb -x "$d" root; done)
  fi
  rm -rf /tmp/mitt-fw; mkdir -p /tmp/mitt-fw
  # без root unsquashfs не создаёт узлы устройств (/dev/console) и выходит с ошибкой — это ожидаемо, проверяем результат
  "$FW/sqfs/root/usr/bin/unsquashfs" -no-progress -no-xattrs -d /tmp/mitt-fw/rootfs "$FW/vol/1_ubi_rootfs.bin" >/dev/null 2>&1 || true
  [ -x /tmp/mitt-fw/rootfs/bin/busybox ] && [ -x /tmp/mitt-fw/rootfs/usr/sbin/xtables-multi ] || { echo "rootfs не распакован"; exit 1; }
fi
echo "rootfs: /tmp/mitt-fw/rootfs ($(grep -o "ROM '[0-9.]*'" /tmp/mitt-fw/rootfs/usr/share/xiaoqiang/xiaoqiang_version)), kernel config: $FW/kernel/config"
