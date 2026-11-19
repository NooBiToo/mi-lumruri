#!/usr/bin/env bash
# Изолированные инструменты сборки в .tools/ проекта. PATH, реестр и профиль пользователя не меняются.
#  - Rust 1.100.0 (хост x86_64-pc-windows-gnu на Windows) + цель aarch64-unknown-linux-musl, линковка rust-lld;
#  - qemu-aarch64 (user-mode) из пакета Ubuntu qemu-user: только распакован в .tools/qemu/root, не установлен.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
T="$ROOT/.tools"; mkdir -p "$T/dl" "$T/qemu"
export RUSTUP_HOME="$T/rustup" CARGO_HOME="$T/cargo"
if [ ! -x "$CARGO_HOME/bin/cargo" ] && [ ! -x "$CARGO_HOME/bin/cargo.exe" ]; then
  case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) HOST=x86_64-pc-windows-gnu; EXE=rustup-init.exe ;;
    *) HOST="$(uname -m)-unknown-linux-gnu"; EXE=rustup-init ;;
  esac
  URL="https://static.rust-lang.org/rustup/dist/$HOST/$EXE"
  curl -sSfL --proto '=https' -o "$T/dl/$EXE" "$URL"
  echo "$(curl -sSfL --proto '=https' "$URL.sha256" | cut -d' ' -f1)  $T/dl/$EXE" | sha256sum -c -
  chmod +x "$T/dl/$EXE"
  "$T/dl/$EXE" -y --no-modify-path --no-update-default-toolchain --profile minimal --default-host "$HOST" \
    --default-toolchain 1.100.0 --target aarch64-unknown-linux-musl
fi
# rust-toolchain.toml в controller/ закрепляет 1.100.0 и цель ARM64
"$ROOT/tools/cargo.sh" --version

# qemu-aarch64 для запуска ARM64-бинарника на x86_64 (Linux/WSL, без sudo и без binfmt)
if [ ! -f "$T/qemu/root/usr/bin/qemu-aarch64" ]; then
  GET='set -e; cd "$1"; apt-get download qemu-user; for d in qemu-user_*.deb; do dpkg-deb -x "$d" root; done'
  if command -v apt-get >/dev/null; then bash -c "$GET" _ "$T/qemu"
  elif command -v wsl >/dev/null; then
    WT="/mnt/$(echo "${T:1:1}" | tr 'A-Z' 'a-z')${T:2}"
    MSYS_NO_PATHCONV=1 wsl -d Ubuntu -- bash -c "$GET" _ "$WT/qemu"
  else echo "qemu-aarch64 недоступен: шаг ARM64-запуска будет пропущен"; fi
fi

# сервер TrustTunnel для лабораторий (x86_64): trusttunnel_endpoint v1.1.0, кэш в .tools/lab
"$ROOT/tools/lab/fetch.sh"
