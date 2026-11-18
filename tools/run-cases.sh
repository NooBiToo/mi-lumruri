#!/usr/bin/env bash
# Прогон одного набора случаев через бинарник контроллера; <out>/<случай>.out = stdout + строка exit=<код>.
# Использование: run-cases.sh <out-dir> <бинарник> [префикс запуска, например qemu-aarch64]
set -uo pipefail
OUT="$1"; BIN="$2"; shift 2; RUN=("$@")
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
F="$ROOT/fixtures"
mkdir -p "$OUT"
c() { local name="$1"; shift; "${RUN[@]}" "$BIN" "$@" >"$OUT/$name.out" 2>/dev/null; printf '\nexit=%s\n' "$?" >>"$OUT/$name.out"; }
c version --version
c validate-valid validate "$F/config.valid.json"
c validate-broken validate "$F/invalid/config.broken.json"
c preview-tv preview "$F/config.valid.json" "$F/request.tv-video-trusttunnel.json"
c preview-unknown-refs preview "$F/config.valid.json" "$F/invalid/request.unknown-refs.json"
c preview-bad-cidr preview "$F/config.valid.json" "$F/invalid/request.bad-destination.json"
c preview-unknown-field preview "$F/config.valid.json" "$F/invalid/request.unknown-field.json"
# CGI как у uhttpd: переменные окружения + тело в stdin. MSYS2_ENV_CONV_EXCL — чтобы Git Bash не переписал PATH_INFO.
cgi() {
  local name="$1" method="$2" path="$3" body="${4:-}"
  local base=(env -i MSYS2_ENV_CONV_EXCL=PATH_INFO MI_TT_CONFIG="$F/config.valid.json" REQUEST_METHOD="$method" PATH_INFO="$path")
  if [ -n "$body" ]; then
    "${base[@]}" CONTENT_TYPE=application/json CONTENT_LENGTH="$(wc -c <"$body" | tr -d ' ')" "${RUN[@]}" "$BIN" cgi <"$body" >"$OUT/$name.out"
  else
    "${base[@]}" "${RUN[@]}" "$BIN" cgi </dev/null >"$OUT/$name.out"
  fi
  printf '\nexit=%s\n' "$?" >>"$OUT/$name.out"
}
# Этап 6: без входа CGI закрыт одинаково на обеих архитектурах (503 без настройки входа, 403 POST без Origin);
# вход и защищённые адреса ARM64 проверяются в лаборатории (tools/lab), на хосте — в controller/tests/stage6.rs.
cgi cgi-noauth-get-config GET /config
cgi cgi-noauth-preview-tv POST /preview "$F/request.tv-video-trusttunnel.json"
cgi cgi-noauth-preview-bad POST /preview "$F/invalid/request.unknown-refs.json"
cgi cgi-noauth-apply POST /apply "$F/request.tv-video-trusttunnel.json"
for f in "$OUT"/*.out; do
  printf '%-24s %-7s %s\n' "$(basename "$f" .out)" "$(tail -1 "$f")" "$(head -1 "$f" | tr -d '\r' | cut -c1-40)"
done
