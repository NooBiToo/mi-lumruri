#!/usr/bin/env bash
# Обновление из релизов GitHub (package/scripts/mitt-update.sh) на штатном BusyBox ash 1.25.1 (ARM64 из образа
# RC06 1.1.38 под qemu-user): заглушка curl вместо GitHub, заглушка install.sh внутри пакета, настоящий mi-tt-admin ARM64
# (sha256). Нужен `bash tools/cargo.sh build --locked --release --target aarch64-unknown-linux-musl`.
# Запуск — в WSL: bash tools/lab/test-update.sh
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
"$ROOT/tools/fw/prepare.sh" >/dev/null
F=/tmp/mitt-fw/rootfs; Q="$ROOT/.tools/qemu/root/usr/bin/qemu-aarch64"
ADM="$ROOT/controller/target/aarch64-unknown-linux-musl/release/mi-tt-admin"
[ -f "$ADM" ] || { echo "нет $ADM: bash tools/cargo.sh build --locked --release --target aarch64-unknown-linux-musl"; exit 2; }
W="$(mktemp -d /tmp/mitt-update.XXXXXX)"; [ -n "${KEEP:-}" ] && echo "каталог: $W" || trap 'rm -rf "$W"' EXIT
FAIL=0
ok() { echo "  ok   $*"; }
bad() { echo "  FAIL $*"; FAIL=1; }

SB="$W/stockbin"; mkdir -p "$SB"
for a in sh ash cat cp mv rm mkdir chmod sed awk grep head tail wc tr cut cmp date sleep kill basename dirname touch printf echo test expr tar; do
  if [ -e "$F/bin/$a" ] || [ -e "$F/usr/bin/$a" ] || [ -e "$F/sbin/$a" ] || [ -e "$F/usr/sbin/$a" ]; then
    printf '#!/bin/sh\nexec %s -L %s %s/bin/busybox %s "$@"\n' "$Q" "$F" "$F" "$a" >"$SB/$a"
  else echo "нет апплета $a в образе"; exit 2; fi
done
chmod +x "$SB"/*

# «GitHub»: API последнего релиза, пакет и SHA256SUMS из $LT/remote; сценарий — $LT/scenario (online|offline)
ST="$W/stub"; mkdir -p "$ST"
cat >"$ST/curl" <<'EOF'
#!/bin/sh
PATH=/usr/bin:/bin
echo "$*" >>"$LT/curl.log"
out=""; url=""
while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift;; -H|--max-time|--max-filesize|--proto) shift;; -*) ;; *) url="$1";; esac; shift; done
[ "$(cat "$LT/scenario")" = offline ] && { echo "curl: (6) Could not resolve host: api.github.com" >&2; exit 6; }
case "$url" in
  https://api.github.test/latest) cp "$LT/remote/latest.json" "$out";;
  https://github.test/dl/*) cp "$LT/remote/${url##*/}" "$out" || exit 22;;
  *) echo "curl: (22) 404 $url" >&2; exit 22;;
esac
EOF
chmod +x "$ST/curl"

# пакет: mi-trusttunnel/install.sh — заглушка, поведение по $LT/install (ok | foreign); аргументы пишет в $LT/install.args
mkpkg() { # mkpkg <каталог lt> <имя файла пакета>
  local d="$W/pkg.$$"; rm -rf "$d"; mkdir -p "$d/mi-trusttunnel"
  cat >"$d/mi-trusttunnel/install.sh" <<'EOF'
echo "$*" >"$LT/install.args"
case "$(cat "$LT/install")" in
  foreign)
    case "$*" in *--trust-key=e4a271890e5643ab*) ;; *)
      echo "mi-trusttunnel: ОТКАЗ: пакет подписан другим ключом: закреплён 1e1e65e7b11b50ca, у пакета e4a271890e5643ab. Если это ваш новый ключ, повторите с --trust-key=e4a271890e5643ab"; exit 3;; esac;;
esac
echo "$NEWVER" >"$MITT_ROOT/data/mi-trusttunnel/current.ver"; echo "mi-trusttunnel: установлен релиз $NEWVER"
EOF
  (cd "$d" && tar -cf "$1/remote/$2" mi-trusttunnel); rm -rf "$d"
  (cd "$1/remote" && sha256sum "$2" >SHA256SUMS)
}
latest() { # latest <каталог lt> <тег> <файл пакета>
  printf '{"url":"x","html_url":"https://github.test/rel/releases/tag/%s","tag_name":"%s","published_at":"2026-11-21T10:00:00Z","assets":[{"name":"%s","browser_download_url":"https://github.test/dl/%s"},{"name":"SHA256SUMS","browser_download_url":"https://github.test/dl/SHA256SUMS"}]}' \
    "$2" "$2" "$3" "$3" >"$1/remote/latest.json"
}
root() { # root <имя> <установленная версия>
  local d="$W/$1/root" lt="$W/$1/lt"
  mkdir -p "$d/data/mi-trusttunnel" "$d/tmp/mi-trusttunnel/bin" "$d/tmp/mi-trusttunnel/scripts" "$d/tmp/mi-trusttunnel/run" "$lt/remote"
  echo "$2" >"$d/data/mi-trusttunnel/current.ver"
  cp "$ROOT"/package/scripts/*.sh "$d/tmp/mi-trusttunnel/scripts/"
  printf '#!/bin/sh\nexec %s %s "$@"\n' "$Q" "$ADM" >"$d/tmp/mi-trusttunnel/bin/mi-tt-admin"; chmod +x "$d/tmp/mi-trusttunnel/bin/mi-tt-admin"
  printf '#!/bin/sh\necho "$1" >>"%s/boot.log"\n' "$lt" >"$d/data/mi-trusttunnel/mitt-boot.sh"
  echo online >"$lt/scenario"; echo ok >"$lt/install"
}
upd() { # upd <имя> <json заявки>
  local d="$W/$1/root"
  printf '%s' "$2" >"$d/tmp/mi-trusttunnel/run/update.request.run"
  timeout 300 env -i PATH="$SB" MITT_ROOT="$d" MITT_QUIET=1 MITT_CURL="$ST/curl" MITT_UPDATE_API=https://api.github.test/latest LT="$W/$1/lt" NEWVER="${NEWVER:-ci-0123456789ab}" \
    "$Q" -L "$F" "$F/bin/busybox" ash "$d/tmp/mi-trusttunnel/scripts/mitt-update.sh" >>"$W/$1/out" 2>&1
  echo "[$1] $2: код $?"
}
j() { python3 -I -c 'import json,sys
s=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$W/$1/root/tmp/mi-trusttunnel/run/update.json" "$2" 2>&1; }
check() { local r; r="$(j "$1" "$3")"; if [ "$r" = True ]; then ok "$1: $2"; else bad "$1: $2 → $r; update.json: $(cat "$W/$1/root/tmp/mi-trusttunnel/run/update.json" 2>/dev/null); вывод: $(tail -5 "$W/$1/out")"; fi; }
waitdone() { local i=0; while [ $i -lt 60 ] && [ "$(j "$1" 's["state"]')" != done ]; do sleep 1; i=$((i + 1)); done; }

echo "(а) проверка: установлена 0.3.3, в релизе v0.4.0 — есть новее"
root a 0.3.3; latest "$W/a/lt" v0.4.0 mi-trusttunnel-ci-0123456789ab.tar; mkpkg "$W/a/lt" mi-trusttunnel-ci-0123456789ab.tar
upd a '{"action":"check"}'
check a "ready, latest v0.4.0, available ci-0123456789ab, newer" 's["state"]=="ready" and s["latest"]=="v0.4.0" and s["available"]=="ci-0123456789ab" and s["newer"] is True and s["error"] is None'
check a "ссылка на страницу релиза и дата" 's["page"].endswith("/releases/tag/v0.4.0") and s["published"].startswith("2026-11-21")'
[ ! -e "$W/a/root/tmp/mi-trusttunnel/run/update.request.run" ] && ok "a: заявка снята" || bad "a: заявка не снята"

echo "(б) проверка: установлена та же сборка — не новее; установлена 0.5.0 — не новее"
root b ci-0123456789ab; latest "$W/b/lt" v0.4.0 mi-trusttunnel-ci-0123456789ab.tar; upd b '{"action":"check"}'
check b "та же сборка — newer false" 's["state"]=="ready" and s["newer"] is False'
echo 0.5.0 >"$W/b/root/data/mi-trusttunnel/current.ver"; upd b '{"action":"check"}'
check b "0.5.0 против v0.4.0 — newer false" 's["newer"] is False'
echo ci-ffffffffffff >"$W/b/root/data/mi-trusttunnel/current.ver"; upd b '{"action":"check"}'
check b "другая сборка CI — newer true" 's["newer"] is True'

echo "(в) установка: SHA-256 сверен, install.sh --no-start, перезапуск службы отдельным процессом"
upd a '{"action":"install","trust_official":false}'
waitdone a
check a "done, установлена ci-0123456789ab" 's["state"]=="done" and s["installed"]=="ci-0123456789ab"'
[ "$(cat "$W/a/lt/install.args")" = "install --no-start" ] && ok "a: install.sh install --no-start (без --trust-key)" || bad "a: аргументы install.sh: $(cat "$W/a/lt/install.args")"
[ "$(tr '\n' ' ' <"$W/a/lt/boot.log")" = "stop start " ] && ok "a: служба перезапущена (stop, start)" || bad "a: boot.log: $(cat "$W/a/lt/boot.log" 2>/dev/null)"
[ -z "$(ls -d "$W/a/root/tmp/mitt-update."* 2>/dev/null)" ] && ok "a: временный каталог удалён" || bad "a: остался временный каталог"

echo "(г) подменённый пакет: SHA-256 не совпал — установщик не запускается"
root g 0.3.3; latest "$W/g/lt" v0.4.0 mi-trusttunnel-ci-0123456789ab.tar; mkpkg "$W/g/lt" mi-trusttunnel-ci-0123456789ab.tar
printf 'x' >>"$W/g/lt/remote/mi-trusttunnel-ci-0123456789ab.tar"
upd g '{"action":"install"}'
check g "error: SHA-256 не совпал" 's["state"]=="error" and "SHA-256" in s["error"]'
[ ! -e "$W/g/lt/install.args" ] && ok "g: install.sh не запускался" || bad "g: install.sh запускался"
[ "$(cat "$W/g/root/data/mi-trusttunnel/current.ver")" = 0.3.3 ] && ok "g: current без изменений" || bad "g: current изменён"

echo "(д) другой ключ: ошибка с ключом пакета; с trust_official — установка с --trust-key официального ключа"
root k 0.3.3; latest "$W/k/lt" v0.4.0 mi-trusttunnel-ci-0123456789ab.tar; mkpkg "$W/k/lt" mi-trusttunnel-ci-0123456789ab.tar; echo foreign >"$W/k/lt/install"
upd k '{"action":"install","trust_official":false}'
check k "error: другой ключ, package_key = e4a271890e5643ab, official_key тот же" 's["state"]=="error" and "другим ключом" in s["error"] and s["package_key"]=="e4a271890e5643ab" and s["official_key"]=="e4a271890e5643ab"'
upd k '{"action":"install","trust_official":true}'
waitdone k
check k "с trust_official — done" 's["state"]=="done" and s["installed"]=="ci-0123456789ab"'
grep -q -- "--trust-key=e4a271890e5643ab" "$W/k/lt/install.args" && ok "k: install.sh получил --trust-key официального ключа" || bad "k: аргументы: $(cat "$W/k/lt/install.args")"

echo "(е) без сети: ошибка «GitHub не ответил»"
root o 0.3.3; echo offline >"$W/o/lt/scenario"; upd o '{"action":"check"}'
check o "error с причиной curl" 's["state"]=="error" and "GitHub не ответил" in s["error"] and "Could not resolve" in s["error"]'

echo "(ж) релиз без пакета — понятная ошибка"
root e 0.3.3; printf '{"tag_name":"v0.4.0","assets":[]}' >"$W/e/lt/remote/latest.json"; upd e '{"action":"check"}'
check e "error: нет пакета или SHA256SUMS" 's["state"]=="error" and "нет пакета" in s["error"]'

[ $FAIL -eq 0 ] && echo "ИТОГ: ПРОЙДЕНО" || { echo "ИТОГ: ЕСТЬ ОШИБКИ"; exit 1; }
