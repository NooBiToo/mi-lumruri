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

# пакет: <mi-lumruri|mi-trusttunnel>/install.sh (каталог — по имени файла) — заглушка, поведение по $LT/install (ok | foreign); аргументы пишет в $LT/install.args
mkpkg() { # mkpkg <каталог lt> <имя файла пакета>
  local d="$W/pkg.$$" n="${2%%-ci-*}"; rm -rf "$d"; mkdir -p "$d/$n"
  cat >"$d/$n/install.sh" <<'EOF'
if [ "$1" = rollback ]; then cat "$LT/oldver" >"$MITT_ROOT/data/mi-lumruri/current.ver"; echo rollback >>"$LT/boot.log"; exit 0; fi
echo "$*" >"$LT/install.args"; basename "$(dirname "$0")" >"$LT/install.dir"
case "$(cat "$LT/install")" in
  foreign)
    case "$*" in *--trust-key=e4a271890e5643ab*) ;; *)
      echo "mi-lumruri: ОТКАЗ: пакет подписан другим ключом: закреплён 1e1e65e7b11b50ca, у пакета e4a271890e5643ab. Если это ваш новый ключ, повторите с --trust-key=e4a271890e5643ab"; exit 3;; esac;;
esac
echo "$NEWVER" >"$MITT_ROOT/data/mi-lumruri/current.ver"; echo "mi-lumruri: установлен релиз $NEWVER"
EOF
  (cd "$d" && tar -cf "$1/remote/$2" "$n"); rm -rf "$d"
  (cd "$1/remote" && sha256sum "$2" >>SHA256SUMS)
}
latest() { # latest <каталог lt> <тег> <файл пакета>
  printf '{"url":"x","html_url":"https://github.test/rel/releases/tag/%s","tag_name":"%s","published_at":"2026-11-21T10:00:00Z","assets":[{"name":"%s","browser_download_url":"https://github.test/dl/%s"},{"name":"SHA256SUMS","browser_download_url":"https://github.test/dl/SHA256SUMS"}]}' \
    "$2" "$2" "$3" "$3" >"$1/remote/latest.json"
}
root() { # root <имя> <установленная версия>
  local d="$W/$1/root" lt="$W/$1/lt"
  mkdir -p "$d/data/mi-lumruri/etc" "$d/tmp/mi-lumruri/bin" "$d/tmp/mi-lumruri/scripts" "$d/tmp/mi-lumruri/run" "$lt/remote"
  echo "$2" >"$d/data/mi-lumruri/current.ver"
  cp "$ROOT"/package/scripts/*.sh "$d/tmp/mi-lumruri/scripts/"
  printf '#!/bin/sh\nexec %s %s "$@"\n' "$Q" "$ADM" >"$d/tmp/mi-lumruri/bin/mi-tt-admin"; chmod +x "$d/tmp/mi-lumruri/bin/mi-tt-admin"
  # загрузчик-заглушка: пишет stop/start в boot.log; start — status.json по $lt/health (ok | nginx | apply)
  cat >"$d/data/mi-lumruri/mitt-boot.sh" <<EOF
#!/bin/sh
echo "\$1" >>"$lt/boot.log"
[ "\$1" = start ] || exit 0
v="\$(cat "\$MITT_ROOT/data/mi-lumruri/current.ver")"; now="\$(date +%s)"
eng='"service":true,"nginx":true,"uhttpd":true'; ap="{\"tag\":\"start\",\"exit\":0,\"at\":\$now,\"error\":null}"
case "\$(cat "$lt/health" 2>/dev/null)" in
  nginx) eng='"service":true,"nginx":false,"uhttpd":true';;
  apply) ap="{\"tag\":\"start\",\"exit\":1,\"at\":\$now,\"error\":\"нет маршрута в туннель\"}";;
esac
printf '{"at":%s,"release":"%s","protection":"full","endpoint":"primary","engines":{%s},"last_apply":null,"render":null,"apply":%s}\n' "\$now" "\$v" "\$eng" "\$ap" >"\$MITT_ROOT/tmp/mi-lumruri/run/status.json"
EOF
  echo "$2" >"$lt/oldver"
  echo online >"$lt/scenario"; echo ok >"$lt/install"
}
upd() { # upd <имя> <json заявки>
  local d="$W/$1/root"
  printf '%s' "$2" >"$d/tmp/mi-lumruri/run/update.request.run"
  timeout 300 env -i PATH="$SB" MITT_ROOT="$d" MITT_QUIET=1 MITT_CURL="$ST/curl" MITT_UPDATE_API=https://api.github.test/latest MITT_UPDATE_HEALTH_WAIT="${HW:-20}" LT="$W/$1/lt" NEWVER="${NEWVER:-ci-0123456789ab}" \
    "$Q" -L "$F" "$F/bin/busybox" ash "$d/tmp/mi-lumruri/scripts/mitt-update.sh" >>"$W/$1/out" 2>&1
  echo "[$1] $2: код $?"
}
j() { python3 -I -c 'import json,sys
s=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$W/$1/root/tmp/mi-lumruri/run/update.json" "$2" 2>&1; }
check() { local r; r="$(j "$1" "$3")"; if [ "$r" = True ]; then ok "$1: $2"; else bad "$1: $2 → $r; update.json: $(cat "$W/$1/root/tmp/mi-lumruri/run/update.json" 2>/dev/null); вывод: $(tail -5 "$W/$1/out")"; fi; }
waitdone() { local i=0; while [ $i -lt 60 ] && [ "$(j "$1" 's["state"]')" != done ]; do sleep 1; i=$((i + 1)); done; }

echo "(а) проверка: установлена 0.3.3, в релизе v0.4.0 — есть новее"
root a 0.3.3; latest "$W/a/lt" v0.4.0 mi-lumruri-ci-0123456789ab.tar; mkpkg "$W/a/lt" mi-lumruri-ci-0123456789ab.tar
upd a '{"action":"check"}'
check a "ready, latest v0.4.0, available ci-0123456789ab, newer" 's["state"]=="ready" and s["latest"]=="v0.4.0" and s["available"]=="ci-0123456789ab" and s["newer"] is True and s["error"] is None'
check a "ссылка на страницу релиза и дата" 's["page"].endswith("/releases/tag/v0.4.0") and s["published"].startswith("2026-11-21")'
[ ! -e "$W/a/root/tmp/mi-lumruri/run/update.request.run" ] && ok "a: заявка снята" || bad "a: заявка не снята"

echo "(б) проверка: установлена та же сборка — не новее; установлена 0.5.0 — не новее"
root b ci-0123456789ab; latest "$W/b/lt" v0.4.0 mi-lumruri-ci-0123456789ab.tar; upd b '{"action":"check"}'
check b "та же сборка — newer false" 's["state"]=="ready" and s["newer"] is False'
echo 0.5.0 >"$W/b/root/data/mi-lumruri/current.ver"; upd b '{"action":"check"}'
check b "0.5.0 против v0.4.0 — newer false" 's["newer"] is False'
echo ci-ffffffffffff >"$W/b/root/data/mi-lumruri/current.ver"; upd b '{"action":"check"}'
check b "другая сборка CI — newer true" 's["newer"] is True'

echo "(в) установка: SHA-256 сверен, install.sh --no-start, перезапуск службы отдельным процессом"
upd a '{"action":"install","trust_official":false}'
waitdone a
check a "done, установлена ci-0123456789ab" 's["state"]=="done" and s["installed"]=="ci-0123456789ab"'
[ "$(cat "$W/a/lt/install.args")" = "install --no-start" ] && ok "a: install.sh install --no-start (без --trust-key)" || bad "a: аргументы install.sh: $(cat "$W/a/lt/install.args")"
[ "$(tr '\n' ' ' <"$W/a/lt/boot.log")" = "stop start " ] && ok "a: служба перезапущена (stop, start)" || bad "a: boot.log: $(cat "$W/a/lt/boot.log" 2>/dev/null)"
[ -z "$(ls -d "$W/a/root/tmp/mitt-update."* 2>/dev/null)" ] && ok "a: временный каталог удалён" || bad "a: остался временный каталог"

echo "(г) подменённый пакет: SHA-256 не совпал — установщик не запускается"
root g 0.3.3; latest "$W/g/lt" v0.4.0 mi-lumruri-ci-0123456789ab.tar; mkpkg "$W/g/lt" mi-lumruri-ci-0123456789ab.tar
printf 'x' >>"$W/g/lt/remote/mi-lumruri-ci-0123456789ab.tar"
upd g '{"action":"install"}'
check g "error: SHA-256 не совпал" 's["state"]=="error" and "SHA-256" in s["error"]'
[ ! -e "$W/g/lt/install.args" ] && ok "g: install.sh не запускался" || bad "g: install.sh запускался"
[ "$(cat "$W/g/root/data/mi-lumruri/current.ver")" = 0.3.3 ] && ok "g: current без изменений" || bad "g: current изменён"

echo "(д) другой ключ: ошибка с ключом пакета; с trust_official — установка с --trust-key официального ключа"
root k 0.3.3; latest "$W/k/lt" v0.4.0 mi-lumruri-ci-0123456789ab.tar; mkpkg "$W/k/lt" mi-lumruri-ci-0123456789ab.tar; echo foreign >"$W/k/lt/install"
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

echo "(з) релиз 0.5+: два пакета (mi-lumruri и совместимый mi-trusttunnel) — берётся mi-lumruri"
root n 0.4.0; mkpkg "$W/n/lt" mi-lumruri-ci-0123456789ab.tar; mkpkg "$W/n/lt" mi-trusttunnel-ci-0123456789ab.tar
printf '{"html_url":"https://github.test/rel/releases/tag/v0.5.0","tag_name":"v0.5.0","published_at":"2026-11-21T10:00:00Z","assets":[{"name":"mi-trusttunnel-ci-0123456789ab.tar","browser_download_url":"https://github.test/dl/mi-trusttunnel-ci-0123456789ab.tar"},{"name":"mi-lumruri-ci-0123456789ab.tar","browser_download_url":"https://github.test/dl/mi-lumruri-ci-0123456789ab.tar"},{"name":"SHA256SUMS","browser_download_url":"https://github.test/dl/SHA256SUMS"}]}' >"$W/n/lt/remote/latest.json"
upd n '{"action":"install"}'
waitdone n
check n "done, установлена ci-0123456789ab" 's["state"]=="done" and s["installed"]=="ci-0123456789ab"'
[ "$(cat "$W/n/lt/install.dir")" = mi-lumruri ] && ok "n: запущен mi-lumruri/install.sh" || bad "n: каталог пакета: $(cat "$W/n/lt/install.dir" 2>/dev/null)"

echo "(и) релиз до 0.5: только mi-trusttunnel-*.tar — тоже устанавливается"
root p 0.3.3; latest "$W/p/lt" v0.4.0 mi-trusttunnel-ci-0123456789ab.tar; mkpkg "$W/p/lt" mi-trusttunnel-ci-0123456789ab.tar
upd p '{"action":"install"}'
waitdone p
check p "done, установлена ci-0123456789ab" 's["state"]=="done" and s["installed"]=="ci-0123456789ab"'
[ "$(cat "$W/p/lt/install.dir")" = mi-trusttunnel ] && ok "p: запущен mi-trusttunnel/install.sh" || bad "p: каталог пакета: $(cat "$W/p/lt/install.dir" 2>/dev/null)"

# до обновления настройки применялись: status.json с apply.exit 0
baseline() { printf '{"at":1,"release":"%s","protection":"full","engines":{"service":true},"apply":{"tag":"start","exit":0,"at":1,"error":null}}\n' "$2" >"$W/$1/root/tmp/mi-lumruri/run/status.json"; }
inst_case() { # inst_case <имя> <health> [baseline]
  root "$1" 0.5.0; latest "$W/$1/lt" v0.6.0 mi-lumruri-ci-0123456789ab.tar; mkpkg "$W/$1/lt" mi-lumruri-ci-0123456789ab.tar
  echo "$2" >"$W/$1/lt/health"; [ -n "${3:-}" ] && baseline "$1" 0.5.0
  upd "$1" '{"action":"install"}'; waitdone "$1"; local i=0
  while [ $i -lt 60 ] && case "$(j "$1" 's["state"]')" in done|error) false;; *) true;; esac; do sleep 1; i=$((i + 1)); done
}

echo "(к) проверка после обновления: новая версия работает и применила настройки — done"
inst_case q ok base
check q "done, установлена ci-0123456789ab, без отката" 's["state"]=="done" and s["installed"]=="ci-0123456789ab" and s["rolled_back"] is False'
[ "$(tr '\n' ' ' <"$W/q/lt/boot.log")" = "stop start " ] && ok "q: только stop, start" || bad "q: boot.log: $(cat "$W/q/lt/boot.log")"

echo "(л) не работает панель (nginx) — откат на прежнюю версию"
inst_case r nginx
check r "error, rolled_back, failed = новая, installed = 0.5.0, причина nginx" 's["state"]=="error" and s["rolled_back"] is True and s["failed"]=="ci-0123456789ab" and s["installed"]=="0.5.0" and "nginx" in s["error"]'
[ "$(cat "$W/r/root/data/mi-lumruri/current.ver")" = 0.5.0 ] && ok "r: current = 0.5.0" || bad "r: current $(cat "$W/r/root/data/mi-lumruri/current.ver")"
grep -q rollback "$W/r/lt/boot.log" && ok "r: install.sh rollback выполнен" || bad "r: отката не было: $(cat "$W/r/lt/boot.log")"
[ -z "$(ls -d "$W/r/root/tmp/mitt-update."* 2>/dev/null)" ] && ok "r: временный каталог удалён" || bad "r: остался временный каталог"

echo "(м) до обновления настройки применялись, после — нет: откат с причиной"
inst_case s apply base
check s "error, rolled_back, причина из apply" 's["state"]=="error" and s["rolled_back"] is True and "настройки не применились" in s["error"] and "нет маршрута" in s["error"]'

echo "(н) до обновления настройки не применялись — их сбой после обновления не повод для отката"
inst_case u apply
check u "done без отката" 's["state"]=="done" and s["rolled_back"] is False'

echo "(о) проверка по расписанию (auto): новая версия — итог ready и одно уведомление на тег"
root v 0.5.0; latest "$W/v/lt" v0.6.0 mi-lumruri-ci-0123456789ab.tar
upd v '{"action":"check","auto":true}'
check v "ready, newer" 's["state"]=="ready" and s["newer"] is True'
NQ="$W/v/root/tmp/mi-lumruri/run/notify.queue"
[ "$(grep -c 'update_available' "$NQ" 2>/dev/null)" = 1 ] && grep -q 'v0.6.0' "$NQ" && ok "v: уведомление update_available v0.6.0" || bad "v: очередь: $(cat "$NQ" 2>/dev/null)"
upd v '{"action":"check","auto":true}'
[ "$(grep -c 'update_available' "$NQ")" = 1 ] && ok "v: повторная проверка того же тега — без второго уведомления" || bad "v: очередь: $(cat "$NQ")"
upd v '{"action":"check"}'
[ "$(grep -c 'update_available' "$NQ")" = 1 ] && ok "v: проверка кнопкой — без уведомления" || bad "v: очередь: $(cat "$NQ")"

echo "(п) проверка по расписанию без сети: прежний итог в панели не затирается"
echo offline >"$W/v/lt/scenario"; upd v '{"action":"check","auto":true}'
check v "итог прежний (ready, newer)" 's["state"]=="ready" and s["newer"] is True and s["error"] is None'

echo "(р) расписание: вручную — не проверять; первая проверка — через 10 минут после запуска; затем раз в период"
due() { timeout 60 env -i PATH="$SB" MITT_ROOT="$W/v/root" MITT_QUIET=1 "$Q" -L "$F" "$F/bin/busybox" ash -c \
  ". \"$W/v/root/tmp/mi-lumruri/scripts/mitt-lib.sh\"; $1; update_check_due && echo due || echo wait"; }
mkdir -p "$W/v/root/tmp/mi-lumruri/run/render" "$W/v/root/data/mi-lumruri/etc"; E="$W/v/root/data/mi-lumruri/etc/update-check.last"
printf 'lists=86400\nzapret_check=0\nupdate_check=0\n' >"$W/v/root/tmp/mi-lumruri/run/render/schedule"; rm -f "$E"
[ "$(due :)" = wait ] && ok "v: update_check=0 — вручную" || bad "v: вручную, но due"
printf 'lists=86400\nzapret_check=0\nupdate_check=86400\n' >"$W/v/root/tmp/mi-lumruri/run/render/schedule"
[ "$(due :)" = wait ] && [ -s "$E" ] && ok "v: первая проверка отложена (метка записана)" || bad "v: первая: $(cat "$E" 2>/dev/null)"
echo $(( $(date +%s) - 90000 )) >"$E"
[ "$(due :)" = due ] && ok "v: прошли сутки — пора" || bad "v: сутки прошли, но wait"
echo $(( $(date +%s) - 3600 )) >"$E"
[ "$(due :)" = wait ] && ok "v: час назад — рано" || bad "v: час назад, но due"

[ $FAIL -eq 0 ] && echo "ИТОГ: ПРОЙДЕНО" || { echo "ИТОГ: ЕСТЬ ОШИБКИ"; exit 1; }
