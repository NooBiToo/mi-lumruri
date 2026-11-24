#!/usr/bin/env bash
# Подписка TrustTunnel (package/scripts/mitt-sub.sh) на штатном BusyBox ash 1.25.1 (ARM64 из образа RC06 1.1.38 под
# qemu-user): заглушка curl вместо сервера подписки, настоящий mi-tt ARM64 (subscription-url, subscription-import).
# Нужен `bash tools/cargo.sh build --locked --release --target aarch64-unknown-linux-musl`.
# Запуск — в WSL: bash tools/lab/test-sub.sh
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
"$ROOT/tools/fw/prepare.sh" >/dev/null
F=/tmp/mitt-fw/rootfs; Q="$ROOT/.tools/qemu/root/usr/bin/qemu-aarch64"
MT="$ROOT/controller/target/aarch64-unknown-linux-musl/release/mi-tt"
[ -f "$MT" ] || { echo "нет $MT: bash tools/cargo.sh build --locked --release --target aarch64-unknown-linux-musl"; exit 2; }
W="$(mktemp -d /tmp/mitt-sub.XXXXXX)"; [ -n "${KEEP:-}" ] && echo "каталог: $W" || trap 'rm -rf "$W"' EXIT
FAIL=0
ok() { echo "  ok   $*"; }
bad() { echo "  FAIL $*"; FAIL=1; }

SB="$W/stockbin"; mkdir -p "$SB"
for a in sh ash cat cp mv rm mkdir chmod sed awk grep head tail wc tr cut cmp date sleep kill basename dirname touch printf echo test expr; do
  if [ -e "$F/bin/$a" ] || [ -e "$F/usr/bin/$a" ] || [ -e "$F/sbin/$a" ] || [ -e "$F/usr/sbin/$a" ]; then
    printf '#!/bin/sh\nexec %s -L %s %s/bin/busybox %s "$@"\n' "$Q" "$F" "$F" "$a" >"$SB/$a"
  fi
done
cat >"$SB/curl" <<'EOF'
#!/bin/sh
echo "$*" >>"$LT/curl.log"
out=""; while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift;; esac; shift; done
# подписка sing-box (ссылка …/list) — список ссылок из $LT/list.b64
case "$(tail -n 1 "$LT/curl.log")" in *sub.example.com/list*) cp "$LT/list.b64" "$out"; exit 0;; esac
case "$(cat "$LT/mode")" in
  ok) cp "$LT/sub.json" "$out";;
  401) echo "curl: (22) The requested URL returned error: 401" >&2; exit 22;;
  html) printf '<html>login</html>' >"$out";;
esac
EOF
chmod +x "$SB"/*

R="$W/root"; LT="$W/lt"; E="$R/data/mi-lumruri/etc"; S="$R/tmp/mi-lumruri/run"
mkdir -p "$E" "$S" "$R/tmp/mi-lumruri/bin" "$R/tmp/mi-lumruri/scripts" "$LT"
cp "$ROOT"/package/scripts/*.sh "$R/tmp/mi-lumruri/scripts/"
printf '#!/bin/sh\nexec %s %s.arm64 "$@"\n' "$Q" "$R/tmp/mi-lumruri/bin/mi-tt-ctl" >"$R/tmp/mi-lumruri/bin/mi-tt-ctl"; chmod +x "$R/tmp/mi-lumruri/bin/mi-tt-ctl"
cp "$MT" "$R/tmp/mi-lumruri/bin/mi-tt-ctl.arm64"
cat >"$E/config.json" <<'EOF'
{ "version": 1, "profiles": [{ "id": "tt", "name": "Мой сервер", "kind": "trusttunnel", "on_failure": "block" }],
  "networks": [], "devices": [], "groups": [], "rules": [], "default_action": { "type": "direct" } }
EOF
printf '{"version":1,"profiles":{"tt":{"subscription_url":"https://alice:pw@vpn.example.com/subscription"}}}\n' >"$E/secrets.json" # secret-scan: allow тестовая ссылка
printf '{"version":1,"hostname":"vpn.example.com","address":"203.0.113.1:443","username":"alice","password":"lab-pass-1","upstream_protocol":"http3","anti_dpi":false,"skip_verification":false}' >"$LT/sub.json" # secret-scan: allow тестовый пароль
sub() { timeout 300 env -i PATH="$SB" MITT_ROOT="$R" MITT_QUIET=1 MITT_CURL="$SB/curl" LT="$LT" MI_TT_RUN_DIR="$S" \
  "$Q" -L "$F" "$F/bin/busybox" ash "$R/tmp/mi-lumruri/scripts/mitt-sub.sh" >>"$W/out" 2>&1; echo "  [код $?]"; }
j() { python3 -I -c 'import json,sys; s=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$1" "$2" 2>&1; }

echo "(а) подписка без точки подключения: точка, пароль, заявка на применение"
echo ok >"$LT/mode"; sub
[ "$(j "$S/sub/tt.json" 's["ok"] and s["updated"]==s["checked"] and s["error"] is None')" = True ] && ok "a: ok, updated" || bad "a: $(cat "$S/sub/tt.json"); $(tail -3 "$W/out")"
[ "$(j "$E/config.json" 's["profiles"][0]["endpoint"]["server"]=="203.0.113.1" and s["profiles"][0]["endpoint"]["quic"] is True')" = True ] && ok "a: точка подключения из подписки" || bad "a: config: $(cat "$E/config.json")"
[ "$(j "$E/secrets.json" 's["profiles"]["tt"]["password"]=="lab-pass-1" and s["profiles"]["tt"]["subscription_url"].startswith("https://")')" = True ] && ok "a: пароль записан, ссылка сохранена" || bad "a: secrets"
[ -f "$S/apply.request" ] && ok "a: заявка на применение" || bad "a: нет заявки"
grep -q -- "--proto =https" "$LT/curl.log" && ok "a: curl только https" || bad "a: curl: $(cat "$LT/curl.log")"

echo "(б) без изменений: заявки нет, updated прежний"
rm -f "$S/apply.request"; U1="$(j "$S/sub/tt.json" 's["updated"]')"; sleep 1; sub
[ ! -f "$S/apply.request" ] && [ "$(j "$S/sub/tt.json" 's["updated"]')" = "$U1" ] && ok "b: ничего не изменилось" || bad "b: $(cat "$S/sub/tt.json")"

echo "(в) сервер отказал (401) и вернул HTML: ошибка без ссылки, настройки прежние"
cp "$E/config.json" "$W/cfg.before"
echo 401 >"$LT/mode"; sub
[ "$(j "$S/sub/tt.json" 'not s["ok"] and "401" in s["error"] and "alice" not in s["error"] and s["updated"]=='"$U1")" = True ] && ok "c: 401 — ошибка, без логина и пароля в тексте" || bad "c: $(cat "$S/sub/tt.json")"
echo html >"$LT/mode"; sub
[ "$(j "$S/sub/tt.json" 'not s["ok"] and "не принят" in s["error"]')" = True ] && cmp -s "$E/config.json" "$W/cfg.before" && ok "c: HTML — не принят, настройки прежние" || bad "c: $(cat "$S/sub/tt.json")"

echo "(г) пароль сменился на сервере — обновлён"
echo ok >"$LT/mode"; sed -i 's/lab-pass-1/lab-pass-2/' "$LT/sub.json"; sub
[ "$(j "$E/secrets.json" 's["profiles"]["tt"]["password"]=="lab-pass-2"')" = True ] && [ -f "$S/apply.request" ] && ok "d: новый пароль и заявка" || bad "d: secrets"

echo "(д) подписки нет — сценарий ничего не делает"
printf '{"version":1,"profiles":{"tt":{"password":"x"}}}\n' >"$E/secrets.json"; : >"$LT/curl.log"; sub
[ ! -s "$LT/curl.log" ] && [ ! -f "$S/sub/tt.json" ] && ok "e: без ссылки — без запросов, состояние снято" || bad "e: curl: $(cat "$LT/curl.log")"

echo "(е) подписка сервера sing-box (список ссылок base64) рядом с TrustTunnel: первый сервер, выбор сохраняется"
cat >"$E/config.json" <<'EOF'
{ "version": 1, "profiles": [{ "id": "tt", "name": "Мой сервер", "kind": "trusttunnel", "on_failure": "block" },
  { "id": "vl", "name": "Подписка", "kind": "vless", "tunnel": 1, "on_failure": "block" }],
  "networks": [], "devices": [], "groups": [], "rules": [], "default_action": { "type": "direct" } }
EOF
printf '{"version":1,"profiles":{"tt":{"subscription_url":"https://alice:pw@vpn.example.com/subscription"},"vl":{"subscription_url":"https://bob:pw@sub.example.com/list"}}}\n' >"$E/secrets.json" # secret-scan: allow тестовые ссылки
printf 'vless://bf000d23-0752-40b4-affe-68f7707a9661@a.example.com:443?security=tls#A\nhy2://pw@b.example.com:443#B\n' | base64 >"$LT/list.b64" # secret-scan: allow тестовые ссылки
echo ok >"$LT/mode"; rm -f "$S/apply.request"; sub
[ "$(j "$S/sub/vl.json" 's["ok"] and s["count"]==2')" = True ] && ok "f: список принят, 2 сервера" || bad "f: $(cat "$S/sub/vl.json" 2>&1); $(tail -3 "$W/out")"
[ "$(j "$E/secrets.json" '"a.example.com" in s["profiles"]["vl"]["link"]')" = True ] && ok "f: ссылка первого сервера — в секрете" || bad "f: secrets"
[ "$(j "$E/config.json" 's["profiles"][1]["proxy"]["server"]=="a.example.com"')" = True ] && ok "f: сводка в настройках" || bad "f: config"
[ "$(j "$S/sub/tt.json" 's["ok"]')" = True ] && ok "f: подписка TrustTunnel тоже обновлена" || bad "f: tt: $(cat "$S/sub/tt.json" 2>&1)"
python3 -I -c 'import json,sys;p=sys.argv[1];c=json.load(open(p));c["profiles"][1]["sub_pick"]="B";json.dump(c,open(p,"w"))' "$E/config.json"
sub
[ "$(j "$E/config.json" 's["profiles"][1]["kind"]=="hysteria2" and s["profiles"][1]["proxy"]["server"]=="b.example.com"')" = True ] && ok "f: выбранный сервер B (Hysteria2)" || bad "f: pick: $(cat "$E/config.json")"

[ $FAIL -eq 0 ] && echo "ИТОГ: ПРОЙДЕНО" || { echo "ИТОГ: ЕСТЬ ОШИБКИ"; exit 1; }
