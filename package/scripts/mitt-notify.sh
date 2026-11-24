#!/bin/sh
# mi-lumruri: отправка уведомлений в Telegram из очереди $STATE/notify.queue (строки «событие<TAB>unix<TAB>ключ<TAB>параметр»,
# их пишет notify в mitt-lib.sh). Параметры (токен, чат, события, язык) — mi-tt-ctl notify-conf из secrets.json.
# Путь: через туннель, если он поднят, иначе напрямую; не ушло — пробуем другим путём, потом — следующий проход службы
# (до суток). Токен не попадает в аргументы процессов: curl читает адрес из конфигурации на stdin.
# Итог последней попытки — $STATE/notify.json.
D="$(cd "$(dirname "$0")" && pwd)"
. "$D/mitt-lib.sh"
CURL="${MITT_NOTIFY_CURL:-curl}"
API="${MITT_TELEGRAM_API:-https://api.telegram.org}"
Q="$STATE/notify.queue"; S="$Q.sending"
mkdir -p "$STATE" "$LOG"
[ -s "$Q" ] || [ -s "$S" ] || exit 0
conf="$(ctl notify-conf "$ETC/secrets.json" 2>/dev/null)" || { rm -f "$Q" "$S"; exit 0; }
cv() { printf '%s\n' "$conf" | sed -n "s/^$1=//p" | head -n 1; }
token="$(cv token)"; chat="$(cv chat)"; events=",$(cv events),"; lang="$(cv lang)"
# очередь забирается целиком; новые строки за время отправки остаются в $Q
[ -s "$S" ] || mv -f "$Q" "$S" 2>/dev/null
now=$(date +%s)

# текст сообщения: ключ и параметр → строка на языке панели
msg() {
  local k="$1" p="$2"
  case "$lang:$k" in
    en:tunnel_down) echo "VPN tunnel is down: no connection to the server for ${p} s. Sites from the VPN list do not open" ;;
    zh:tunnel_down) echo "VPN 隧道中断：已 ${p} 秒无法连接服务器。VPN 列表中的网站无法打开" ;;
    *:tunnel_down) echo "VPN-туннель упал: нет связи с сервером ${p} с. Сайты из списка VPN не открываются" ;;
    en:tunnel_up) echo "VPN tunnel is back up" ;;
    zh:tunnel_up) echo "VPN 隧道已恢复" ;;
    *:tunnel_up) echo "VPN-туннель снова работает" ;;
    en:watch_restart) echo "Traffic stopped flowing through the tunnel, so the TrustTunnel client was restarted" ;;
    zh:watch_restart) echo "隧道中流量中断，已重启 TrustTunnel 客户端" ;;
    *:watch_restart) echo "Трафик через туннель перестал идти — клиент TrustTunnel перезапущен" ;;
    en:failover_backup) echo "The primary server is not responding: switched to the backup server" ;;
    zh:failover_backup) echo "主服务器无响应：已切换到备用服务器" ;;
    *:failover_backup) echo "Основной сервер не отвечает — переключение на запасной" ;;
    en:failover_primary) echo "Switched back to the primary server" ;;
    zh:failover_primary) echo "已切换回主服务器" ;;
    *:failover_primary) echo "Возврат на основной сервер" ;;
    en:update_available) echo "Version ${p} is available. Update in the panel: Advanced → Update" ;;
    zh:update_available) echo "有新版本 ${p}。可在面板「高级」→「更新」中更新" ;;
    *:update_available) echo "Доступна версия ${p}. Обновить — в панели: «Дополнительно» → «Обновление»" ;;
    en:update_done) echo "Updated to ${p}" ;;
    zh:update_done) echo "已更新到 ${p}" ;;
    *:update_done) echo "Обновлено до ${p}" ;;
    en:update_rolled) echo "The new version did not start working and the previous one was restored: ${p}" ;;
    zh:update_rolled) echo "新版本未能正常工作，已恢复之前的版本：${p}" ;;
    *:update_rolled) echo "Новая версия не заработала, возвращена прежняя: ${p}" ;;
    en:sub_failed) echo "TrustTunnel subscription was not updated: ${p}" ;;
    zh:sub_failed) echo "TrustTunnel 订阅更新失败：${p}" ;;
    *:sub_failed) echo "Подписка TrustTunnel не обновилась: ${p}" ;;
    en:sub_changed) echo "The TrustTunnel subscription changed the server settings; they are applied" ;;
    zh:sub_changed) echo "TrustTunnel 订阅更改了服务器参数，已应用" ;;
    *:sub_changed) echo "Подписка TrustTunnel изменила параметры сервера — применены" ;;
    en:module_missing) echo "The USB drive with the ${p} module is unavailable. Its servers keep working until the router restarts" ;;
    zh:module_missing) echo "装有 ${p} 模块的 U 盘不可用。该模块的服务器在路由器重启前仍会工作" ;;
    *:module_missing) echo "Флешка с модулем ${p} недоступна. Серверы модуля работают до перезагрузки роутера" ;;
    en:module_missing_off) echo "The USB drive with the ${p} module is unavailable: the module's servers are not running" ;;
    zh:module_missing_off) echo "装有 ${p} 模块的 U 盘不可用：该模块的服务器未运行" ;;
    *:module_missing_off) echo "Флешка с модулем ${p} недоступна — серверы модуля не работают" ;;
    en:module_back) echo "The USB drive with the ${p} module is available again" ;;
    zh:module_back) echo "装有 ${p} 模块的 U 盘已恢复可用" ;;
    *:module_back) echo "Флешка с модулем ${p} снова доступна" ;;
    en:boot) echo "The router has started, the service is running" ;;
    zh:boot) echo "路由器已启动，服务正在运行" ;;
    *:boot) echo "Роутер загрузился, служба запущена" ;;
    en:test) echo "Test notification: everything is set up" ;;
    zh:test) echo "测试通知：一切设置正常" ;;
    *:test) echo "Проверка уведомлений: всё настроено" ;;
    *) echo "$k ${p}" ;;
  esac
}

# send <текст> <путь tunnel|direct>: 0 — Telegram ответил ok
send() {
  local opt="" r
  [ "$2" = tunnel ] && opt="--interface $(tun_up_dev || echo mitt0)"
  # shellcheck disable=SC2086
  r="$(printf 'url = "%s/bot%s/sendMessage"\n' "$API" "$token" | "$CURL" -sS -K - $opt --max-time 15 \
    --data-urlencode "chat_id=$chat" --data-urlencode "text=$1" --data-urlencode "disable_web_page_preview=true" 2>&1)"
  case "$r" in *'"ok":true'*) return 0;; esac
  # ответ Telegram (без токена: он только в адресе) или ошибка curl
  ERR="$(printf '%s' "$r" | sed -n 's/.*"description":"\([^"]*\)".*/\1/p' | head -n 1)"
  [ -n "$ERR" ] || ERR="$(printf '%s' "$r" | tail -n 1 | sed "s#$token#<токен>#g" | cut -c1-200)"
  return 1
}

sent=0; failed=0; ERR=""; via=""
while IFS="$(printf '\t')" read -r ev at key par; do
  [ -n "$ev" ] || continue
  case "$ev" in test) ;; *) case "$events" in *",$ev,"*) ;; *) continue;; esac;; esac
  [ $((now - ${at:-0})) -lt 86400 ] || continue
  text="Mi Lumruri: $(msg "$key" "$par")"
  if tun_ready; then first=tunnel; second=direct; else first=direct; second=tunnel; fi
  if send "$text" "$first"; then via=$first
  elif [ "$second" = direct ] || tun_ready; then
    if send "$text" "$second"; then via=$second; else printf '%s\t%s\t%s\t%s\n' "$ev" "$at" "$key" "$par" >>"$Q"; failed=$((failed + 1)); continue; fi
  else
    printf '%s\t%s\t%s\t%s\n' "$ev" "$at" "$key" "$par" >>"$Q"; failed=$((failed + 1)); continue
  fi
  sent=$((sent + 1))
done <"$S"
rm -f "$S"
js() { printf '%s' "$1" | tr -d '"\\' | tr '\n\r\t' '   ' | cut -c1-300; }
if [ "$failed" -eq 0 ]; then
  printf '{"ok":true,"at":%s,"sent":%s,"via":"%s","error":null}\n' "$now" "$sent" "$via" >"$STATE/notify.json"
else
  mlog "уведомления: не отправлено $failed (${ERR:-нет ответа}), повтор позже"
  printf '{"ok":false,"at":%s,"sent":%s,"via":"%s","error":"%s"}\n' "$now" "$sent" "$via" "$(js "$ERR")" >"$STATE/notify.json"
fi
exit 0
