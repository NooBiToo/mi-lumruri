"""Проверка лаборатории автозагрузки и службы (этап 12)."""
import json
import sys
from pathlib import Path

OUT = Path(sys.argv[1])
TV = ("10.10.1.2", "10.10.1.50")
VPN = "10.30.0.2"


def jl(p):
    f = OUT / p
    return [json.loads(x) for x in f.read_text(encoding="utf-8").splitlines() if x.strip()] if f.exists() else []


def text(p):
    f = OUT / p
    return f.read_text(encoding="utf-8", errors="replace") if f.exists() else ""


def js(p):
    try:
        return json.loads(text(p))
    except ValueError:
        return {}


P = {p["probe"]: p for p in jl("probes.jsonl")}
checks = []


def check(name, ok, detail=""):
    checks.append({"check": name, "ok": bool(ok), "detail": str(detail)[:300]})


def seen(i):
    p = P.get(i, {})
    return (p.get("rc"), p.get("reply", {}).get("seen_client"))


b1 = text("boot1.out")
st = js("status.boot.json")
z = text("zone.boot-guard.txt")
check("холодный старт без WAN (штатный BusyBox, вызов как из fw3): код 0, защита guard сразу — правила зоны и MITT_FWD на месте",
      "exit=0" in b1 and st.get("protection") == "guard" and "lookup 3100" in z and "MITT_FWD" in z, [b1.strip()[-120:], st.get("protection")])
check("служебная команда mitt-boot.sh auth status (каталоги пакета): вход настроен, TOTP подтверждён",
      js("auth-status.json").get("configured") is True and js("auth-status.json").get("ok") is True, text("auth-status.json")[:200])
check("без WAN: у ТВ нет связи (защищён), телефон без правил — тоже нет (WAN выключен)", seen("B-tv-no-wan")[0] == 1, [seen("B-tv-no-wan"), seen("B-phone-no-wan")])
check("панель без WAN: https://10.10.1.1:8443 через штатный nginx стока (TLS) отдаёт index.html", text("panel-index.code").strip() == "200", text("panel-index.code"))
ps = text("panel-session.out").splitlines()
check("API панели через nginx → штатный uhttpd → CGI ARM64: /auth/session — 200, /config без входа — 401",
      ps[-1:] == ["200"] and text("panel-config-noauth.out").splitlines()[-1:] == ["401"], [ps[-1:], text("panel-config-noauth.out")[-40:]])
check("вход по паролю и TOTP через nginx: 200 и 200; cookie __Host-mitt_sess выставлен (HTTPS — по доверенному loopback-прокси nginx; uhttpd стока не передаёт X-Forwarded-Proto)",
      text("panel-login.code").strip() == "200" and text("panel-second.code").strip() == "200" and text("panel-cookie.count").strip() == "1",
      [text("panel-login.code").strip(), text("panel-second.code").strip(), text("panel-cookie.count").strip()])
check("после входа /config — 200", text("panel-config-auth.code").strip() == "200", text("panel-config-auth.code"))
h = text("panel-headers.txt")
check("заголовки защиты от nginx: HSTS, X-Frame-Options DENY, CSP frame-ancestors 'none'", "Strict-Transport-Security" in h and "X-Frame-Options: DENY" in h and "frame-ancestors 'none'" in h, h[:200])
check("WAN появился: служба сама подключила туннель — ТВ через Hysteria2, телефон напрямую",
      js("wan-up.json").get("tunnel") is True and seen("W-tv") == (0, VPN) and seen("W-phone") == (0, "10.10.1.3"), [seen("W-tv"), seen("W-phone")])
check("состояние службы: protection full, движок mihomo работает, last_apply = start",
      js("status.wan.json").get("protection") == "full" and js("status.wan.json").get("engines", {}).get("mihomo") is True, js("status.wan.json"))
check("перезагрузка firewall (цепочки сняты): вызов include восстановил MITT_FWD и переход из FORWARD; ТВ через туннель",
      "MITT_FWD" not in text("zone.flushed.txt").split("lookup")[-1] and "-j MITT_FWD" in text("zone.restored.txt") and seen("F-tv") == (0, VPN)
      and js("last-apply.fw.json").get("tag") == "fw-reload", [js("last-apply.fw.json"), seen("F-tv")])
check("смена аренды ТВ (новый IPv4): служба применила политику по изменению файла аренд, ТВ с новым адресом — через туннель",
      js("last-apply.lease.json").get("tag") == "lease-change" and seen("L-tv-new-ip") == (0, VPN), [js("last-apply.lease.json"), seen("L-tv-new-ip")])
check("падение Mihomo: в это время у ТВ нет связи; служба перезапустила движок и применила политику, туннель восстановлен",
      seen("E-tv-down")[0] == 1 and js("last-apply.crash.json").get("tag") == "mihomo-restart" and seen("E-tv-restored") == (0, VPN),
      [seen("E-tv-down"), js("last-apply.crash.json"), seen("E-tv-restored")])
pso = text("panel-status.out")
check("заявка на применение из панели (сессия 2FA, CSRF через Authorization от nginx): 202, служба выполнила (last_apply = panel-request), статус виден в панели",
      text("panel-apply.code").strip() == "202" and js("last-apply.panel.json").get("tag") == "panel-request" and '"service"' in pso, [text("panel-apply.code").strip(), js("last-apply.panel.json")])
check("«перезагрузка»: после остановки наших правил нет; холодный старт без WAN снова ставит защиту до движков, затем WAN — туннель",
      text("zone.after-reboot.txt").strip() == "" and "exit=0" in text("boot2.out") and "lookup 3100" in text("zone.boot2.txt") and seen("R-tv-no-wan")[0] == 1 and seen("R-tv-wan") == (0, VPN),
      [text("zone.after-reboot.txt")[:80], seen("R-tv-no-wan"), seen("R-tv-wan")])
wan = jl("sniff-wan.jsonl")
leak = [p for p in wan if p.get("src") in TV]
check("сниффер WAN за весь прогон (загрузка без WAN, перезагрузка firewall, смена аренды, падение движка, «перезагрузка»): от ТВ — 0 пакетов",
      wan and not leak, f"пакетов WAN: {len(wan)}, от ТВ: {len(leak)}")
check("секреты (пароль панели, TOTP, Hysteria2) не попали в артефакты", js("secret-leak.json").get("found") == [], js("secret-leak.json"))
bt = js("boot-time.json").get("boot_seconds")
check("время холодного старта до защиты и панели (под qemu на x86) измерено", isinstance(bt, (int, float)), f"{bt} с")
ok = all(c["ok"] for c in checks)
json.dump({"ok": ok, "checks": checks, "probes": list(P.values())}, open(OUT / "summary.json", "w", encoding="utf-8"), ensure_ascii=False, indent=2)
md = ["| Проверка | Детали | Итог |", "|---|---|---|"] + [f"| {c['check']} | {c['detail'].replace('|', '/')} | {'да' if c['ok'] else 'НЕТ'} |" for c in checks]
(OUT / "summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")
print("\n".join(md))
print(f"проверок: {sum(c['ok'] for c in checks)} из {len(checks)}")
print("ИТОГ:", "ПРОЙДЕНО" if ok else "НЕ ПРОЙДЕНО")
sys.exit(0 if ok else 1)
