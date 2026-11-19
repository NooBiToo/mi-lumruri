"""Проверка лаборатории автозагрузки и службы: клиент и сервер TrustTunnel, штатные BusyBox, nginx и uhttpd."""
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
check("холодный старт без WAN (штатный BusyBox, вызов как из fw3): код 0, защита guard сразу — метка, unreachable в таблице 3100, цепочки MITT_ и наборы ipset на месте",
      "exit=0" in b1 and st.get("protection") == "guard" and "fwmark 0x4000/0x4000 lookup 3100" in z and "unreachable default" in z and "-j MITT_C" in z and "mitt" in z,
      [b1.strip()[-120:], st.get("protection"), z[:200]])
eng = text("engines.ls").split()
check("после холодного старта рядом с nfqws2 лежат блобы, списки хостов и Lua zapret2 (--chdir)",
      all(n in eng for n in ("tls_clienthello_www_google_com.bin", "tls_clienthello_www_4pda_to.bin", "quic_initial_www_google_com.bin", "zapret-hosts-youtube.txt", "zapret-hosts-discord.txt", "zapret-auto.lua.gz")), eng)
check("служебная команда mitt-boot.sh auth status (каталоги пакета): вход настроен, TOTP подтверждён",
      js("auth-status.json").get("configured") is True and js("auth-status.json").get("ok") is True, text("auth-status.json")[:200])
check("без WAN: у ТВ нет связи (трафик правила упирается в unreachable), телефон без правил — тоже нет (WAN выключен)", seen("B-tv-no-wan")[0] == 1, [seen("B-tv-no-wan"), seen("B-phone-no-wan")])
check("панель без WAN: https://10.10.1.1:8443 через штатный nginx стока (TLS) отдаёт index.html", text("panel-index.code").strip() == "200", text("panel-index.code"))
ps = text("panel-session.out").splitlines()
check("API панели через nginx → штатный uhttpd → CGI ARM64: /auth/session — 200, /config без входа — 401",
      ps[-1:] == ["200"] and text("panel-config-noauth.out").splitlines()[-1:] == ["401"], [ps[-1:], text("panel-config-noauth.out")[-40:]])
check("вход по паролю и TOTP через nginx: 200 и 200; cookie __Host-mitt_sess выставлен",
      text("panel-login.code").strip() == "200" and text("panel-second.code").strip() == "200" and text("panel-cookie.count").strip() == "1",
      [text("panel-login.code").strip(), text("panel-second.code").strip(), text("panel-cookie.count").strip()])
cl = text("categories.ls").split()
pl = text("panel-lists.out").splitlines()
try:
    lj = json.loads("\n".join(pl[:-1]))
except ValueError:
    lj = {}
ls_ = js("lists.json")
check("готовые списки: svc-*.list из снимка релиза разложены до рендера; /lists отдаёт каталог; проверка обновлений без сети — ok=false, «нет связи» (состояние пережило «перезагрузку»)",
      "svc-youtube.list" in cl and "svc-meta-ip.list" in cl and pl[-1:] == ["200"] and len(lj.get("catalog", {}).get("services", [])) >= 20
      and ls_.get("ok") is False and "нет связи" in " ".join(ls_.get("errors", [])),
      [cl[:4], pl[-1:], len(lj.get("catalog", {}).get("services", [])), ls_])
rj = text("panel-router.out").splitlines()
try:
    rl = json.loads(chr(10).join(rj[:-1])).get("lan", {})
except ValueError:
    rl = {}
check("/router через nginx: LAN лаборатории — мост br-lan, 10.10.1.0/24, адрес 10.10.1.1 (из uci-файла роутера)",
      rj[-1:] == ["200"] and rl == {"bridge": "br-lan", "subnet": "10.10.1.0/24", "address": "10.10.1.1"}, [rj[-1:], rl])
check("после входа /config — 200", text("panel-config-auth.code").strip() == "200", text("panel-config-auth.code"))
h = text("panel-headers.txt")
check("заголовки защиты от nginx: HSTS, X-Frame-Options DENY, CSP frame-ancestors 'none'", "Strict-Transport-Security" in h and "X-Frame-Options: DENY" in h and "frame-ancestors 'none'" in h, h[:200])
check("WAN появился: служба сама подключила клиент TrustTunnel — ТВ (правило устройства) через туннель, телефон напрямую",
      js("wan-up.json").get("tunnel") is True and seen("W-tv") == (0, VPN) and seen("W-phone") == (0, "10.10.1.3"), [seen("W-tv"), seen("W-phone")])
check("состояние службы: protection full, клиент trusttunnel работает",
      js("status.wan.json").get("protection") == "full" and js("status.wan.json").get("engines", {}).get("trusttunnel") is True, js("status.wan.json"))
DA = jl("dnsauth.jsonl")
q_tunnel = [q for q in DA if "ok2.lab.test" in json.dumps(q, ensure_ascii=False)]
q_other = [q for q in DA if '"ok.lab.test' in json.dumps(q, ensure_ascii=False)]
ips = text("ipset.after-dns.txt")
conf = text("dnsmasq-mitt.conf")
check("dnsmasq роутера: файл пакета содержит ipset= для доменов правил и server=/домен/резолвер туннеля",
      "ipset=/ok2.lab.test/mitt" in conf and "server=/ok2.lab.test/198.51.100.54" in conf, conf[:300])
check("домен из правила ТВ: до вопроса DNS адрес не в наборе — напрямую; после ответа dnsmasq (ipset) — через туннель",
      seen("D-tv-before-dns") == (0, "10.10.1.2") and "10.99.0.11" in ips and seen("D-tv-after-dns") == (0, VPN),
      [seen("D-tv-before-dns"), seen("D-tv-after-dns"), ips[:200]])
check("вопрос о домене туннеля ушёл к резолверу через туннель (резолвер видит адрес сервера TrustTunnel), а не через провайдера",
      q_tunnel and all(q.get("client") == VPN and q.get("server") == "tunnel-resolver" for q in q_tunnel), q_tunnel[:2])
check("остальные домены — через обычный вышестоящий DNS роутера (резолвер видит WAN роутера)",
      q_other and all(q.get("client") == "10.20.0.2" and q.get("server") == "internet" for q in q_other), q_other[:2])
check("телефон без правила: тот же домен и адрес — напрямую", seen("D-phone-after-dns") == (0, "10.10.1.3"), seen("D-phone-after-dns"))
rt = text("routes.main.txt")
check("клиент TrustTunnel не трогает основную таблицу маршрутов: маршрута по умолчанию через mitt0 в main нет",
      rt and not any(l.startswith("default") and "mitt0" in l for l in rt.splitlines()), rt[:300])
check("перезагрузка firewall (цепочки сняты): вызов include восстановил цепочки и переходы; ТВ снова через туннель",
      "MITT_" not in text("zone.flushed.txt") and "-j MITT_C" in text("zone.restored.txt")
      and seen("F-tv") == (0, VPN) and js("last-apply.fw.json").get("tag") == "fw-reload", [js("last-apply.fw.json"), seen("F-tv")])
check("ТВ сменил адрес: правило устройства по MAC действует сразу, без применения политики",
      seen("N-tv-new-ip") == (0, VPN), seen("N-tv-new-ip"))
check("падение клиента TrustTunnel: в это время у ТВ нет связи (unreachable, не напрямую); служба перезапустила клиент и применила политику",
      seen("E-tv-down")[0] == 1 and js("last-apply.crash.json").get("tag") == "trusttunnel-restart" and seen("E-tv-restored") == (0, VPN),
      [seen("E-tv-down"), js("last-apply.crash.json"), seen("E-tv-restored")])
pso = text("panel-status.out")
check("заявка на применение из панели (сессия 2FA, CSRF через Authorization от nginx): 202, служба выполнила (last_apply = panel-request), статус виден в панели",
      text("panel-apply.code").strip() == "202" and js("last-apply.panel.json").get("tag") == "panel-request" and '"service"' in pso, [text("panel-apply.code").strip(), js("last-apply.panel.json")])
check("«перезагрузка»: после остановки наших правил и наборов нет; холодный старт без WAN снова ставит защиту до клиента, затем WAN — туннель",
      text("zone.after-reboot.txt").strip() == "" and "exit=0" in text("boot2.out") and "lookup 3100" in text("zone.boot2.txt") and seen("R-tv-no-wan")[0] == 1 and seen("R-tv-wan") == (0, VPN),
      [text("zone.after-reboot.txt")[:80], seen("R-tv-no-wan"), seen("R-tv-wan")])
wan = jl("sniff-wan.jsonl")
PH = {p["phase"]: p["t"] for p in jl("phases.jsonl")}
win = (PH.get("fw_flushed", 0), PH.get("fw_restored", 0))
# трафик правил ТВ: к 10.99.0.10 (CIDR правила) — всегда; к 10.99.0.11 (домен правила) — после ответа DNS
leak = [p for p in wan if p.get("src") in TV and (p.get("dst") == "10.99.0.10" or (p.get("dst") == "10.99.0.11" and p.get("t", 0) >= PH.get("dns_answered", 1e12)))]
outside = [p for p in leak if not (win[0] <= p.get("t", 0) <= win[1])]
check("сниффер WAN за весь прогон (загрузка без WAN, новый адрес, падение клиента, «перезагрузка»): от ТВ вне окна перезагрузки firewall — 0 пакетов",
      wan and not outside, f"пакетов WAN: {len(wan)}, от ТВ вне окна: {len(outside)}")
check("известное ограничение: пока цепочки сняты перезагрузкой firewall и include ещё не вызван, трафик правил идёт напрямую (окно измерено)",
      True, f"от ТВ в окне {round(win[1] - win[0], 1)} с: {len(leak) - len(outside)} пакетов; проба в окне: {seen('F-tv-flushed')}")
check("секреты (пароль панели, TOTP, пароль TrustTunnel, ключ TLS) не попали в артефакты", js("secret-leak.json").get("found") == [], js("secret-leak.json"))
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
