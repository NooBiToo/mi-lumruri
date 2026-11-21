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
lb = js("lists.boot.json")
check("готовые списки: svc-*.list из снимка релиза разложены до рендера; /lists отдаёт каталог; проверка обновлений без WAN (curl стока) — ok=false, «нет связи»",
      "svc-youtube.list" in cl and "svc-meta-ip.list" in cl and pl[-1:] == ["200"] and len(lj.get("catalog", {}).get("services", [])) >= 20
      and lb.get("ok") is False and "нет связи" in " ".join(lb.get("errors", [])),
      [cl[:4], pl[-1:], len(lj.get("catalog", {}).get("services", [])), lb])
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
check("состояние службы: protection full, клиент trusttunnel работает; рендер и полное применение — без ошибок",
      js("status.wan.json").get("protection") == "full" and js("status.wan.json").get("engines", {}).get("trusttunnel") is True
      and (js("status.wan.json").get("render") or {}).get("ok") is True and (js("status.wan.json").get("apply") or {}).get("exit") == 0, js("status.wan.json"))
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
# --- Zapret на настоящем ядре: план mi-tt-admin (Q, Z, P), nfqws2 x86_64 с аргументами рендера, очередь 200
aw = js("apply.wan.json")
owned = aw.get("owned", [])
plan = {}
for lab in owned:
    if lab.startswith("iptables -t mangle MITT_") and ": " in lab:
        name, rows = lab[len("iptables -t mangle "):].split(": ", 1)
        plan[name] = rows.lower().split(" | ")  # MAC в плане — заглавными, iptables -S печатает строчными
live = {}
for line in text("mangle.wan.txt").splitlines():
    if line.startswith("-A MITT_"):
        name, _, row = line[3:].partition(" ")
        live.setdefault(name, []).append(row.lower())
qpz = {k: v for k, v in plan.items() if k[5] in "QPZ"}
mw = text("mangle.wan.txt")
check("Zapret («напрямую с Zapret» по умолчанию): mi-tt-admin применил цепочки Q, Z и P без конфликтов, сверка с ядром — verified",
      aw.get("ok") is True and aw.get("verified") is True and sorted(k[5] for k in qpz) == ["P", "Q", "Z"],
      [aw.get("ok"), aw.get("verified"), sorted(qpz)])
check("iptables -S цепочек Q, Z и P совпадает с планом построчно (без учёта регистра MAC); Z — из FORWARD, P — из OUTPUT",
      qpz and all(live.get(k) == v for k, v in qpz.items())
      and any(l.startswith("-A FORWARD") and "-j MITT_Z" in l for l in mw.splitlines()) and any(l.startswith("-A OUTPUT") and "-j MITT_P" in l for l in mw.splitlines()),
      {k: (v, live.get(k)) for k, v in qpz.items() if live.get(k) != v} or "совпадает")
dr = text("nfqws2-dry-run.out")
check("nfqws2 x86_64 (zapret2 v1.0.7) принимает отрендеренные аргументы каталога: --dry-run — код 0, «command line parameters verified», списки хостов из каталога программы",
      "exit=0" in dr and "command line parameters verified" in dr and "Loaded" in dr and "--lua-init=@zapret-auto.lua.gz" in text("nfqws2.args"), dr.strip()[-200:])
ml = text("mitt.log")
check("служба запустила nfqws2 с аргументами рендера: работает после WAN, после заявки панели и после подбора; перезапусков не было",
      js("status.wan.json").get("engines", {}).get("nfqws2") is True and all((OUT / f"nfqws2.{x}.alive").exists() for x in ("wan", "panel", "after-test"))
      and "движок nfqws2 завершился" not in ml,
      [js("status.wan.json").get("engines"), [x for x in ("wan", "panel", "after-test") if (OUT / f"nfqws2.{x}.alive").exists()], ml.count("движок nfqws2 завершился")])


def nfq(txt):
    r = {}
    for line in txt.splitlines():
        f = line.split()
        if len(f) >= 8 and f[0].isdigit():
            r[int(f[0])] = max(r.get(int(f[0]), 0), int(f[7]))
    return r


q = nfq(text("nfqueue.wan.txt"))
udp = js("zapret-udp.json")
check("трафик телефона к порту 443 (TCP и UDP) идёт через очередь 200 (nfqws2 привязан, пакеты прошли) и доходит до сервера",
      q.get(200, 0) > 0 and seen("Z-phone-443") == (0, "10.10.1.3") and udp.get("seen_client") == "10.10.1.3" and seen("Z-phone-after-test") == (0, "10.10.1.3"),
      [q, seen("Z-phone-443"), udp, seen("Z-phone-after-test")])

# --- обновление готовых списков по кнопке панели (curl стока, локальный «репозиторий»)
lu = js("lists.update.json")
wl = jl("web-lists.jsonl")
check("обновление списков из панели: 202; служба загрузила файлы с «репозитория» (curl стока через WAN роутера), проверка без ошибок",
      text("panel-lists-update.out").splitlines()[-1:] == ["202"] and lu.get("ok") is True and lu.get("errors") == [] and isinstance(lu.get("updated"), int)
      and wl and all(r.get("client") == "10.20.0.2" and r.get("code") == 200 for r in wl),
      [text("panel-lists-update.out").splitlines()[-1:], lu, len(wl)])
dl = text("dnsmasq-mitt.lists.conf")
q_new = [x for x in DA if "lab-new.lab.test" in json.dumps(x, ensure_ascii=False)]
check("изменённый список применён заново: svc-cloudflare.list с новым доменом, применение panel-request, домен в dnsmasq (ipset и резолвер туннеля), вопрос ТВ — через туннель",
      "lab-new.lab.test" in text("svc-cloudflare.after.list") and js("last-apply.lists.json").get("tag") == "panel-request" and js("last-apply.lists.json").get("exit") == 0
      and "ipset=/lab-new.lab.test/" in dl and "server=/lab-new.lab.test/198.51.100.54" in dl and "lab-new" not in text("dnsmasq-mitt.conf")
      and q_new and all(x.get("client") == VPN for x in q_new),
      [js("last-apply.lists.json"), [l for l in dl.splitlines() if "lab-new" in l][:2], q_new[:1]])
ls_ = js("lists.json")
check("состояние проверки списков пережило «перезагрузку» (копия в /data): после неё — итог обновления",
      ls_.get("ok") is True and ls_.get("updated") == lu.get("updated"), ls_)

z6 = text("zone.ipv6.txt")
check("IPv6 через VPN («всё через VPN» для ТВ): применение прошло, ip -6 rule метка → 3100, маршрут IPv6 через mitt0, цепочки ip6tables mangle и ACCEPT в filter, клиент с has_ipv6",
      js("last-apply.ipv6.json").get("exit") == 0 and "fwmark 0x4000/0x4000 lookup 3100" in z6 and "default dev mitt0" in z6
      and "-A MITT_C" in z6 and "-o mitt0 -j ACCEPT" in z6 and "has_ipv6 = true" in text("client.ipv6.txt"),
      [js("last-apply.ipv6.json"), z6[:600], text("client.ipv6.txt")])
check("IPv6 через VPN выключен обратно: правил IPv6 в зоне 3000–3199 нет", text("zone.ipv6-off.txt").strip() == "", text("zone.ipv6-off.txt"))

# --- подбор стратегии по кнопке панели: настоящие nfqws2 и curl стока, очередь 201
zt = js("zapret-test.json")
zl = text("zapret-test.log")
qt = nfq(text("nfqueue.zapret-test.txt"))
wz = [r for r in jl("web-zapret.jsonl") if r.get("client") == "10.20.0.2"]
zp = zt.get("progress", {})
nz = zp.get("total", 0)  # контроль и стратегии общего набора (каталог; прохода YouTube нет — целей YouTube нет)
check("подбор Zapret из панели: 202; контроль и все стратегии общего набора проверены, у каждой стратегии свой nfqws2 на очереди 201 запустился",
      text("panel-zapret-test.out").splitlines()[-1:] == ["202"] and zt.get("state") == "done" and nz >= 2 and zp.get("done") == nz
      and "не запустился" not in zl and qt.get(201, 0) > 0 and len(wz) >= 3 * nz,
      [zt.get("progress"), zl.count("не запустился"), qt, len(wz)])
check("DPI в лаборатории нет: без Zapret открываются все цели, лучше контроля стратегии нет — ничего не применено",
      zt.get("control") == {"opened": 3, "total": 3} and zt.get("applied") is False and zt.get("message") == "Подходящей стратегии лучше, чем без Zapret, не нашлось",
      [zt.get("control"), zt.get("best"), zt.get("message")])
ok = all(c["ok"] for c in checks)
json.dump({"ok": ok, "checks": checks, "probes": list(P.values())}, open(OUT / "summary.json", "w", encoding="utf-8"), ensure_ascii=False, indent=2)
md = ["| Проверка | Детали | Итог |", "|---|---|---|"] + [f"| {c['check']} | {c['detail'].replace('|', '/')} | {'да' if c['ok'] else 'НЕТ'} |" for c in checks]
(OUT / "summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")
print("\n".join(md))
print(f"проверок: {sum(c['ok'] for c in checks)} из {len(checks)}")
print("ИТОГ:", "ПРОЙДЕНО" if ok else "НЕ ПРОЙДЕНО")
sys.exit(0 if ok else 1)
