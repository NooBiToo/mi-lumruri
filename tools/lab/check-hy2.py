"""Проверка прогона лаборатории Hysteria2 (этап 7) по наблюдениям: ответы эхо-целей (кто пришёл), сниффер на WAN-линке
роутера (любой пакет защищённого устройства наружу), сниффер транспорта к серверу, журналы, коды mi-tt-admin и API.
Пишет summary.json и summary.md; код 0 — всё совпало с ожиданиями."""
import json
import sys
from pathlib import Path

OUT = Path(sys.argv[1])
TV4, TV6, PHONE4 = "10.10.1.2", "fd00:10::2", "10.10.1.3"
VPN, ROUTER_WAN, GROUP, OUTSIDE = "10.30.0.2", "10.20.0.2", "10.99.0.10", "10.98.0.10"


def jl(p):
    f = OUT / p
    if not f.exists():
        return []
    out = []
    for x in f.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            out.append(json.loads(x))
        except ValueError:
            pass
    return out


def js(p):
    f = OUT / p
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


probes = {p["probe"]: p for p in jl("probes.jsonl")}
phases = jl("phases.jsonl")
wan = jl("sniff-wan.jsonl")
vpn = jl("sniff-vpn.jsonl")
echo = jl("echo.jsonl")
admin = {a["step"]: a for a in jl("admin.jsonl")}
checks = []


def check(name, ok, detail=""):
    checks.append({"check": name, "ok": bool(ok), "detail": str(detail)[:300]})


def seen(pid):
    p = probes.get(pid, {})
    return p.get("rc"), p.get("reply", {}).get("seen_client")


def window(name):
    names = [p["phase"] for p in phases]
    if name not in names:
        return (0, 0)
    i = names.index(name)
    return (phases[i]["t"], phases[i + 1]["t"] if i + 1 < len(phases) else 1e12)


# 1) API и рендер
api = js("api-status.json")
check("API: без сессии 401; preview и сохранение правил ТВ → Hysteria2 и ТВ → Zapret после входа (пароль + TOTP) — 200",
      api == {"noauth": "401", "preview": "200", "save": "200", "save_zapret": "200"}, api)
pv = js("api-preview.json").get("preview", {})
check("preview: выход «Hysteria2», без предупреждения profile_not_ready, отказ закрыт (fail_closed)",
      "Hysteria2" in pv.get("exit", "") and not any(f["code"] == "profile_not_ready" for f in pv.get("findings", []))
      and any(f["code"] == "fail_closed" for f in pv.get("findings", [])), pv.get("exit"))
mh = js("mihomo.config.redacted.json")
px = [p for p in mh.get("proxies", []) if p.get("name") == "hy2-lab"]
p0 = px[0] if px else {}
check("рендер: proxy type hysteria2, проверка TLS не отключена (skip-cert-verify=false), закреплён SHA-256, SNI, obfs salamander, ALPN h3, без username",
      p0.get("type") == "hysteria2" and p0.get("skip-cert-verify") is False and len(p0.get("fingerprint", "")) == 64
      and p0.get("sni") == "vpn.lab.test" and p0.get("obfs") == "salamander" and p0.get("alpn") == ["h3"] and "username" not in p0
      and p0.get("password") == "<скрыт>", {k: v for k, v in p0.items() if k not in ("password", "obfs-password")})
check("рендер: правило Mihomo направляет ТВ в hy2-lab", any("hy2-lab" in r and TV4 in r for r in mh.get("rules", [])), mh.get("rules"))

# 2) применение через netfilter
a1 = admin.get("A1-apply", {})
check("mi-tt-admin apply (netfilter) — 0; guard до запуска Mihomo — 0; revert — 0",
      a1.get("exit") == 0 and admin.get("G0-guard", {}).get("exit") == 0 and admin.get("X1-revert", {}).get("exit") == 0
      and a1.get("out", {}).get("marker") == "netfilter", {s: a.get("exit") for s, a in admin.items()})

# 3) трафик
for ph, label in (("T", "туннель"), ("R", "после восстановления сервера"), ("X", "после повторного apply")):
    tv = [seen(f"{ph}-tv-tcp"), seen(f"{ph}-tv-udp")]
    check(f"{label}: ТВ → группа по TCP и UDP идёт через Hysteria2 (цель видит сервер {VPN})", tv == [(0, VPN), (0, VPN)], tv)
    ph_ = [seen(f"{ph}-phone-tcp"), seen(f"{ph}-phone-udp")]
    check(f"{label}: контрольный телефон → группа по TCP и UDP напрямую (цель видит {PHONE4})", ph_ == [(0, PHONE4), (0, PHONE4)], ph_)
    check(f"{label}: внешний IPv6 ТВ запрещён", seen(f"{ph}-tv-v6")[0] == 1, seen(f"{ph}-tv-v6"))
out = [seen("T-tv-outside-tcp"), seen("T-tv-outside-udp")]
check("ТВ → цель вне группы — без туннеля: Mihomo DIRECT с адреса WAN роутера (правило действует только на группу)", out == [(0, ROUTER_WAN), (0, ROUTER_WAN)], out)
rec = js("recovery.json")
check("после рестарта сервера туннель восстанавливается сам, без перезапуска Mihomo (время измерено)", 0 < rec.get("recovered_after_s", 0) < 80, rec)
for ph, label in (("S", "сервер Hysteria2 остановлен"), ("E", "движок Mihomo остановлен"), ("B", "неверный закреплённый сертификат")):
    tv = [seen(f"{ph}-tv-tcp")[0], seen(f"{ph}-tv-udp")[0], seen(f"{ph}-tv-v6")[0]]
    check(f"{label}: у ТВ нет связи с группой (TCP, UDP, IPv6) — без выхода в обход", tv == [1, 1, 1], [probes.get(f"{ph}-tv-{x}", {}).get("reply") for x in ("tcp", "udp")])
    ph_ = [seen(f"{ph}-phone-tcp"), seen(f"{ph}-phone-udp")]
    check(f"{label}: контрольный телефон продолжает работать напрямую", ph_ == [(0, PHONE4), (0, PHONE4)], ph_)

# 4) пакеты: прямых пакетов от защищённого устройства наружу нет
tv_pk = [p for p in wan if p.get("src") in (TV4, TV6)]
outside_w = [(probes[k]["t0"] - 0.2, probes[k]["t1"] + 0.5) for k in ("T-tv-outside-tcp", "T-tv-outside-udp") if k in probes]
stray = [p for p in tv_pk if not (p.get("dst") == OUTSIDE and any(a <= p["t"] <= b for a, b in outside_w))]
check("сниффер WAN роутера: все пакеты ТВ наружу — только к цели вне группы во время её пробы; к группе и по IPv6 — ни одного",
      len(wan) > 0 and not stray, f"пакетов на WAN: {len(wan)}, от ТВ: {len(tv_pk)}, лишних: {stray[:3]}")
for name, label in (("server_down", "сервер остановлен"), ("engine_down", "движок остановлен"), ("bad_pin", "неверный сертификат")):
    a, b = window(name)
    n = sum(1 for p in tv_pk if a <= p["t"] < b)
    check(f"сниффер WAN, фаза «{label}»: от ТВ 0 пакетов", b > a and n == 0, f"окно {round(b - a, 1)} с, пакетов от ТВ: {n}")
bad_echo = [e for e in echo if e.get("client") in (TV4, TV6) and e.get("service") != f"echo-{OUTSIDE}"]
check("эхо-цели группы ни разу не видели адрес ТВ", not bad_echo, bad_echo[:3])

# 5) транспорт — QUIC (UDP 443), TCP к серверу не используется
tr = [p for p in vpn if {p.get("src"), p.get("dst")} == {ROUTER_WAN, VPN}]
udp443 = [p for p in tr if p.get("proto") == "udp" and 443 in (p.get("sport"), p.get("dport"))]
icmp = [p for p in tr if p.get("proto") == "icmp"]
check("транспорт роутер ↔ сервер: UDP 443 (QUIC Hysteria2) и ICMP «порт недоступен» при остановленном сервере; TCP нет; сервер не слушает TCP 443",
      len(udp443) > 0 and len(udp443) + len(icmp) == len(tr) and js("hy-tcp.json").get("tcp_listen_443") is False,
      f"пакетов транспорта: {len(tr)}, UDP/443: {len(udp443)}, ICMP: {len(icmp)}")
direct_to_vpn = [p for p in vpn if p.get("src") in (TV4, TV6)]
check("к серверу ходит только роутер (адрес ТВ на линке сервера не появляется)", not direct_to_vpn, direct_to_vpn[:2])
hylog = (OUT / "hysteria.log").read_text(encoding="utf-8", errors="replace") if (OUT / "hysteria.log").exists() else ""
check("журнал сервера Hysteria2: клиент подключён, есть TCP- и UDP-запросы к цели",
      "client connected" in hylog and "TCP request" in hylog and "UDP request" in hylog, f"{len(hylog)} байт журнала")

# 6) Zapret (этап 9)
zt = [p for p in wan if p.get("dst") == "10.97.0.10" and p.get("proto") == "tcp" and p.get("dport") == 80 and p.get("plen", 0) > 0]
def first_data(src, probe):
    pr = probes.get(probe, {})
    w = [p for p in zt if p.get("src") == src and pr and pr["t0"] - 0.05 <= p["t"] <= pr["t1"] + 0.05]
    return [p["plen"] for p in w]
zr, pr_, yr = first_data(ROUTER_WAN, "Z-tv-http"), first_data(PHONE4, "Z-phone-http"), first_data(ROUTER_WAN, "Y-tv-http")
zh = probes.get("Z-tv-http", {})
check("Zapret: ТВ → группа «Zapret» по HTTP — ответ 200 через прямой выход движка (цель видит WAN роутера)",
      zh.get("rc") == 0 and zh.get("http") == "200" and zh.get("reply", {}).get("seen_client") == ROUTER_WAN, zh)
full = pr_[0] - 3 if pr_ else 0  # запрос телефона длиннее на 3 байта (X-Probe: Z-phone-http против Z-tv-http)
check("Zapret: первый пакет данных ТВ разрезан nfqws2 (multisplit:pos=2 → сегменты 2 и остаток), цель получила запрос целиком",
      len(zr) >= 2 and zr[0] == 2 and zr[0] + zr[1] == full and zh.get("http") == "200", f"длины сегментов: {zr}, целиком: {full}")
check("контроль: запрос телефона к той же цели не обрабатывается (один сегмент, напрямую без движка)",
      len(pr_) == 1 and pr_[0] > 1 and probes.get("Z-phone-http", {}).get("http") == "200", f"длины: {pr_}")
zq = js("zapret-queue.json")
check("очередь NFQUEUE 200 (MITT_ZQ в mangle OUTPUT): 0 пакетов после фазы туннеля с трафиком Hysteria2 (TCP и UDP), пакеты появились только с запросом Zapret",
      zq.get("before") == 0 and isinstance(zq.get("after_zapret"), int) and 0 < zq["after_zapret"] <= 20, zq)
yh = probes.get("Y-tv-http", {})
check("nfqws2 остановлен: прямой выход Zapret работает без обработки (--queue-bypass), первый пакет не разрезан",
      yh.get("http") == "200" and len(yr) == 1 and yr[0] > 1, f"{yh.get('http')}, длины: {yr}")
nlog = (OUT / "nfqws2.log").read_text(encoding="utf-8", errors="replace") if (OUT / "nfqws2.log").exists() else ""
check("nfqws2 запущен с профилем рендера (multisplit pos=2, http_req и tls_client_hello) и не завершился",
      'multisplit(pos="2"' in nlog and "setgid" not in nlog and "setgroups" not in nlog, f"{len(nlog)} байт журнала nfqws2")
zc = (OUT / "zapret-chain.txt").read_text(encoding="utf-8", errors="replace") if (OUT / "zapret-chain.txt").exists() else ""
check("цепочка MITT_ZQ: tcp multiport 80,443, метка 0x4000/0x4000, NFQUEUE 200 с --queue-bypass",
      "--dports 80,443" in zc and "0x4000/0x4000" in zc and "--queue-num 200" in zc and "--queue-bypass" in zc, zc.strip()[:200])

# 7) категории (этап 11)
ac = jl("api-categories.jsonl")
cu = [(OUT / f).read_text(encoding="utf-8") if (OUT / f).exists() else "" for f in ("category-update-ip.json", "category-update-dom.json")]
check("категории: списки проверены и заменены ARM64-контроллером, правила с назначением «категория» сохранены через API после входа",
      all("exit=0" in x for x in cu) and [a.get("status") for a in ac] == [200, 200], [a.get("status") for a in ac])
check("рендер: rule-providers категорий (ipcidr и domain) и правила RULE-SET для ТВ → hy2-lab",
      mh.get("rule-providers", {}).get("cat-geo-ip", {}).get("behavior") == "ipcidr" and mh.get("rule-providers", {}).get("cat-geo-dom", {}).get("behavior") == "domain"
      and any("RULE-SET,cat-geo-ip" in r and "hy2-lab" in r for r in mh.get("rules", [])), mh.get("rule-providers"))
ci = [seen("C-tv-ip-tcp"), seen("C-tv-ip-udp")]
check("IP-категория: ТВ → 10.95.0.10 по TCP и UDP через Hysteria2; телефон — напрямую", ci == [(0, VPN), (0, VPN)] and seen("C-phone-ip-tcp") == (0, PHONE4), [ci, seen("C-phone-ip-tcp")])
cd = [(probes.get(i, {}).get("http"), probes.get(i, {}).get("reply", {}).get("seen_client")) for i in ("C-tv-dom", "C-tv-sub", "C-tv-other")]
check("доменная категория (по HTTP Host): cat.lab.test и www.cat.lab.test — через Hysteria2; other.lab.test на тот же IP — без туннеля (Mihomo DIRECT)",
      cd == [("200", VPN), ("200", VPN), ("200", ROUTER_WAN)], cd)

leak = js("secret-leak.json")
check("пароль панели, секрет TOTP, пароль и obfs Hysteria2 не попали в артефакты", leak.get("found") == [], leak)

ok = all(c["ok"] for c in checks)
json.dump({"ok": ok, "checks": checks, "probes": list(probes.values())}, open(OUT / "summary.json", "w", encoding="utf-8"), ensure_ascii=False, indent=2)
md = ["| Проверка | Детали | Итог |", "|---|---|---|"] + [f"| {c['check']} | {c['detail'].replace('|', '/')} | {'да' if c['ok'] else 'НЕТ'} |" for c in checks]
(OUT / "summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")
print("\n".join(md))
print(f"проверок: {sum(c['ok'] for c in checks)} из {len(checks)}; проб: {len(probes)}")
print("ИТОГ:", "ПРОЙДЕНО" if ok else "НЕ ПРОЙДЕНО")
sys.exit(0 if ok else 1)
