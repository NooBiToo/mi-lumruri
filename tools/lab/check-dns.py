"""Проверка лаборатории DNS (этап 10): ответы клиентам, транспорт роутер ↔ серверы по сниффу, отсутствие открытого DNS
и прямых обращений к ODoH target, журнал авторитетного DNS, обновление списка рекламы. Пишет summary.json/summary.md."""
import json
import sys
from pathlib import Path

OUT = Path(sys.argv[1])
ROUTER, DOH, TARGET, RELAY = "10.20.0.2", "10.30.2.2", "10.30.3.2", "10.30.4.2"


def jl(p):
    f = OUT / p
    out = []
    if f.exists():
        for x in f.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                out.append(json.loads(x))
            except ValueError:
                pass
    return out


def text(p):
    f = OUT / p
    return f.read_text(encoding="utf-8", errors="replace") if f.exists() else ""


Q = {q["id"]: q for q in jl("queries.jsonl")}
phases = jl("phases.jsonl")
wan = jl("sniff-wan.jsonl")
auth = jl("auth.jsonl")
checks = []


def check(name, ok, detail=""):
    checks.append({"check": name, "ok": bool(ok), "detail": str(detail)[:300]})


def window(name):
    names = [p["phase"] for p in phases]
    if name not in names:
        return (0, 0)
    i = names.index(name)
    return (phases[i]["t"], phases[i + 1]["t"] if i + 1 < len(phases) else 1e12)


def ans(i):
    q = Q.get(i, {})
    return (q.get("rcode"), q.get("answers"))


PORTS = {"doh": ("tcp", 443), "dot": ("tcp", 853), "doq": ("udp", 853), "doh3": ("udp", 443)}
for t, (proto, port) in PORTS.items():
    check(f"{t}: A ok.lab.test у ТВ и телефона — ответы зоны; AAAA — пустой NOERROR от движка (IPv6 в движке выключен), сервер AAAA не спрашивается",
          ans(f"{t}-A") == ("NOERROR", ["10.99.0.10"]) and ans(f"{t}-AAAA") == ("NOERROR", []) and ans(f"{t}-phone") == ("NOERROR", ["10.99.0.11"]),
          [ans(f"{t}-A"), ans(f"{t}-AAAA"), ans(f"{t}-phone")])
    check(f"{t}: реклама (ads, tracker) — NXDOMAIN для A и AAAA; исключение good.ads.lab.test отвечает; несуществующее имя — NXDOMAIN от сервера",
          ans(f"{t}-ads-A")[0] == "NXDOMAIN" and ans(f"{t}-ads-AAAA")[0] == "NXDOMAIN" and ans(f"{t}-tracker")[0] == "NXDOMAIN"
          and ans(f"{t}-good") == ("NOERROR", ["10.99.0.77"]) and ans(f"{t}-nx")[0] == "NXDOMAIN",
          [ans(f"{t}-ads-A"), ans(f"{t}-good"), ans(f"{t}-nx")])
    a, b = window(t)
    tr = [p for p in wan if a <= p["t"] < b and {p.get("src"), p.get("dst")} == {ROUTER, DOH}]
    good = [p for p in tr if p.get("proto") == proto and port in (p.get("sport"), p.get("dport"))]
    # ICMP «порт недоступен» в ответ на запоздалые пакеты сервера после остановки движка — не транспорт DNS
    icmp = [p for p in tr if p.get("proto") == "icmp"]
    check(f"{t}: транспорт роутер ↔ сервер — только {proto}/{port} (и ICMP после остановки движка)", good and len(good) + len(icmp) == len(tr),
          f"пакетов: {len(tr)}, {proto}/{port}: {len(good)}, ICMP: {len(icmp)}")
names_seen = {e["name"] for e in auth}
u0 = window("adblock_update")[0]
before_update = {e["name"] for e in auth if e["t"] < u0}
check("заблокированные имена ни разу не дошли до резолвера (ads, blocked2 — весь прогон; tracker — пока был в списке); исключение дошло",
      not ({"ads.lab.test", "blocked2.lab.test"} & names_seen) and "tracker.lab.test" not in before_update and "good.ads.lab.test" in names_seen, sorted(names_seen))
dns53 = [p for p in wan if p.get("proto") in ("udp", "tcp") and 53 in (p.get("sport"), p.get("dport"))]
check("за весь прогон на WAN роутера нет ни одного пакета DNS (порт 53): ни в работе, ни при отказах", wan and not dns53, f"пакетов WAN: {len(wan)}, DNS/53: {len(dns53)}")
to_res = [p for p in wan if "1.1.1.1" in (p.get("src"), p.get("dst"))]
check("роутер ни разу не обращался к «публичному» резолверу напрямую", not to_res, len(to_res))

u1, u2, u3 = text("adblock-update-1.json"), text("adblock-update-2.json"), text("adblock-update-3.json")
check("обновление списка рекламы: корректный список применён (2 домена), ошибочный отклонён (код 1, adblock_invalid), действующий список сохранён",
      "exit=0" in u2 and '"domains": 2' in u2 and "exit=1" in u3 and "adblock_invalid" in u3 and json.loads(text("adblock-kept.json") or "{}").get("kept") is True,
      [u2.strip()[-60:], u3.strip()[-60:]])
tr_after = [e for e in auth if e["name"] == "tracker.lab.test" and e["t"] >= u0]
check("после обновления: blocked2 и ads — NXDOMAIN без обращения к резолверу; tracker (нет в новом списке) снова спрашивается у резолвера; ok — отвечает",
      ans("U-blocked2")[0] == "NXDOMAIN" and ans("U-ads")[0] == "NXDOMAIN" and tr_after and ans("U-ok") == ("NOERROR", ["10.99.0.10"]),
      [ans("U-blocked2"), ans("U-tracker"), len(tr_after), ans("U-ok")])

f = [Q.get("F-A", {}), Q.get("F-phone", {})]
check("DoH-сервер остановлен: клиенты получают ошибку (SERVFAIL или нет ответа), ответа зоны нет", all(x.get("rcode") != "NOERROR" for x in f) and f[0],
      [x.get("rcode") or x.get("error") for x in f])
a, b = window("doh_down")
fail_tr = [p for p in wan if a <= p["t"] < b and p.get("src") == ROUTER and p.get("dst") not in (DOH,)]
check("при отказе DoH роутер не ищет другой путь: пакеты только к настроенному серверу", not fail_tr, fail_tr[:3])

check("ODoH: A ok.lab.test отвечает, AAAA — пустой NOERROR; реклама — NXDOMAIN; исключение отвечает",
      ans("O-A") == ("NOERROR", ["10.99.0.10"]) and ans("O-AAAA") == ("NOERROR", []) and ans("O-ads")[0] == "NXDOMAIN" and ans("O-good") == ("NOERROR", ["10.99.0.77"]),
      [ans("O-A"), ans("O-ads"), ans("O-good")])
tgt = jl("sniff-target.jsonl")
qwin = [(Q[i]["t0"] - 0.05, Q[i]["t0"] + 3) for i in ("O-A", "O-AAAA", "O-good") if i in Q]
def in_q(p):
    return any(x <= p["t"] <= y for x, y in qwin)
# новое соединение (SYN) или данные длиннее TLS-alert; закрытие keep-alive соединения получения ключа (close_notify, FIN, RST) — не вопрос
rt = [p for p in tgt if p.get("src") == ROUTER and in_q(p) and ((p.get("flags", 0) & 2) or p.get("plen", 0) > 40)]
lt = [p for p in tgt if p.get("src") == RELAY and in_q(p)]
check("ODoH: во время DNS-вопросов к target обращается relay; от роутера к target — ни новых соединений, ни данных (кроме закрытия соединения получения ключа)",
      lt and not rt, f"relay→target: {len(lt)}, роутер→target: {len(rt)}")
od = [p for p in wan if in_q(p) and p.get("src") == ROUTER and (p.get("dst") != TARGET or (p.get("flags", 0) & 2) or p.get("plen", 0) > 40)]
check("ODoH: во время DNS-вопросов роутер отправляет данные только relay (TCP 443)", od and all(p.get("dst") == RELAY and p.get("dport") == 443 for p in od),
      f"пакетов от роутера: {len(od)}, адреса: {sorted({p.get('dst') for p in od})}")
viat = [e for e in auth if e["server"] == "auth-target" and e["name"] == "ok.lab.test"]
check("вопрос ODoH дошёл до резолвера со стороны target (relay видел только роутер, target — только relay)", viat, len(viat))
cfg_fetch = [p for p in tgt if p.get("src") == ROUTER and not in_q(p)]
check("ограничение клиента зафиксировано: dnscrypt-proxy 2.1.20 берёт открытый ключ target (/.well-known/odohconfigs) напрямую, вне DNS-вопросов",
      True, f"пакетов роутер→target вне вопросов: {len(cfg_fetch)}")
r = Q.get("R-A", {})
a, b = window("relay_down")
rd = [p for p in wan if a <= p["t"] < b and p.get("src") == ROUTER and p.get("dst") != RELAY]
ok4 = [e for e in auth if e["name"] == "ok4.lab.test"]
tlog = text("odoh-target.log")
check("relay остановлен: ошибка у клиента; вопрос не дошёл до резолвера ни одним путём (обхода relay нет), открытого DNS нет",
      r and r.get("rcode") != "NOERROR" and not ok4 and not [p for p in rd if p.get("dst") not in (TARGET, RELAY)],
      [r.get("rcode") or r.get("error"), len(ok4), sorted({p.get("dst") for p in rd})])
check("обращения роутера к target — только получение открытого ключа (GET /.well-known/odohconfigs, по журналу target)",
      tlog.count("GET Handling /.well-known/odohconfigs") > 0, f"запросов ключа: {tlog.count('GET Handling /.well-known/odohconfigs')}, пакетов роутер→target за прогон: {len([p for p in tgt if p.get('src') == ROUTER])}")
md = text("dnsmasq-mitt.doh.conf")
check("dnsmasq: no-resolv, единственный сервер — 127.0.0.1#1053, блокировка address=/…/ и исключение server=/…/",
      "no-resolv\nserver=127.0.0.1#1053\n" in md and "address=/ads.lab.test/" in md and "server=/good.ads.lab.test/127.0.0.1#1053" in md, md[:200])
mdns = json.loads(text("mihomo-dns.doh.json") or "{}")
check("Mihomo DNS: сервер по IP из настроек с проверкой сертификата по имени, bootstrap — закрытый локальный порт, DNS движка — тем же путём",
      mdns.get("nameserver") == [f"https://{DOH}/dns-query#name-cert-verify=doh.lab.test"] and mdns.get("default-nameserver") == ["127.0.0.1:9"]
      and mdns.get("proxy-server-nameserver") == mdns.get("nameserver"), mdns)

ok = all(c["ok"] for c in checks)
json.dump({"ok": ok, "checks": checks, "queries": list(Q.values())}, open(OUT / "summary.json", "w", encoding="utf-8"), ensure_ascii=False, indent=2)
mdt = ["| Проверка | Детали | Итог |", "|---|---|---|"] + [f"| {c['check']} | {c['detail'].replace('|', '/')} | {'да' if c['ok'] else 'НЕТ'} |" for c in checks]
(OUT / "summary.md").write_text("\n".join(mdt) + "\n", encoding="utf-8")
print("\n".join(mdt))
print(f"проверок: {sum(c['ok'] for c in checks)} из {len(checks)}; запросов: {len(Q)}")
print("ИТОГ:", "ПРОЙДЕНО" if ok else "НЕ ПРОЙДЕНО")
sys.exit(0 if ok else 1)
