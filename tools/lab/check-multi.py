"""Проверка лаборатории этапа 8 (VLESS-REALITY и AmneziaWG одновременно) по наблюдениям: ответы эхо-целей,
сниффер WAN роутера (пакеты защищённых источников наружу), сниффер транспорта (TCP 443 VLESS, UDP 51820 AmneziaWG
с изменёнными заголовками), счётчики peer AmneziaWG, коды mi-tt-admin и API. Пишет summary.json/summary.md."""
import json
import os
import struct
import sys
from pathlib import Path

OUT = Path(sys.argv[1])
TV = ("10.10.1.2", "fd00:10::2")
LAP = ("10.10.2.2", "fd00:11::2")
PHONE, VLESS, AWG, WAN, SRV = "10.10.1.3", "10.30.0.2", "10.66.66.2", "10.20.0.2", "10.30.0.2"
H1 = 1361409513
MODE = os.environ.get("VLESS_MODE", "tls")


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


def js(p):
    try:
        return json.loads((OUT / p).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


probes = {p["probe"]: p for p in jl("probes.jsonl")}
phases = jl("phases.jsonl")
admin = {a["step"]: a for a in jl("admin.jsonl")}
checks = []


def check(name, ok, detail=""):
    checks.append({"check": name, "ok": bool(ok), "detail": str(detail)[:300]})


def seen(pid):
    p = probes.get(pid, {})
    return (p.get("rc"), p.get("reply", {}).get("seen_client"))


DOWN = (1, None)
EXPECT = {
    "P": ("оба профиля работают", VLESS, AWG, WAN),
    "V": ("сервер VLESS остановлен", None, AWG, WAN),
    "A": ("peer AmneziaWG остановлен", VLESS, None, WAN),
    "E": ("Mihomo остановлен", None, None, None),
    "B": ("неверные h1 AmneziaWG и " + ("ключ REALITY" if MODE == "reality" else "закреплённый сертификат VLESS"), None, None, WAN),
    "G": ("загрузка: guard до запуска Mihomo", None, None, None),
    "Z": ("после «перезагрузки» и apply", VLESS, AWG, WAN),
}
for ph, (label, tv, lap, lap_other) in EXPECT.items():
    got = [seen(f"{ph}-tv-tcp"), seen(f"{ph}-tv-udp")]
    want = [(0, tv), (0, tv)] if tv else [DOWN, DOWN]
    check(f"{label}: ТВ → «Видео» TCP/UDP {'через VLESS (' + tv + ')' if tv else '— нет связи, без обхода'}", [(r, c if r == 0 else None) for r, c in got] == want, got)
    got = [seen(f"{ph}-lap-tcp"), seen(f"{ph}-lap-udp")]
    want = [(0, lap), (0, lap)] if lap else [DOWN, DOWN]
    check(f"{label}: гостевая сеть (SSID) → «Видео» TCP/UDP {'через AmneziaWG (' + lap + ')' if lap else '— нет связи, без обхода'}",
          [(r, c if r == 0 else None) for r, c in got] == want, got)
    o = seen(f"{ph}-lap-other")
    check(f"{label}: гостевая сеть → цель вне правил {'— Mihomo DIRECT с WAN роутера' if lap_other else '— нет связи'}",
          (o == (0, lap_other)) if lap_other else o[0] == 1, o)
    check(f"{label}: ТВ → «Широкая» (пересекается с «Видео», правило ниже) — блок; внешний IPv6 ТВ — запрещён",
          seen(f"{ph}-tv-wide")[0] == 1 and seen(f"{ph}-tv-v6")[0] == 1, (seen(f"{ph}-tv-wide"), seen(f"{ph}-tv-v6")))
    check(f"{label}: контрольный телефон → «Видео» TCP/UDP напрямую", [seen(f"{ph}-phone-tcp"), seen(f"{ph}-phone-udp")] == [(0, PHONE), (0, PHONE)],
          [seen(f"{ph}-phone-tcp"), seen(f"{ph}-phone-udp")])

wan = jl("sniff-wan.jsonl")
leak = [p for p in wan if p.get("src") in TV + LAP]
check("сниффер WAN за весь прогон: ни одного пакета ТВ или гостевой сети наружу (все фазы, включая отказы и загрузку)",
      len(wan) > 0 and not leak, f"пакетов на WAN: {len(wan)}, от защищённых источников: {len(leak)} {leak[:2]}")
echo = jl("echo.jsonl")
check("эхо-цели ни разу не видели адреса ТВ и гостевой сети", not [e for e in echo if e.get("client") in TV + LAP], len(echo))

vpn = jl("sniff-vpn.jsonl")
tr = [p for p in vpn if {p.get("src"), p.get("dst")} == {WAN, SRV}]
tcp443 = [p for p in tr if p.get("proto") == "tcp" and 443 in (p.get("sport"), p.get("dport"))]
udp51820 = [p for p in tr if p.get("proto") == "udp" and 51820 in (p.get("sport"), p.get("dport"))]
other = [p for p in tr if p not in tcp443 and p not in udp51820 and p.get("proto") != "icmp"]
check("транспорт роутер ↔ сервер: VLESS по TCP 443, AmneziaWG по UDP 51820, другого нет", tcp443 and udp51820 and not other,
      f"TCP/443: {len(tcp443)}, UDP/51820: {len(udp51820)}, прочее: {len(other)}")
std = [p for p in udp51820 if p.get("head") in ("01000000", "02000000", "03000000", "04000000")]
# AWG 1.0: init = s1 случайных байт + сообщение 148 байт (тип h1), response = s2 + 92 (тип h2); обычный WG — 148 и 92
init = [p for p in udp51820 if p.get("dport") == 51820 and p.get("len") == 148 + 37]
resp = [p for p in udp51820 if p.get("sport") == 51820 and p.get("len") == 92 + 61]
plain = [p for p in udp51820 if p.get("len") in (148, 92)]
junk = [p for p in udp51820 if p.get("dport") == 51820 and 40 <= p.get("len", 0) <= 70]
check("AmneziaWG на проводе: нет заголовков и размеров обычного WireGuard (148/92), init = s1+148, response = s2+92, мусорные пакеты jmin..jmax перед рукопожатием",
      udp51820 and not std and not plain and init and resp and junk, f"заголовков WG: {len(std)}, размеров WG: {len(plain)}, init: {len(init)}, response: {len(resp)}, мусорных: {len(junk)}")
bad = js("awg-bad-params.json")
b0, b1 = bad.get("before") or {}, bad.get("after") or {}
check("peer AmneziaWG с неверным h1 у клиента рукопожатие не принял: время последнего рукопожатия не изменилось",
      b0.get("last_handshake_time_sec") not in (None, "0") and b0.get("last_handshake_time_sec") == b1.get("last_handshake_time_sec"), bad)
try:
    xa = int((OUT / "xray-accepted.count").read_text().strip())
except (OSError, ValueError):
    xa = 0
check("журнал Xray: соединения к целям приняты сервером VLESS", xa > 0, xa)

mh = js("mihomo.config.redacted.json")
px = {p["name"]: p for p in mh.get("proxies", [])}
v, a = px.get("vless-lab", {}), px.get("awg-lab", {})
vok = set(v.get("reality-opts", {})) == {"public-key", "short-id"} if MODE == "reality" else (len(v.get("fingerprint", "")) == 64 and "reality-opts" not in v)
check(f"рендер VLESS ({MODE}): tls, " + ("reality-opts (public-key, short-id)" if MODE == "reality" else "закреплённый SHA-256 сертификата") + ", servername, flow xtls-rprx-vision, client-fingerprint, skip-cert-verify=false, uuid скрыт",
      v.get("type") == "vless" and v.get("tls") is True and vok and v.get("servername") == "vpn.lab.test"
      and v.get("flow") == "xtls-rprx-vision" and v.get("client-fingerprint") == "chrome" and v.get("skip-cert-verify") is False and v.get("uuid") == "<скрыт>",
      {k: x for k, x in v.items() if k != "uuid"})
check("рендер AmneziaWG: wireguard + amnezia-wg-option (jc, jmin, jmax, s1, s2, h1–h4), ip, public-key, private-key скрыт",
      a.get("type") == "wireguard" and set(a.get("amnezia-wg-option", {})) == {"jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4"} and a.get("ip") == AWG
      and a.get("private-key") == "<скрыт>", {k: x for k, x in a.items() if k != "private-key"})
rules = mh.get("rules", [])
check("порядок правил Mihomo: ТВ «Видео» → VLESS раньше ТВ «Широкая» → REJECT; гостевая сеть → AmneziaWG",
      any("vless-lab" in r for r in rules) and any("awg-lab" in r for r in rules)
      and [i for i, r in enumerate(rules) if "vless-lab" in r][0] < [i for i, r in enumerate(rules) if "10.96.0.0/14" in r and "REJECT" in r][0], rules)
api = jl("api.jsonl")
check("три правила (устройство, SSID, пересечение групп) сохранены через API после входа", [x["status"] for x in api] == [200, 200, 200], api)
ok_steps = {s: x.get("exit") for s, x in admin.items()}
check("mi-tt-admin: guard, apply, revert, guard при загрузке, apply после загрузки — 0",
      all(ok_steps.get(s) == 0 for s in ("G0-guard", "A1-apply", "B0-apply-bad-params", "R0-revert", "R1-guard-at-boot", "R2-apply-after-boot", "X1-revert")), ok_steps)
lk = js("secret-leak.json")
check("пароль панели, TOTP, UUID VLESS, закрытые ключи AmneziaWG и REALITY не попали в артефакты", lk.get("found") == [], lk)

ok = all(c["ok"] for c in checks)
json.dump({"ok": ok, "checks": checks, "probes": list(probes.values())}, open(OUT / "summary.json", "w", encoding="utf-8"), ensure_ascii=False, indent=2)
md = ["| Проверка | Детали | Итог |", "|---|---|---|"] + [f"| {c['check']} | {c['detail'].replace('|', '/')} | {'да' if c['ok'] else 'НЕТ'} |" for c in checks]
(OUT / "summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")
print("\n".join(md))
print(f"проверок: {sum(c['ok'] for c in checks)} из {len(checks)}; проб: {len(probes)}")
print("ИТОГ:", "ПРОЙДЕНО" if ok else "НЕ ПРОЙДЕНО")
sys.exit(0 if ok else 1)
