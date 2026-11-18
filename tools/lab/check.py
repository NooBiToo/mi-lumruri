"""Проверка прогона лаборатории (этап 4) по наблюдениям: клиент (curl), цель и управление роутера (журналы),
сервер TrustTunnel и Mihomo (журналы), mi-tt-admin (коды и JSON), снимки правил, маршрутов и tc роутера.
Пишет summary.json и summary.md; код выхода 0 — всё совпало с ожиданиями."""
import json
import os
import re
import sys
from pathlib import Path

OUT = Path(sys.argv[1])
MARKER = os.environ.get("MARKER", "tc")
TV, TV_NEW, PHONE, LAPTOP, LAPTOP_NEW = "10.10.1.2", "10.10.1.50", "10.10.1.3", "10.10.2.2", "10.10.2.77"
TV6, TV6_NEW, PHONE6, LAPTOP6 = "fd00:10::2", "fd00:10::99", "fd00:10::3", "fd00:11::2"
ROUTER_WAN, VPN = "10.20.0.2", "10.30.0.2"


def jl(p):
    f = OUT / p
    return [json.loads(x) for x in f.read_text(encoding="utf-8").splitlines() if x.strip()] if f.exists() else []


def text(p):
    f = OUT / p
    return f.read_text(encoding="utf-8", errors="replace") if f.exists() else ""


probes = {p["probe"]: p for p in jl("probes.jsonl")}
seen = {}
for r in jl("target.log") + jl("target6.log") + jl("mgmt.log") + jl("mgmt6.log"):
    seen.setdefault(r["probe"], []).append(r)
admin = {a["step"]: a for a in jl("admin.jsonl")}

# (проба, допустимые адреса источника у цели/управления или None — запрос не должен дойти ни до кого, описание)
EXPECT = [
    ("B1-tv-group", {TV}, "до применения: ТВ напрямую"),
    ("B2-tv-v6", {TV6}, "до применения: IPv6 ТВ напрямую"),
    ("B3-laptop-group", {LAPTOP}, "до применения: ноутбук напрямую"),
    ("B4-laptop-v6", {LAPTOP6}, "до применения: IPv6 ноутбука напрямую"),
    ("G1-tv-group", None, "guard (Mihomo не запущен): ТВ → группа отказ"),
    ("G2-tv-mgmt", {TV}, "guard: управление роутером по IPv4"),
    ("G3-tv-mgmt6", {TV6}, "guard: управление роутером по IPv6 (локальный адрес роутера)"),
    ("G4-tv-v6", None, "guard: внешний IPv6 ТВ запрещён"),
    ("G5-phone-group", {PHONE}, "guard: телефон на том же мосту напрямую"),
    ("G6-phone-v6", {PHONE6}, "guard: IPv6 телефона напрямую"),
    ("G7-laptop-group", None, "guard: гостевая сеть → группа отказ"),
    ("G8-laptop-mgmt", {LAPTOP}, "guard: управление роутером из гостевой сети"),
    ("G9-laptop-v6", None, "guard: внешний IPv6 гостевой сети запрещён"),
    ("P1-tv-group", {VPN}, "ТВ → группа через TrustTunnel"),
    ("P2-tv-domain", {VPN}, "ТВ → домен группы через TrustTunnel"),
    ("P3-tv-outside", {ROUTER_WAN}, "ТВ → вне группы: Mihomo DIRECT"),
    ("P4-phone-group", {PHONE}, "телефон (тот же мост) напрямую"),
    ("P5-laptop-group", {VPN}, "гостевая сеть (политика сети) → группа через TrustTunnel"),
    ("P6-laptop-outside", {ROUTER_WAN}, "гостевая сеть → вне группы: Mihomo DIRECT"),
    ("P7-tv-mgmt", {TV}, "управление роутером при захвате"),
    ("P8-tv-mgmt6", {TV6}, "управление роутером по IPv6 при захвате"),
    ("P9-tv-v6", None, "внешний IPv6 ТВ запрещён"),
    ("P10-phone-v6", {PHONE6}, "IPv6 телефона напрямую"),
    ("P11-laptop-v6", None, "внешний IPv6 гостевой сети запрещён"),
    ("C1-tv-newip-group", None, "ТВ сменил IPv4 без apply: группа — отказ, не напрямую"),
    ("C2-tv-newip-outside", None, "ТВ с новым IPv4 без apply: весь внешний трафик блокируется до apply"),
    ("C3-tv-newip-mgmt", {TV_NEW}, "ТВ с новым IPv4: управление роутером доступно"),
    ("C4-tv-newv6-external", None, "новый IPv6 ТВ без apply: внешний IPv6 запрещён"),
    ("C5-tv-newv6-mgmt6", {TV6_NEW}, "новый IPv6 ТВ: управление роутером по IPv6 доступно"),
    ("C6-laptop-newip-group", {VPN}, "ноутбук сменил IPv4 внутри гостевой подсети: через TrustTunnel без apply"),
    ("C7-laptop-outsidesubnet-group", None, "адрес вне гостевой подсети на гостевом порту: отказ"),
    ("C8-phone-group-unaffected", {PHONE}, "телефон не затронут"),
    ("C9a-tv-newip-group-stale-mihomo", None, "apply с новой арендой, Mihomo ещё со старой конфигурацией: отказ (REJECT неизвестного источника), не DIRECT"),
    ("C9-tv-newip-group-after-apply", {VPN}, "после перезапуска Mihomo и apply: ТВ с новым адресом через TrustTunnel"),
    ("D2-tv-group-during-drift", {TV_NEW}, "ДРЕЙФ: ядро потеряло фильтр ТВ — защиты нет, пока не выполнен apply (status это показывает)"),
    ("D4-tv-group-restored", {VPN}, "после apply дрейф устранён"),
    ("R2-tv-group-unprotected-before-boot-apply", {TV_NEW}, "ПОСЛЕ ПЕРЕЗАГРУЗКИ до apply --guard-only защиты нет: шаг загрузки обязателен"),
    ("R4-tv-group-boot-guard", None, "загрузка: guard до Mihomo — ТВ → группа отказ"),
    ("R5-laptop-group-boot-guard", None, "загрузка: guard до Mihomo — гостевая сеть → группа отказ"),
    ("R7-tv-group-after-boot", {VPN}, "после запуска Mihomo и apply — через TrustTunnel"),
    ("T1-tv-group-tunnel-down", None, "туннель остановлен: ТВ → группа отказ"),
    ("T2-laptop-group-tunnel-down", None, "туннель остановлен: гостевая сеть → группа отказ"),
    ("T3-phone-group-tunnel-down", {PHONE}, "туннель остановлен: телефон напрямую"),
    ("T4-tv-outside-tunnel-down", {ROUTER_WAN}, "туннель остановлен: ТВ вне группы работает"),
    ("E2-tv-group-engine-down", None, "Mihomo остановлен: ТВ → группа отказ (unreachable)"),
    ("E3-laptop-group-engine-down", None, "Mihomo остановлен: гостевая сеть → группа отказ"),
    ("E4-tv-mgmt-engine-down", {TV_NEW}, "Mihomo остановлен: управление роутером доступно"),
    ("E5-phone-group-engine-down", {PHONE}, "Mihomo остановлен: телефон напрямую"),
    ("E7-tv-group-restored", {VPN}, "восстановление: ТВ через TrustTunnel"),
    ("E8-laptop-group-restored", {VPN}, "восстановление: гостевая сеть через TrustTunnel"),
    ("X3-tv-group-after-revert", {TV_NEW}, "после revert ТВ напрямую"),
    ("X4-tv-v6-after-revert", {TV6, TV6_NEW}, "после revert IPv6 ТВ работает"),
    ("X5-laptop-group-after-revert", {LAPTOP_NEW}, "после revert ноутбук напрямую"),
]

rows, ok_all = [], True
for pid, want, title in EXPECT:
    p = probes.get(pid)
    got = seen.get(pid, [])
    clients = sorted({r["client"] for r in got})
    if p is None:
        ok, note = False, "проба не выполнялась"
    elif want is None:
        ok = p["curl_exit"] != 0 and not got
        note = f"curl={p['curl_exit']} ({p['error'][:60]}); записей у цели/управления: {len(got)}"
    else:
        try:
            body = json.loads(p["body"]) if p["body"] else {}
        except ValueError:
            body = {}
        ok = p["curl_exit"] == 0 and p["http"] == "200" and body.get("seen_client") in want and len(clients) == 1 and clients[0] in want
        note = f"клиент: seen_client={body.get('seen_client')} ({body.get('service')}); журнал: {clients}"
    ok_all &= ok
    rows.append({"probe": pid, "expect": " или ".join(sorted(want)) if want else "нет соединения", "title": title, "ok": ok, "observed": note})


def adm(step):
    return admin.get(step, {"exit": None, "out": {}})


def snapf(name):
    return text(f"snap/{name}.txt")


checks = []


def check(title, ok, observed):
    global ok_all
    ok_all &= bool(ok)
    checks.append({"check": title, "ok": bool(ok), "observed": observed})


def code(step):
    e = adm(step)["out"].get("error")
    return e.get("code") if isinstance(e, dict) else None


i1, i2 = adm("I1-missing-port"), adm("I2-port-outside-bridge")
check("интерфейсы проверяются до применения: несуществующий порт → отказ (2), ничего не изменено",
      i1["exit"] == 2 and code("I1-missing-port") == "interfaces" and snapf("zone.00a-badport").strip() == "", f"exit={i1['exit']} {i1['out'].get('issues')}")
check("порт не своего моста → отказ (2)", i2["exit"] == 2 and code("I2-port-outside-bridge") == "interfaces", f"exit={i2['exit']} {i2['out'].get('issues')}")
a1 = adm("A1-guard")
check("apply --guard-only: фаза guard, проверено по ядру", a1["exit"] == 0 and a1["out"].get("phase") == "guard" and a1["out"].get("verified"), f"exit={a1['exit']}")
a3, a3s = adm("A3-partial-failure"), adm("A3s-status-after-partial")
steps, rb = a3["out"].get("steps", []), a3["out"].get("rollback", [])
check("частичный отказ: шаг TUN упал, выполненные шаги откатаны, ни правил, ни наших tc не осталось",
      a3["exit"] == 4 and steps and steps[-1].get("ok") is False and rb and all(s.get("ok") for s in rb) and snapf("zone.03-after-partial").strip() == "",
      f"exit={a3['exit']} шагов={len(steps)}, последний: {steps[-1].get('error', '')[:70] if steps else '-'}; откат={len(rb)}; зона: {snapf('zone.03-after-partial').strip()!r}")
check("после частичного отказа журнал согласован", a3s["exit"] == 0 and a3s["out"].get("phase") == "reverted", f"exit={a3s['exit']} phase={a3s['out'].get('phase')}")
check("параллельное изменение заблокировано", adm("A5-locked")["exit"] == 6, f"exit={adm('A5-locked')['exit']}")
a6, a7 = adm("A6-apply"), adm("A7-repeat")
check("полное применение, проверено по ядру", a6["exit"] == 0 and a6["out"].get("phase") == "applied" and a6["out"].get("verified"), f"exit={a6['exit']} шагов={len(a6['out'].get('steps', []))}")
check("повтор — без изменений", a7["exit"] == 0 and a7["out"].get("noop") is True, f"noop={a7['out'].get('noop')}")
k1, k2 = adm("A7c-status-after-crash"), adm("A7d-apply-after-crash")
check("сбой посреди apply (фильтр в pending): status незавершён, apply согласует без изменений ядра",
      k1["exit"] == 1 and k1["out"].get("pending") and k2["exit"] == 0 and k2["out"].get("noop") is True, f"status={k1['exit']} apply={k2['exit']} noop={k2['out'].get('noop')}")
a8 = adm("A8-status-addr-changed")
srcs = a8["out"].get("sources", [])
check("status видит у защищённого MAC адреса вне плана (новые IPv4/IPv6)", any("вне плана" in s.get("note", "") for s in srcs), json.dumps(srcs, ensure_ascii=False)[:200])
a9 = adm("A9-apply-new-lease")
a9_steps = a9["out"].get("steps", [])
check("apply с новой арендой меняет только записи ТВ (старый адрес → новый)", a9["exit"] == 0 and 1 <= len(a9_steps) <= 4
      and all("10.10.1.50" in x["entry"] or "10.10.1.2 " in x["entry"] + " " or "10.10.1.2/" in x["entry"] for x in a9_steps), f"exit={a9['exit']} шаги={[s['op'] + ' ' + s['entry'] for s in a9['out'].get('steps', [])]}")
if MARKER == "tc":
    kchecks = [("K1-foreign-rule-in-zone", "чужое правило в зоне"), ("K2-foreign-mark-overlap", "чужое правило на битах наших меток"),
               ("K3-foreign-tc-in-zone", "чужой фильтр tc в нашем диапазоне pref"), ("K4-foreign-tc-before-ours", "чужой фильтр tc раньше нашего"),
               ("K5-firewall-mark-overlap", "MARK в firewall (iptables-save) на наших битах")]
else:
    kchecks = [("K1-foreign-rule-in-zone", "чужое правило в зоне"), ("K3-foreign-rule-in-our-chain", "чужое правило внутри MITT_FWD"),
               ("K4-untracked-mitt-chain", "неучтённая цепочка MITT_* (ip6tables)"), ("K5-untracked-jump", "неучтённый переход в MITT_FWD")]
    k2 = adm("K2-foreign-mark-overlap")
    check("netfilter-путь не использует метки: чужое fwmark 0x10000/0xff0000 не конфликт, apply без изменений", k2["exit"] == 0 and k2["out"].get("noop") is True, f"exit={k2['exit']}")
for step, what in kchecks:
    a = adm(step)
    check(f"{what}: отказ без изменений (3)", a["exit"] == 3 and a.get("outside_unchanged"), f"exit={a['exit']} {str(a['out'].get('conflicts'))[:150]}")
check("после устранения конфликтов apply — без изменений", adm("K6-clean-after-conflicts")["exit"] == 0 and adm("K6-clean-after-conflicts")["out"].get("noop"), "")
d1, d3 = adm("D1-status-drift"), adm("D3-restore")
check("дрейф виден в status", d1["exit"] == 1 and len(d1["out"].get("missing", [])) == 2, f"missing={d1['out'].get('missing')}")
check("apply восстанавливает только недостающее", d3["exit"] == 0 and len(d3["out"].get("steps", [])) == 2, f"шагов={len(d3['out'].get('steps', []))}")
r1, r3, r6 = adm("R1-status-after-reboot"), adm("R3-boot-guard"), adm("R6-apply-after-engine")
check("после «перезагрузки» status показывает потерю всех записей", r1["exit"] == 1 and len(r1["out"].get("missing", [])) >= 10, f"missing={len(r1['out'].get('missing', []))}")
check("загрузка: apply --guard-only восстанавливает метки и запреты, затем apply — TUN", r3["exit"] == 0 and r3["out"].get("phase") == "guard" and r6["exit"] == 0 and r6["out"].get("phase") == "applied", f"guard={r3['exit']} apply={r6['exit']}")
e1 = adm("E1-status-engine-down")
check("status при остановленном Mihomo", "блокируется" in str(e1["out"].get("protection")) and e1["out"].get("tun_present") is False, str(e1["out"].get("protection")))
x1, x2 = adm("X1-revert"), adm("X2-status")
check("revert снимает все свои записи и наши tc", x1["exit"] == 0 and snapf("zone.14-reverted").strip() == "" and x2["out"].get("phase") == "reverted", f"зона: {snapf('zone.14-reverted').strip()!r}")
changed = [s for s, a in admin.items() if not a.get("outside_unchanged")]
check("вне зоны (чужие правила, все таблицы кроме 3100, чужой clsact и фильтр на br-lan) ничего не менялось ни при одном вызове mi-tt-admin",
      not changed and len(admin) >= 30, f"вызовов: {len(admin)}, с изменениями вне зоны: {changed or 'нет'}")
check("чужой clsact и фильтр pref 2000 на br-lan сохранены после revert",
      snapf("foreign-tc.16-final") == snapf("foreign-tc.00-initial") and "pref 2000" in snapf("foreign-tc.00-initial"), snapf("foreign-tc.16-final").strip()[:150])
check("таблицы маршрутов после revert совпадают с исходными", snapf("routing.00-initial") == snapf("routing.16-final") and "10.66.0.0/24" in snapf("routing.16-final"),
      f"строк: {len(snapf('routing.00-initial').splitlines())} → {len(snapf('routing.16-final').splitlines())}")
check("чужие правила после revert и остановки Mihomo совпадают с исходными", snapf("foreign-rules.16-final") == snapf("foreign-rules.00-initial"), "")
check("Mihomo (ipv6: false) не добавил правил вне зоны при запуске", snapf("foreign-rules.05-before-mihomo") == snapf("foreign-rules.05-mihomo-started"),
      "; ".join(sorted(set(snapf("foreign-rules.05-mihomo-started").splitlines()) - set(snapf("foreign-rules.05-before-mihomo").splitlines()))) or "ничего")
au = json.loads(text("auth.json") or "{}")
ast = json.loads(text("auth-status.json") or "{}")
check("вход (ARM64): без подтверждения TOTP и без сессии API закрыт (503/401); одного пароля мало",
      au.get("unconfirmed") == "503 auth_not_configured" and au.get("noauth") == "401 auth_required"
      and au.get("pending_only") == "401 auth_required" and au.get("pending_as_sess") == "401 auth_required", str({k: au.get(k) for k in ("unconfirmed", "noauth", "pending_only", "pending_as_sess")}))
check("вход (ARM64): пароль → TOTP даёт сессию; повтор кода отклонён; recovery-код одноразовый; POST без CSRF отклонён",
      au.get("login") == "200" and au.get("second") == "200" and au.get("replay") == "401 code_reused" and au.get("recovery") == "200"
      and au.get("recovery_again") == "401 invalid_code" and au.get("nocsrf") == "403 csrf_failed", str({k: au.get(k) for k in ("second", "replay", "recovery", "recovery_again", "nocsrf")}))
check("вход (ARM64): cookie __Host- Secure/HttpOnly/SameSite=Strict; каталоги 700, auth.json 600; Argon2id по умолчанию",
      all(f in au.get("cookie_attrs", "") for f in ("Path=/", "Secure", "HttpOnly", "SameSite=Strict"))
      and (au.get("perm_auth_dir"), au.get("perm_auth_json"), au.get("perm_session_dir")) == ("700", "600", "700")
      and ast.get("kdf") == "argon2id m=19456,t=2,p=1" and ast.get("permissions") == {"auth_dir": "700", "auth_json": "600"},
      f"{au.get('cookie_attrs')}; {au.get('perm_auth_dir')}/{au.get('perm_auth_json')}/{au.get('perm_session_dir')}; {ast.get('kdf')}; init {au.get('init_ms')} мс, пароль {au.get('login_password_ms')} мс (qemu)")
leak = json.loads(text("secret-leak.json") or "{}")
check("пароль, секрет TOTP и recovery-коды не попали в артефакты и журналы лаборатории", leak.get("found") == [], str(leak))
check("mi-tt-admin в CGI-окружении отказывается (77)", json.loads(text("admin-under-cgi.json") or "{}").get("exit") == 77, "")
ndp = json.loads(text("ndp.json") or "{}")
check("с нового IPv6 ТВ локальный обмен с роутером (NDP + ICMPv6) работает", ndp.get("ndp_ping_router_from_new_v6") == 0, str(ndp))
plan = adm("A0-plan")["out"]
desired = plan.get("desired", [])
if MARKER == "tc":
    check("план (tc): метка ТВ по MAC на br-lan, метка гостевой сети на порту r-gst, чужой clsact br-lan не создаётся заново",
          any("flower src_mac 02:00:00:00:0a:02" in x and "br-lan" in x for x in desired) and any("dev r-gst" in x and "matchall" in x for x in desired)
          and not any(x == "tc qdisc dev br-lan clsact" for x in desired), "; ".join(x for x in desired if x.startswith("tc")))
else:
    check("план (netfilter): привязка MAC↔IP ТВ в FORWARD (IPv4 и IPv6), гостевая сеть по iif br-guest, без tc и без меток",
          plan.get("marker") == "netfilter"
          and "iptables -w -t filter -A MITT_FWD ! -s 10.10.1.2/32 -i br-lan -m mac --mac-source 02:00:00:00:0a:02 -j REJECT --reject-with icmp-port-unreachable" in desired
          and "ip6tables -w -t filter -A MITT_FWD -i br-lan -m mac --mac-source 02:00:00:00:0a:02 -j REJECT --reject-with icmp6-port-unreachable" in desired
          and "ip rule priority 3110 from 10.10.2.0/24 iif br-guest lookup 3100" in desired
          and not any(x.startswith("tc ") or "fwmark" in x for x in desired), "; ".join(x for x in desired if "iptables" in x)[:220])
    n0, n1 = adm("N0-caps-lab")["out"], adm("N1-caps-stock")["out"]
    c1 = n1.get("caps", {})
    check("возможности ядра стока (конфигурация и модули из образа 1.1.38): tc недоступен, netfilter доступен, auto выбирает netfilter",
          n1.get("chosen") == "netfilter" and c1.get("tc_ok") is False and c1.get("netfilter_ok") is True,
          "tc: " + "; ".join(f"{i['what']}={i['detail']}" for i in c1.get("tc", []) if not i["ok"])[:200])
    check("возможности лаборатории: MARK rev2 недоступен (xt_mark не загружается из userns) — фиксируется, а не предполагается",
          n0.get("caps", {}).get("netfilter_mark_ok") is False, "; ".join(f"{i['what']}" for i in n0.get("caps", {}).get("netfilter_mark", []) if not i["ok"]))
    n2, n3, n4, n5 = adm("N2-apply-stock-without-xt_mac"), adm("N3-apply-tc-on-stock"), adm("N4-plan-stock-auto"), adm("N5-partial-bridge-without-mark")
    check("отсутствующий набор (ядро стока без xt_mac): apply отказывает (2, capabilities), сеть не изменена",
          n2["exit"] == 2 and code("N2-apply-stock-without-xt_mac") == "capabilities" and n2.get("outside_unchanged") and snapf("zone.00b-nomac").strip() == "",
          str(n2["out"].get("missing"))[:200])
    check("tc на ядре стока: отказ (2), перечислены NET_CLS_ACT и др.", n3["exit"] == 2 and "NET_CLS_ACT" in json.dumps(n3["out"], ensure_ascii=False), str(n3["out"].get("missing"))[:160])
    check("план на ядре стока (auto): netfilter, без конфликтов", n4["exit"] == 0 and n4["out"].get("marker") == "netfilter", f"exit={n4['exit']} marker={n4['out'].get('marker')}")
    check("сеть на части моста (physdev+MARK) при недоступной ревизии 2 MARK: отказ (2, capabilities) без изменений",
          n5["exit"] == 2 and code("N5-partial-bridge-without-mark") == "capabilities" and n5.get("outside_unchanged") and snapf("zone.00c-kids").strip() == "",
          str(n5["out"].get("missing"))[:220])
    pf_syntax = json.loads(text("preflight.syntax.json") or "{}")
    pf1, pf2 = json.loads(text("preflight.stock-userland.exit.json") or "{}"), json.loads(text("preflight.lab-iptables.exit.json") or "{}")
    t1, t2 = text("preflight.stock-userland.txt"), text("preflight.lab-iptables.txt")
    mac_re = re.compile(r"\b[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}\b")
    ip_re = re.compile(r"\b10\.10\.\d+\.\d+\b|fd00:1[01]::[0-9a-f]+\b")
    check("preflight: ARM64 BusyBox 1.25.1 прошивки разбирает (sh -n) и выполняет скрипт; код 0; итоговые строки есть",
          pf_syntax.get("exit") == 0 and pf1.get("exit") == 0 and pf2.get("exit") == 0 and "verdict.marker_netfilter=" in t1 and "verdict.marker_tc=" in t2,
          f"строк: {len(t1.splitlines())}/{len(t2.splitlines())}; {[l for l in t2.splitlines() if l.startswith('verdict.')][:3]}")
    check("preflight ничего не меняет (правила, маршруты, tc, iptables до и после равны)", json.loads(text("preflight.mutation.json") or "{}").get("unchanged") is True, "")
    check("preflight не выводит MAC и адреса клиентов", not mac_re.search(t1 + t2) and not ip_re.search(t1 + t2), "")
    check("preflight видит наши цепочки и маски меток в firewall (iptables лаборатории)", "fw.iptables.mitt_chains=1" in t2, [l for l in t2.splitlines() if l.startswith("fw.")][:4].__str__()[:200])
    check("чужие правила iptables/ip6tables сохранены после revert", snapf("foreign-nf.16-final") == snapf("foreign-nf.00-initial") and "-i br-guest -o br-lan -j ACCEPT" in snapf("foreign-nf.00-initial"), "")
tt = [l for l in text("trusttunnel.log").splitlines() if "CONNECT" in l and ("10.99.0.10" in l or "10.98.0.10" in l)]
mh = text("mihomo.log").splitlines()
check("сервер TrustTunnel получил CONNECT к цели", bool(tt), f"{len(tt)} строк")
check("Mihomo направил в tt-lab ТВ и гостевую сеть", any(TV in l and "tt-lab" in l for l in mh) and any("10.10.2." in l and "tt-lab" in l for l in mh), "")
check("трафик телефона не проходил через Mihomo", not any(re.search(re.escape(PHONE) + r":\d+", l) for l in mh), "")

(OUT / "summary.json").write_text(json.dumps({"ok": ok_all, "probes": rows, "checks": checks}, ensure_ascii=False, indent=2), encoding="utf-8")
md = ["| Проба | Ожидание | Наблюдение | Итог |", "|---|---|---|---|"]
md += [f"| {r['probe']} — {r['title']} | {r['expect']} | {r['observed'].replace('|', '/')} | {'да' if r['ok'] else 'НЕТ'} |" for r in rows]
md += ["", "| Проверка | Наблюдение | Итог |", "|---|---|---|"]
md += [f"| {c['check']} | {c['observed'].replace('|', '/')[:220]} | {'да' if c['ok'] else 'НЕТ'} |" for c in checks]
(OUT / "summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")
print("\n".join(md))
print("ИТОГ:", "ПРОЙДЕНО" if ok_all else "ЕСТЬ ОТКЛОНЕНИЯ")
sys.exit(0 if ok_all else 1)
