"""Динамическая привязка отпечатка: всем профилям с закреплённым сертификатом (`endpoint.cert_sha256`) лабораторного
сервера (sni vpn.lab.test) ставится отпечаток эфемерного сертификата этого прогона (tools/lab/ephemeral-tls.sh).

  python3 -I tools/lab/pin-config.py <config.json> <отпечаток SHA-256 AA:BB:…> [<вывод.json>]
"""
import json
import os
import re
import sys

src, fp = sys.argv[1], sys.argv[2].strip()
dst = sys.argv[3] if len(sys.argv) > 3 else src
if not re.fullmatch(r"(?:[0-9A-F]{2}:){31}[0-9A-F]{2}", fp):
    sys.exit("pin-config: отпечаток должен быть SHA-256 вида AA:BB:… (32 байта)")
d = json.load(open(src, encoding="utf-8"))
n = 0
for p in d.get("profiles", []):
    e = p.get("endpoint") or {}
    if "cert_sha256" in e and e.get("sni") == "vpn.lab.test":
        e["cert_sha256"] = fp
        n += 1
if not n:
    sys.exit("pin-config: нет профилей с cert_sha256 для vpn.lab.test")
tmp = dst + ".pin.tmp"
with open(tmp, "w", encoding="utf-8") as f:
    json.dump(d, f, ensure_ascii=False, indent=2)
os.replace(tmp, dst)
print(n)
