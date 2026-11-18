"""Сниффер лаборатории (AF_PACKET, только чтение): пишет каждый IPv4/IPv6-пакет на интерфейсе в JSON Lines.
Запускается в network namespace «интернета» на линке к роутеру — так видно любой пакет, вышедший с роутера наружу,
в том числе прямой пакет защищённого устройства в обход туннеля.
  sniff.py <интерфейс> <журнал>"""
import json
import socket
import struct
import sys
import time

IFACE, LOGFILE = sys.argv[1], sys.argv[2]
log = open(LOGFILE, "a", buffering=1, encoding="utf-8")
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
s.bind((IFACE, 0))
PROTO = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmp6"}
while True:
    frame, meta = s.recvfrom(65535)
    if meta[2] == socket.PACKET_OUTGOING:
        direction = "out"
    else:
        direction = "in"
    etype = struct.unpack("!H", frame[12:14])[0]
    p = frame[14:]
    rec = None
    if etype == 0x0800 and len(p) >= 20:
        ihl = (p[0] & 15) * 4
        proto = p[9]
        src, dst = socket.inet_ntop(socket.AF_INET, p[12:16]), socket.inet_ntop(socket.AF_INET, p[16:20])
        l4 = p[ihl:]
        rec = {"v": 4, "src": src, "dst": dst, "proto": PROTO.get(proto, proto)}
    elif etype == 0x86DD and len(p) >= 40:
        proto = p[6]
        src, dst = socket.inet_ntop(socket.AF_INET6, p[8:24]), socket.inet_ntop(socket.AF_INET6, p[24:40])
        l4 = p[40:]
        rec = {"v": 6, "src": src, "dst": dst, "proto": PROTO.get(proto, proto)}
    if rec is None:
        continue
    if rec["proto"] in ("tcp", "udp") and len(l4) >= 4:
        rec["sport"], rec["dport"] = struct.unpack("!HH", l4[:4])
    if rec["proto"] == "tcp" and len(l4) >= 20:
        doff = (l4[12] >> 4) * 4
        rec["flags"] = l4[13]
        rec["seq"] = struct.unpack("!I", l4[4:8])[0]
        total = struct.unpack("!H", p[2:4])[0] if rec["v"] == 4 else 40 + struct.unpack("!H", p[4:6])[0]
        hdr = ihl if rec["v"] == 4 else 40
        rec["plen"] = max(0, total - hdr - doff)
    if rec["proto"] == "udp" and len(l4) >= 12:
        rec["len"] = len(l4) - 8
        rec["head"] = l4[8:12].hex()  # первые 4 байта полезной нагрузки (тип сообщения WireGuard/AmneziaWG)
    rec["t"] = round(time.time(), 3)
    rec["dir"] = direction
    log.write(json.dumps(rec) + "\n")
