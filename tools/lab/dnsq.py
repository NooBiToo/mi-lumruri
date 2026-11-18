"""DNS-клиент лаборатории (UDP): один вопрос, печатает JSON {rcode, answers} или {error}.
  dnsq.py <сервер> <имя> <A|AAAA> [таймаут]"""
import json
import os
import socket
import struct
import sys

server, name, qt = sys.argv[1], sys.argv[2], sys.argv[3]
timeout = float(sys.argv[4]) if len(sys.argv) > 4 else 4.0
QT = {"A": 1, "AAAA": 28}[qt]
RC = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
tid = int.from_bytes(os.urandom(2), "big")
q = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0) + b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0" + struct.pack("!HH", QT, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(timeout)
try:
    s.sendto(q, (server, 53))
    r, _ = s.recvfrom(4096)
except OSError as e:
    print(json.dumps({"error": str(e) or "timeout"}))
    sys.exit(1)
_, flags, qd, an, _, _ = struct.unpack("!HHHHHH", r[:12])
off = 12
for _ in range(qd):
    while r[off]:
        off += 1 + r[off]
    off += 5
answers = []
for _ in range(an):
    if r[off] & 0xC0 == 0xC0:
        off += 2
    else:
        while r[off]:
            off += 1 + r[off]
        off += 1
    typ, _, _, ln = struct.unpack("!HHIH", r[off:off + 10])
    data = r[off + 10:off + 10 + ln]
    off += 10 + ln
    if typ == 1:
        answers.append(socket.inet_ntop(socket.AF_INET, data))
    elif typ == 28:
        answers.append(socket.inet_ntop(socket.AF_INET6, data))
print(json.dumps({"rcode": RC.get(flags & 15, str(flags & 15)), "answers": answers}))
