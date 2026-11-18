"""Авторитетный DNS лаборатории (UDP и TCP): отвечает на A/AAAA для зоны lab.test из таблицы, иначе NXDOMAIN.
Пишет каждый вопрос в журнал (JSON Lines): кто спросил, что, по какому транспорту.
  dnsauth.py <адрес> <порт> <журнал> <имя>"""
import json
import socket
import struct
import sys
import threading
import time

ADDR, PORT, LOGFILE, NAME = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
LOG = open(LOGFILE, "a", buffering=1, encoding="utf-8")
ZONE = {
    "ok.lab.test": ("10.99.0.10", "fd00:99::10"),
    "ok2.lab.test": ("10.99.0.11", "fd00:99::11"),
    "ok3.lab.test": ("10.99.0.12", "fd00:99::12"),
    "ok4.lab.test": ("10.99.0.13", "fd00:99::13"),
    "ads.lab.test": ("10.99.0.66", "fd00:99::66"),
    "good.ads.lab.test": ("10.99.0.77", "fd00:99::77"),
    "blocked2.lab.test": ("10.99.0.88", "fd00:99::88"),
}


def qname(msg, off):
    labels = []
    while msg[off]:
        n = msg[off]
        labels.append(msg[off + 1:off + 1 + n].decode("ascii", "replace"))
        off += 1 + n
    return ".".join(labels).lower(), off + 1


def answer(q, client, proto):
    tid, flags = struct.unpack("!HH", q[:4])
    name, off = qname(q, 12)
    qtype, qclass = struct.unpack("!HH", q[off:off + 4])
    question = q[12:off + 4]
    LOG.write(json.dumps({"t": round(time.time(), 3), "server": NAME, "client": client, "proto": proto, "name": name, "type": qtype}) + "\n")
    rec = ZONE.get(name)
    ans = b""
    rcode = 0
    if rec is None:
        rcode = 3
    elif qtype == 1:
        ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_pton(socket.AF_INET, rec[0])
    elif qtype == 28:
        ans = b"\xc0\x0c" + struct.pack("!HHIH", 28, 1, 60, 16) + socket.inet_pton(socket.AF_INET6, rec[1])
    rflags = 0x8400 | (flags & 0x0100) | rcode  # QR, AA, RD копируется
    return struct.pack("!HHHHHH", tid, rflags, 1, 1 if ans else 0, 0, 0) + question + ans


def udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((ADDR, PORT))
    while True:
        q, a = s.recvfrom(4096)
        try:
            s.sendto(answer(q, a[0], "udp"), a)
        except (IndexError, struct.error):
            pass


def tcp():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ADDR, PORT))
    s.listen(32)
    while True:
        c, a = s.accept()

        def one(c=c, a=a):
            with c:
                c.settimeout(5)
                try:
                    while True:
                        h = c.recv(2)
                        if len(h) < 2:
                            return
                        n = struct.unpack("!H", h)[0]
                        q = b""
                        while len(q) < n:
                            part = c.recv(n - len(q))
                            if not part:
                                return
                            q += part
                        r = answer(q, a[0], "tcp")
                        c.sendall(struct.pack("!H", len(r)) + r)
                except (OSError, IndexError, struct.error):
                    return

        threading.Thread(target=one, daemon=True).start()


threading.Thread(target=tcp, daemon=True).start()
udp()
