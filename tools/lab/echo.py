"""TCP/UDP эхо-цель и клиент лаборатории.
  echo.py serve <адрес> <порт> <журнал> <имя>     — TCP и UDP на одном порту; отвечает JSON с адресом клиента
  echo.py probe <tcp|udp> <адрес> <порт> <проба>  — один запрос, печатает ответ или ошибку (код 0/1)
Журнал — JSON Lines: время, протокол, адрес клиента, проба."""
import json
import socket
import sys
import threading
import time


def serve(addr, port, logfile, name):
    log = open(logfile, "a", buffering=1, encoding="utf-8")
    fam = socket.AF_INET6 if ":" in addr else socket.AF_INET

    def record(proto, client, data):
        probe = data.decode("utf-8", "replace").strip()[:64]
        rec = {"t": round(time.time(), 3), "service": name, "proto": proto, "client": client, "probe": probe}
        log.write(json.dumps(rec) + "\n")
        return json.dumps({"seen_client": client, "proto": proto, "probe": probe, "service": name}).encode() + b"\n"

    def tcp():
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((addr, port))
        s.listen(16)
        while True:
            c, a = s.accept()

            def one(c=c, a=a):
                with c:
                    c.settimeout(5)
                    try:
                        data = c.recv(256)
                        c.sendall(record("tcp", a[0], data))
                    except OSError:
                        pass

            threading.Thread(target=one, daemon=True).start()

    def udp():
        s = socket.socket(fam, socket.SOCK_DGRAM)
        s.bind((addr, port))
        while True:
            data, a = s.recvfrom(2048)
            s.sendto(record("udp", a[0], data), a)

    threading.Thread(target=tcp, daemon=True).start()
    udp()


def probe(proto, addr, port, name):
    fam = socket.AF_INET6 if ":" in addr else socket.AF_INET
    try:
        if proto == "tcp":
            with socket.create_connection((addr, port), timeout=5) as s:
                s.sendall(name.encode() + b"\n")
                s.settimeout(5)
                data = s.recv(512)
        else:
            s = socket.socket(fam, socket.SOCK_DGRAM)
            s.settimeout(2)
            data = b""
            for _ in range(3):  # UDP: до трёх попыток
                s.sendto(name.encode() + b"\n", (addr, port))
                try:
                    data, _a = s.recvfrom(512)
                    break
                except socket.timeout:
                    continue
            s.close()
        if not data:
            raise OSError("нет ответа")
        print(data.decode().strip())
        return 0
    except OSError as e:
        print(json.dumps({"error": str(e) or type(e).__name__}))
        return 1


if __name__ == "__main__":
    if sys.argv[1] == "serve":
        serve(sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5])
    else:
        sys.exit(probe(sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5]))
