"""HTTP-сервис стенда: отвечает, с какого адреса пришёл запрос, и пишет то же в журнал (JSON Lines).
Аргументы: порт, журнал, [адрес привязки, по умолчанию 0.0.0.0; IPv6-адрес → отдельный сокет IPV6_V6ONLY], [имя]."""
import json
import socket
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT, LOGFILE = int(sys.argv[1]), sys.argv[2]
BIND = sys.argv[3] if len(sys.argv) > 3 else "0.0.0.0"
NAME = sys.argv[4] if len(sys.argv) > 4 else "target"
LOG = open(LOGFILE, "a", buffering=1, encoding="utf-8")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        rec = {
            "t": round(time.time(), 3),
            "service": NAME,
            "client": self.client_address[0],
            "local": self.connection.getsockname()[0],
            "host": self.headers.get("Host"),
            "probe": self.headers.get("X-Probe"),
        }
        LOG.write(json.dumps(rec) + "\n")
        body = json.dumps({"seen_client": rec["client"], "local": rec["local"], "probe": rec["probe"], "service": NAME}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class Server6(ThreadingHTTPServer):
    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()


(Server6 if ":" in BIND else ThreadingHTTPServer)((BIND, PORT), Handler).serve_forever()
