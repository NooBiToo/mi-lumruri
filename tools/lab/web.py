"""Веб-сервер лаборатории: файлы каталога по HTTP или HTTPS (эфемерный сертификат прогона).
  web.py <адрес> <порт> <каталог> <журнал> [<сертификат> <ключ>]
Журнал — JSON Lines: время, адрес клиента, путь, код ответа."""
import functools
import http.server
import json
import ssl
import sys
import time

addr, port, root, logfile = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
log = open(logfile, "a", buffering=1, encoding="utf-8")


class H(http.server.SimpleHTTPRequestHandler):
    def log_request(self, code="-", size="-"):
        log.write(json.dumps({"t": round(time.time(), 3), "client": self.client_address[0], "path": self.path, "code": int(code) if str(code).isdigit() else str(code)}) + "\n")

    def log_message(self, *a):
        pass


srv = http.server.ThreadingHTTPServer((addr, port), functools.partial(H, directory=root))
if len(sys.argv) > 6:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(sys.argv[5], sys.argv[6])
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
