"""Ключи WireGuard/AmneziaWG для лаборатории (X25519, RFC 7748, без внешних модулей).

python3 -I wgkey.py            → «закрытый открытый» (base64)
python3 -I wgkey.py uapi SOCK  → команды UAPI со стандартного ввода в сокет, печатает ответ (errno=…)
"""
import base64
import os
import socket
import sys

P = 2**255 - 19
A24 = 121665


def x25519(k: bytes, u: bytes) -> bytes:
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    kn = int.from_bytes(k, "little")
    un = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x1, x2, z2, x3, z3, swap = un, 1, 0, un, 1, 0
    for t in reversed(range(255)):
        kt = (kn >> t) & 1
        swap ^= kt
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = kt
        a, b = (x2 + z2) % P, (x2 - z2) % P
        aa, bb = a * a % P, b * b % P
        e = (aa - bb) % P
        c, d = (x3 + z3) % P, (x3 - z3) % P
        da, cb = d * a % P, c * b % P
        x3 = (da + cb) ** 2 % P
        z3 = x1 * (da - cb) ** 2 % P
        x2 = aa * bb % P
        z2 = e * (aa + A24 * e) % P
    if swap:
        x2, x3, z2, z3 = x3, x2, z3, z2
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")


def main():
    if len(sys.argv) > 2 and sys.argv[1] == "uapi":
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(sys.argv[2])
        s.sendall(b"set=1\n" + sys.stdin.read().encode() + b"\n")
        print(s.recv(4096).decode().strip())
        return
    priv = os.urandom(32)
    pub = x25519(priv, (9).to_bytes(32, "little"))
    print(base64.b64encode(priv).decode(), base64.b64encode(pub).decode())


if __name__ == "__main__":
    main()
