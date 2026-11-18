"""Извлекает образ ядра из FIT (flattened device tree) и встроенный .config (IKCONFIG). Только чтение.
Использование: python3 -I fit_kernel.py <kernel-fit.bin> <out-dir>"""
import gzip
import lzma
import struct
import sys
import zlib
from pathlib import Path

fit = Path(sys.argv[1]).read_bytes()
out = Path(sys.argv[2])
out.mkdir(parents=True, exist_ok=True)
magic, totalsize, off_struct, off_strings = struct.unpack_from(">IIII", fit, 0)
assert magic == 0xD00DFEED, "не FIT"


def walk():
    """Обход структуры FDT: (путь узла, имя свойства, значение)."""
    p, path = off_struct, []
    while True:
        tok = struct.unpack_from(">I", fit, p)[0]
        p += 4
        if tok == 1:  # BEGIN_NODE
            end = fit.index(b"\0", p)
            path.append(fit[p:end].decode())
            p = (end + 4) & ~3
        elif tok == 2:  # END_NODE
            path.pop()
        elif tok == 3:  # PROP
            ln, nameoff = struct.unpack_from(">II", fit, p)
            p += 8
            name = fit[off_strings + nameoff: fit.index(b"\0", off_strings + nameoff)].decode()
            yield "/".join(path), name, fit[p:p + ln]
            p = (p + ln + 3) & ~3
        elif tok == 9:
            return


props = {}
for node, name, val in walk():
    props.setdefault(node, {})[name] = val
kernel = next((v for n, v in props.items() if "/images/kernel" in n and "data" in v), None)
assert kernel, f"нет узла kernel: {list(props)}"
comp = kernel.get("compression", b"none").rstrip(b"\0").decode()
raw = kernel["data"]
img = {"gzip": lambda b: gzip.decompress(b), "lzma": lambda b: lzma.decompress(b, format=lzma.FORMAT_ALONE), "none": lambda b: b}[comp](raw)
(out / "Image").write_bytes(img)
print("сжатие", comp, "образ", len(img), "байт")
i = img.find(b"IKCFG_ST")
if i < 0:
    print("IKCONFIG не найден")
    sys.exit(0)
cfg = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(img[i + 8:])
(out / "config").write_bytes(cfg)
print("config", len(cfg), "байт")
