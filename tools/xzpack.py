"""Детерминированное XZ (preset 6, словарь 8 МиБ, CRC32 — как в ARCHITECTURE.md) и детерминированный tar для пакета.
  xzpack.py xz <вход> <выход>            — сжать; печатает SHA-256 и размер входа
  xzpack.py tar <каталог> <выход.tar>    — tar без владельцев и времени (mtime 0), пути отсортированы"""
import hashlib
import lzma
import os
import sys
import tarfile

if sys.argv[1] == "xz":
    data = open(sys.argv[2], "rb").read()
    filters = [{"id": lzma.FILTER_LZMA2, "preset": 6, "dict_size": 8 * 1024 * 1024}]
    out = lzma.compress(data, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC32, filters=filters)
    assert lzma.decompress(out) == data
    open(sys.argv[3], "wb").write(out)
    print(hashlib.sha256(data).hexdigest(), len(data))
elif sys.argv[1] == "tar":
    root = sys.argv[2]
    base = os.path.basename(os.path.normpath(root))
    paths = []
    for d, dirs, files in os.walk(root):
        dirs.sort()
        rel = os.path.relpath(d, os.path.dirname(os.path.normpath(root)))
        paths.append((rel, d, True))
        for f in sorted(files):
            paths.append((os.path.join(rel, f), os.path.join(d, f), False))
    with tarfile.open(sys.argv[3], "w", format=tarfile.USTAR_FORMAT) as t:
        for rel, full, isdir in sorted(paths):
            ti = tarfile.TarInfo(rel.replace(os.sep, "/"))
            ti.mtime, ti.uid, ti.gid, ti.uname, ti.gname = 0, 0, 0, "", ""
            if isdir:
                ti.type, ti.mode = tarfile.DIRTYPE, 0o755
                t.addfile(ti)
            else:
                ti.size = os.path.getsize(full)
                ti.mode = 0o755 if rel.endswith(".sh") else 0o644
                with open(full, "rb") as fh:
                    t.addfile(ti, fh)
    print(base)
