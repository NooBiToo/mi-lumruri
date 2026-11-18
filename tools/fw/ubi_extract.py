"""Разбор UBI-образа (без сторонних библиотек): собирает тома по VID-заголовкам и пишет их в каталог.
Использование: python3 -I ubi_extract.py <root.ubi> <out-dir>. Только чтение входного файла."""
import struct
import sys
from pathlib import Path

data = Path(sys.argv[1]).read_bytes()
out = Path(sys.argv[2])
out.mkdir(parents=True, exist_ok=True)

# размер физического блока: расстояние между двумя первыми EC-заголовками "UBI#"
first = data.find(b"UBI#")
second = data.find(b"UBI#", first + 1)
peb = second - first
vols = {}
names = {}
for off in range(first, len(data) - 64, peb):
    if data[off:off + 4] != b"UBI#":
        continue
    vid_off, data_off = struct.unpack_from(">II", data, off + 16)
    v = off + vid_off
    if data[v:v + 4] != b"UBI!":
        continue  # пустой блок
    vol_type = data[v + 5]
    vol_id, lnum = struct.unpack_from(">II", data, v + 8)
    data_size, used_ebs, data_pad = struct.unpack_from(">III", data, v + 20)
    leb = peb - data_off
    chunk = data[off + data_off: off + data_off + (data_size if vol_type == 2 else leb)]
    if vol_id == 0x7FFFEFFF:  # таблица томов
        for i in range(128):
            rec = chunk[i * 172:(i + 1) * 172]
            if len(rec) < 172:
                break
            nlen = struct.unpack_from(">H", rec, 14)[0]
            if nlen:
                names[i] = rec[16:16 + nlen].decode()
        continue
    vols.setdefault(vol_id, {})[lnum] = chunk

print(f"PEB={peb}")
for vid, lebs in sorted(vols.items()):
    body = b"".join(lebs[i] for i in sorted(lebs))
    name = names.get(vid, f"vol{vid}")
    (out / f"{vid}_{name}.bin").write_bytes(body)
    print(vid, name, len(lebs), "LEB", len(body), "байт", body[:4])
