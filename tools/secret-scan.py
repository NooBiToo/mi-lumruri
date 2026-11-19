"""Сканер опубликованных секретов и постоянных тестовых значений. Значения НЕ печатает: только место, вид и длину.

  python -I tools/secret-scan.py tree            # рабочее дерево (файлы git: отслеживаемые и неигнорируемые новые) — код выхода 1 при находках
  python -I tools/secret-scan.py commit <rev>…   # дерево коммитов (история не меняется — только отчёт)
  python -I tools/secret-scan.py archive <tar>…  # tar-архивы, включая члены .xz/.gz

Ищет: PEM-блоки закрытых ключей; присваивания литералов полям вида password/passwd/secret/token/psk/private_key/
preshared_key/uuid (YAML, JSON, TOML, shell, Python, JS/TS, Rust) с непустым постоянным значением.
Не считает находкой: подстановки ($VAR, ${…}, {{…}}), значения из генераторов (secrets.*, randomBytes, rand_hex, token_urlsafe,
crypto.*), пустые строки, плейсхолдеры (`<…>`, `x`, `***`, `REDACTED`), имена полей без значения, ссылки на переменные.
Строка с пометкой `secret-scan: allow <причина>` пропускается (только для намеренных отрицательных примеров).
"""
import io
import json
import lzma
import gzip
import re
import subprocess
import sys
import tarfile

PEM = re.compile(rb"-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----")
KEYS = r"(?:password|passwd|pass|pw|secret|token|psk|private[_-]?key|preshared[_-]?key|obfs[_-]?password|uuid|api[_-]?key)"
# key = "value" | key: "value" | "key": "value" | key='value' | KEY=value (shell)
ASSIGN = re.compile(
    r"""(?ix)
    (?P<key>["']?[\w.-]*""" + KEYS + r"""[\w-]*["']?)\s*(?:=|:)\s*
    (?P<q>["'])(?P<val>[^"'\n]{1,200})(?P=q)
    """
)
SHELL = re.compile(r"""(?i)(?:^|[\s;])(?P<key>[A-Z_]*""" + KEYS + r"""[A-Z_]*)=(?P<val>[^\s"'$`;|&()]{4,200})""")
GENERATED = re.compile(r"(?i)\$|\{\{|secrets\.|randomBytes|rand_hex|token_urlsafe|crypto\.|random|uuid4|Math\.|getrandom|format!|\{[a-z_]*\}|%s")
PLACEHOLDER = re.compile(r"(?i)^(<[^>]*>|x+|\*+|redacted|changeme-not-used|none|null|true|false|-+|\.\.\.|…|[a-z_]+\(\)|[\w.]+\.[a-z_]+)$")
# ключ X25519 (и любой другой 32-байтный ключ) в base64 (32 байта) или URL-safe без дополнения — постоянный ключевой материал в исходниках
KEYLIT = re.compile(r"""["'`]([A-Za-z0-9+/]{43}=|[A-Za-z0-9_-]{43})["'`]""")
ENVNAME = re.compile(r"^[A-Z][A-Z0-9_]*$")
ALLOW = "secret-scan: allow"
SKIP_EXT = (".png", ".jpg", ".ico", ".woff", ".woff2", ".lock", ".bin", ".xz", ".gz", ".tar", ".ko", ".so", ".wasm")


def scan_text(name, data, out):
    for m in PEM.finditer(data):
        line = data.count(b"\n", 0, m.start()) + 1
        out.append({"where": f"{name}:{line}", "kind": "private_key_pem", "detail": m.group(1).decode()})
    if name.endswith(SKIP_EXT) or b"\0" in data[:4096]:
        return
    text = data.decode("utf-8", "replace")
    for n, line in enumerate(text.splitlines(), 1):
        if ALLOW in line:
            continue
        for m in KEYLIT.finditer(line):
            v = m.group(1)
            if len(set(v)) < 8:  # 'a'*43 и т. п. — заведомо не ключ
                continue
            out.append({"where": f"{name}:{n}", "kind": "key_literal", "detail": f"строка вида ключа X25519 (base64, длина {len(v)})"})
        for rx in (ASSIGN, SHELL):
            for m in rx.finditer(line):
                v = m.group("val").strip()
                if not v or GENERATED.search(v) or PLACEHOLDER.match(v) or ENVNAME.match(v) or len(v) < 4:
                    continue
                if re.match(r"\s*\+", line[m.end():]):  # 'префикс' + сгенерированное значение
                    continue
                key = m.group("key").strip("\"'")
                # тип/вид поля, а не значение: "password": "string" в схемах, перечисления видов
                if v.lower() in {"string", "password", "text", "secret", "token", "uuid", "obfs_password", "private_key", "preshared_key", "hidden", "new-password", "current-password", "off", "on"}:
                    continue
                out.append({"where": f"{name}:{n}", "kind": "literal_secret_value", "detail": f"поле {key}, длина значения {len(v)}"})


def git(*a):
    return subprocess.run(["git", *a], capture_output=True, check=True).stdout


def scan_tree():
    files = [f for f in git("ls-files", "-z", "--cached", "--others", "--exclude-standard").decode().split("\0") if f]
    out = []
    for f in files:
        try:
            data = open(f, "rb").read()
        except OSError:
            continue  # удалён в рабочем дереве
        scan_text(f, data, out)
    return out


def scan_commit(rev):
    out = []
    for f in [x for x in git("ls-tree", "-r", "-z", "--name-only", rev).decode().split("\0") if x]:
        scan_text(f"{rev}:{f}", git("show", f"{rev}:{f}"), out)
    return out


def scan_archive(path):
    out = []
    with tarfile.open(path) as t:
        for m in t.getmembers():
            if not m.isfile():
                continue
            data = t.extractfile(m).read()
            name = f"{path}!{m.name}"
            if m.name.endswith(".xz"):
                data = lzma.decompress(data); name += "(xz)"
            elif m.name.endswith(".gz"):
                data = gzip.decompress(data); name += "(gz)"
            elif m.name.endswith(".tar"):
                with tarfile.open(fileobj=io.BytesIO(data)) as inner:
                    for im in inner.getmembers():
                        if im.isfile():
                            scan_text(f"{name}!{im.name}", inner.extractfile(im).read(), out)
                continue
            scan_text(name, data, out)
    return out


def main():
    mode, args = sys.argv[1], sys.argv[2:]
    found = scan_tree() if mode == "tree" else [x for a in args for x in (scan_commit(a) if mode == "commit" else scan_archive(a))]
    for f in found:
        print(f"{f['where']}\t{f['kind']}\t{f['detail']}")
    print(json.dumps({"mode": mode, "findings": len(found)}, ensure_ascii=False))
    sys.exit(1 if found and mode == "tree" else 0)


if __name__ == "__main__":
    main()
