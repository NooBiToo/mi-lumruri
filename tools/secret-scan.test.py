"""Тест сканера секретов: находит закрытые ключи, литералы паролей и ключей X25519, не срабатывает на генерации,
подстановках и именах переменных, а значения в вывод не попадают. Секреты создаются во время теста.

  python -I tools/secret-scan.test.py
"""
import base64
import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

SCAN = Path(__file__).with_name("secret-scan.py").resolve()


def run(cwd, *args):
    r = subprocess.run([sys.executable, "-I", "-X", "utf8", str(SCAN), *args], cwd=cwd, capture_output=True, text=True, encoding="utf-8")
    return r.returncode, r.stdout + r.stderr


def main():
    pw = secrets.token_urlsafe(12)
    wg = base64.b64encode(secrets.token_bytes(32)).decode()
    pem_body = base64.b64encode(secrets.token_bytes(48)).decode()
    pem = "-----BEGIN " + "PRIVATE KEY-----\n" + pem_body + "\n-----END " + "PRIVATE KEY-----\n"
    values = [pw, wg, pem_body]
    with tempfile.TemporaryDirectory() as d:
        subprocess.run(["git", "init", "-q", d], check=True)
        D = Path(d)
        # находки
        (D / "key.pem").write_text(pem)
        (D / "secrets.json").write_text('{"profiles": {"x": {"password": "%s"}}}\n' % pw)
        (D / "t.rs").write_text('const K: &str = "%s";\n' % wg)
        (D / "run.sh").write_text("ADMIN_PASSWORD=%s ./x\n" % pw)
        # не находки: генерация, подстановки, имена переменных, плейсхолдеры, пометка allow, конкатенация
        (D / "ok.sh").write_text('PASSWORD="$(openssl rand -hex 16)"\nprintf \'password: "%s"\\n\' "$HYPASS"\nMITT_PW="$PW" x\n')
        (D / "ok.py").write_text('sec={"panel_password":"MITT_PW"}\npw = secrets.token_urlsafe(18)\npassword = "<пароль>"\n')
        (D / "ok.ts").write_text("c.req({ password: 'wrong-' + cred.password })\nconst x = { password: '' }\n")
        (D / "ok.rs").write_text('json!({ "uuid": "not-a-uuid" }) // secret-scan: allow отрицательный пример\nlet pw = format!("x-{}", rand_hex(24));\n')
        code, out = run(d, "tree")
        print(out.strip())
        kinds = sorted(l.split("\t")[1] for l in out.splitlines() if "\t" in l)
        where = sorted(l.split("\t")[0].split(":")[0] for l in out.splitlines() if "\t" in l)
        checks = {
            "код выхода 1 при находках": code == 1,
            "закрытый ключ PEM найден": "private_key_pem" in kinds,
            "литерал ключа X25519 найден": "key_literal" in kinds,
            "литералы паролей (JSON и shell) найдены": kinds.count("literal_secret_value") == 2,
            "ложных срабатываний нет": set(where) == {"key.pem", "secrets.json", "t.rs", "run.sh"},
            "значения в выводе отсутствуют": not any(v in out for v in values),
        }
        # чистое дерево — код 0
        for f in ("key.pem", "secrets.json", "t.rs", "run.sh"):
            os.remove(D / f)
        code2, out2 = run(d, "tree")
        checks["чистое дерево: код 0, находок 0"] = code2 == 0 and '"findings": 0' in out2
    for k, v in checks.items():
        print(("да  " if v else "НЕТ ") + k)
    ok = all(checks.values())
    print("ИТОГ:", "ПРОЙДЕНО" if ok else "НЕ ПРОЙДЕНО")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
