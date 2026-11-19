"""Install the BE7000 package from a workstation using OpenSSH (Python 3.8+)."""

import argparse
import hashlib
import ipaddress
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path


REPO = "NooBiToo/mi-lumruri"
ARTIFACT = "mi-trusttunnel-be7000"
# Dropbear штатной прошивки предлагает только ключ хоста ssh-rsa, который OpenSSH 8.8+ по умолчанию отключил.
SSH_OPTS = ["-o", "HostKeyAlgorithms=+ssh-rsa", "-o", "PubkeyAcceptedAlgorithms=+ssh-rsa"]
INSTALL = """set -eu
umask 077
stage=$(mktemp -d /tmp/mitt-install.XXXXXX)
trap 'rm -rf "$stage"' EXIT
cd "$stage"
cat > package.tar
actual=$(openssl dgst -sha256 package.tar)
[ "${actual##* }" = EXPECTED_SHA ] || { echo 'SHA-256 mismatch' >&2; exit 1; }
tar xf package.tar
rm package.tar
cd mi-trusttunnel
sh install.sh
"""
LOGIN = """set -eu
base=/data/mi-trusttunnel
tries=0
while [ ! -f "$base/etc/auth/auth.json" ]; do
  [ "$tries" -lt 3 ] || { echo 'Вход в панель не настроен.' >&2; exit 1; }
  tries=$((tries + 1))
  echo 'Придумайте пароль панели: не короче 12 символов (это не пароль root).'
  sh "$base/mitt-boot.sh" auth init || true
done
if ! sh "$base/mitt-boot.sh" auth status >/dev/null; then
  # TOTP включён, но не подтверждён (auth reset-totp)
  sh "$base/mitt-boot.sh" auth confirm
fi
openssl x509 -in "$base/etc/tls/cert.pem" -noout -fingerprint -sha256
"""


def download(directory):
    result = subprocess.check_output([
        "gh", "run", "list", "-R", REPO, "--workflow", "build.yml",
        "--branch", "main", "--status", "success", "--limit", "1",
        "--json", "databaseId,headSha",
    ])
    runs = json.loads(result)
    if not runs:
        raise ValueError("Успешная сборка для main не найдена.")
    run = runs[0]
    short_sha = run["headSha"][:12]
    print(f"Скачиваю сборку {short_sha} из {REPO}…", flush=True)
    subprocess.run([
        "gh", "run", "download", str(run["databaseId"]), "-R", REPO,
        "-n", ARTIFACT, "-D", str(directory),
    ], check=True)
    return directory / f"mi-trusttunnel-ci-{short_sha}.tar"


def verify(package):
    checksum = (package.parent / "SHA256SUMS").read_text(encoding="ascii").strip()
    match = re.fullmatch(r"([0-9a-f]{64}) [ *](.+)", checksum)
    if not match or match[2] != package.name:
        raise ValueError("SHA256SUMS не соответствует имени выбранного TAR.")
    digest = hashlib.sha256()
    with package.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest() != match[1]:
        raise ValueError("SHA-256 пакета не совпал. Скачайте сборку заново.")
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description="Установить или обновить Mi Lumruri (mi-trusttunnel) по SSH.")
    parser.add_argument("router", nargs="?", type=ipaddress.IPv4Address, default="192.168.31.1",
                        help="LAN-адрес роутера (по умолчанию 192.168.31.1)")
    parser.add_argument("--package", type=Path, help="TAR из распакованного артефакта с SHA256SUMS")
    parser.add_argument("--store", help="каталог на USB-накопителе роутера для релизов, например "
                        "/mnt/usb-XXXX/mi-trusttunnel (если пакет не помещается в /data)")
    args = parser.parse_args()
    if args.store and not re.fullmatch(r"/[A-Za-z0-9._/-]+", args.store):
        raise ValueError("--store: нужен абсолютный путь из латинских букв, цифр и знаков . _ - /")
    target = f"root@{args.router}"
    with tempfile.TemporaryDirectory() as tmp:
        package = args.package
        if package is None:
            adjacent = list(Path(__file__).resolve().parent.glob("mi-trusttunnel-ci-*.tar"))
            if len(adjacent) > 1:
                raise ValueError("Найдено несколько пакетов. Выберите один через --package.")
            package = adjacent[0] if adjacent else download(Path(tmp))
        digest = verify(package)
        print(f"SHA-256 проверен. Устанавливаю пакет на {target}…", flush=True)
        with package.open("rb") as stream:
            script = INSTALL.replace("EXPECTED_SHA", digest)
            if args.store:
                script = script.rstrip("\n") + f" install --store={args.store}\n"
            subprocess.run(["ssh", "-T", *SSH_OPTS, target, script], stdin=stream, check=True)
    print("Пакет установлен. Проверяю вход в панель…", flush=True)
    subprocess.run(["ssh", "-t", *SSH_OPTS, target, LOGIN], check=True)
    print(f"Панель: https://{args.router}:8443/ — сверьте отпечаток сертификата при первом входе.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"Установка прервана: {error}", file=sys.stderr)
        sys.exit(1)
