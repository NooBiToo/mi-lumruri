#!/bin/sh
# Run interactively in a root SSH session on Xiaomi BE7000.
set -eu
umask 077
[ "$(id -u)" = 0 ] || { echo 'Root SSH required' >&2; exit 1; }
version_file=/usr/share/xiaoqiang/xiaoqiang_version
grep -q "option HARDWARE 'RC06'" "$version_file" &&
  grep -q "option ROM '1.1.38'" "$version_file" ||
  { echo 'Expected Xiaomi BE7000 RC06 firmware 1.1.38' >&2; exit 1; }
stage=$(mktemp -d /tmp/mitt-install.XXXXXX)
trap 'rm -rf "$stage"' EXIT
cd "$stage"
url=https://github.com/NooBiToo/mi-lumruri/releases/download/v0.13.0/mi-lumruri-ci-f19d4de10972.tar
if command -v curl >/dev/null; then
  curl -fL --retry 2 -o package.tar "$url"
else
  wget -O package.tar "$url"
fi
digest=$(openssl dgst -sha256 package.tar)
[ "${digest##* }" = 124bee11151d8e05596d223078168695fdcb82a46f810f601083c12fbb1151a0 ] ||
  { echo 'Package SHA-256 mismatch' >&2; exit 1; }
tar xf package.tar
rm package.tar
if [ -d mi-lumruri ]; then cd mi-lumruri; else cd mi-trusttunnel; fi
sh install.sh
base=/data/mi-lumruri
if [ ! -f "$base/etc/auth/auth.json" ]; then
  sh "$base/mitt-boot.sh" auth init
fi
if ! sh "$base/mitt-boot.sh" auth status >/dev/null; then
  # TOTP включён, но не подтверждён (auth reset-totp)
  sh "$base/mitt-boot.sh" auth confirm
fi
openssl x509 -in "$base/etc/tls/cert.pem" -noout -fingerprint -sha256
echo 'Open https://<router-LAN-IP>:8443/'
