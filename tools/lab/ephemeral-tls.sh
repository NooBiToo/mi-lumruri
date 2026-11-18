#!/usr/bin/env bash
# Эфемерный ключ и сертификат TLS для одного прогона лаборатории (вместо постоянного ключа в репозитории).
#   tools/lab/ephemeral-tls.sh <каталог>  →  <каталог>/key.pem (0600), <каталог>/cert.pem, <каталог>/fp (SHA-256, AA:BB:…)
#   На stdout — только отпечаток сертификата (открытые данные). Ключ создаётся в каталоге прогона (tmpfs/mktemp)
#   и удаляется вместе с ним; в артефакты и журналы не копируется.
set -euo pipefail
D="${1:?каталог}"
mkdir -p "$D"; chmod 700 "$D"
( umask 077
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj "/CN=vpn.lab.test" \
    -addext "subjectAltName=DNS:vpn.lab.test" -keyout "$D/key.pem" -out "$D/cert.pem" >/dev/null 2>&1 )
chmod 600 "$D/key.pem"
FP="$(openssl x509 -in "$D/cert.pem" -noout -fingerprint -sha256 | cut -d= -f2)"
[ "${#FP}" -eq 95 ] || { echo "ephemeral-tls: не удалось получить отпечаток" >&2; exit 1; }
printf '%s\n' "$FP" >"$D/fp"
printf '%s\n' "$FP"
