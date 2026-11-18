#!/usr/bin/env bash
# Проверка воспроизводимости: две независимые чистые сборки контроллера (ARM64 musl) и панели,
# затем две сборки комплекта; хэши должны совпасть.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
R="$ROOT/out/repro"
rm -rf "$R"; mkdir -p "$R"
for k in a b; do
  CARGO_TARGET_DIR="$R/target-$k" "$ROOT/tools/cargo.sh" build --release --locked --target aarch64-unknown-linux-musl -q
  (cd "$ROOT/panel" && npx vite build --outDir "$R/panel-$k" --emptyOutDir --logLevel error)
done
A="$R/target-a/aarch64-unknown-linux-musl/release/mi-tt-ctl"; B="$R/target-b/aarch64-unknown-linux-musl/release/mi-tt-ctl"
sha256sum "$A" "$B"
cmp "$A" "$B" && echo "контроллер: побайтно совпадает"
sha256sum "${A%/*}/mi-tt-admin" "${B%/*}/mi-tt-admin"
cmp "${A%/*}/mi-tt-admin" "${B%/*}/mi-tt-admin" && echo "mi-tt-admin: побайтно совпадает"
(cd "$R/panel-a" && find . -type f | sort | xargs sha256sum) >"$R/panel-a.sha"
(cd "$R/panel-b" && find . -type f | sort | xargs sha256sum) >"$R/panel-b.sha"
diff "$R/panel-a.sha" "$R/panel-b.sha" && echo "панель: побайтно совпадает ($(wc -l <"$R/panel-a.sha") файла)"
cmp "$A" "$ROOT/controller/target/aarch64-unknown-linux-musl/release/mi-tt-ctl" && echo "контроллер совпадает с основной сборкой"
node "$ROOT/tools/bundle.mjs" >/dev/null; T1=$(sha256sum "$ROOT"/out/bundle/*-stage12.tar | cut -d' ' -f1)
node "$ROOT/tools/bundle.mjs" >/dev/null; T2=$(sha256sum "$ROOT"/out/bundle/*-stage12.tar | cut -d' ' -f1)
[ "$T1" = "$T2" ] && echo "комплект: tar совпадает при повторной сборке ($T1)"
P1=$(node "$ROOT/tools/package.mjs" --out "$R/pkg-a" | sed -n 's/.*sha256 //p'); P2=$(node "$ROOT/tools/package.mjs" --out "$R/pkg-b" | sed -n 's/.*sha256 //p')
[ -n "$P1" ] && [ "$P1" = "$P2" ] && echo "установочный пакет: tar совпадает при повторной сборке ($P1)"
