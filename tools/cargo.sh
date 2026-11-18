#!/usr/bin/env bash
# Запускает cargo из изолированного тулчейна проекта (.tools), не трогая PATH и профиль пользователя.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export RUSTUP_HOME="$ROOT/.tools/rustup" CARGO_HOME="$ROOT/.tools/cargo"
export PATH="$CARGO_HOME/bin:$PATH"
cd "$ROOT/controller"
exec cargo "$@"
