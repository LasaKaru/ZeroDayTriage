#!/usr/bin/env bash
# SessionStart hook: make sure a Claude Code (web) session can build and test this
# .NET 8 solution. Installs the SDK locally if it is not already on PATH, then restores.
set -euo pipefail

DOTNET_DIR="${DOTNET_ROOT:-$HOME/.dotnet}"

if ! command -v dotnet >/dev/null 2>&1; then
  echo "[session-start] .NET SDK not found; installing 8.0 into ${DOTNET_DIR}..."
  curl -sSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh
  bash /tmp/dotnet-install.sh --channel 8.0 --install-dir "${DOTNET_DIR}"
  export PATH="${DOTNET_DIR}:${PATH}"
fi

export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_NOLOGO=1

echo "[session-start] dotnet $(dotnet --version)"
echo "[session-start] restoring packages..."
dotnet restore ZeroDayTriage.sln >/dev/null 2>&1 || echo "[session-start] restore skipped/failed (offline?)"
echo "[session-start] ready. Build: 'dotnet build'  Test: 'dotnet test'"
