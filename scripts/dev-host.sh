#!/usr/bin/env bash
# Start sandboxd + host-agent as two processes for local development.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

RUN_DIR="${CAPSULE_RUN_DIR:-/tmp/capsule-dev}"
mkdir -p "$RUN_DIR"/{run,lib,workspaces}

export CAPSULE_SANDBOXD_SOCKET="${CAPSULE_SANDBOXD_SOCKET:-$RUN_DIR/run/sandboxd.sock}"
export CAPSULE_SANDBOXD_TOKEN="${CAPSULE_SANDBOXD_TOKEN:-dev-sandboxd-token}"
export CAPSULE_SANDBOXD_STATE_PATH="${CAPSULE_SANDBOXD_STATE_PATH:-$RUN_DIR/lib/sandboxd-state.db}"
export CAPSULE_WORKSPACE_ROOT="${CAPSULE_WORKSPACE_ROOT:-$RUN_DIR/workspaces}"
export CAPSULE_HOST_AGENT_TOKEN="${CAPSULE_HOST_AGENT_TOKEN:-dev-host-token}"
export CAPSULE_HOST_AGENT_BIND_ADDR="${CAPSULE_HOST_AGENT_BIND_ADDR:-127.0.0.1:9090}"

cleanup() {
  if [[ -n "${SANDBOXD_PID:-}" ]] && kill -0 "$SANDBOXD_PID" 2>/dev/null; then
    kill "$SANDBOXD_PID" 2>/dev/null || true
    wait "$SANDBOXD_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

# Build first so the socket wait below only covers process startup, not a
# multi-minute cold compile (the wait loop would otherwise kill the build).
echo "building sandboxd and host-agent"
cargo build -p capsule-sandboxd --bin sandboxd
cargo build -p capsule-host-agent --bin capsule-host-agent

echo "starting sandboxd on $CAPSULE_SANDBOXD_SOCKET"
cargo run -p capsule-sandboxd --bin sandboxd &
SANDBOXD_PID=$!

# Wait for the UDS to appear; fail fast if sandboxd dies first (e.g. a
# build failure or config error printed above).
for _ in $(seq 1 100); do
  if [[ -S "$CAPSULE_SANDBOXD_SOCKET" ]]; then
    break
  fi
  if ! kill -0 "$SANDBOXD_PID" 2>/dev/null; then
    echo "sandboxd exited before creating $CAPSULE_SANDBOXD_SOCKET (see error output above)" >&2
    exit 1
  fi
  sleep 0.05
done
if [[ ! -S "$CAPSULE_SANDBOXD_SOCKET" ]]; then
  echo "sandboxd socket did not appear at $CAPSULE_SANDBOXD_SOCKET" >&2
  exit 1
fi

echo "starting host-agent on $CAPSULE_HOST_AGENT_BIND_ADDR"
cargo run -p capsule-host-agent --bin capsule-host-agent
