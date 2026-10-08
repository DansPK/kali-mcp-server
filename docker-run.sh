#!/usr/bin/env bash
set -euo pipefail

IMAGE="kali-mcp:latest"

build() {
    echo "[*] Building $IMAGE ..."
    docker build -t "$IMAGE" .
}

run() {
    if ! docker image inspect "$IMAGE" &>/dev/null; then
        echo "[!] Image $IMAGE not found — building first"
        build
    fi

    local auth=""
    if [[ -n "${KALI_MCP_AUTH_TOKEN:-}" ]]; then
        auth="-e KALI_MCP_AUTH_TOKEN=$KALI_MCP_AUTH_TOKEN"
    fi

    echo "[*] Starting Kali MCP server (privileged mode) ..."
    exec docker run --rm -i --privileged $auth "$IMAGE"
}

compose() {
    local auth="${KALI_MCP_AUTH_TOKEN:-}"
    KALI_MCP_AUTH_TOKEN="$auth" docker compose run --rm kali-mcp
}

test_image() {
    if ! docker image inspect "$IMAGE" &>/dev/null; then
        echo "[!] Image $IMAGE not found — building first"
        build
    fi

    echo "[*] Smoke-testing $IMAGE over stdio (initialize + tools/list) ..."
    local out count
    out=$(printf '%s\n' \
        '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}' \
        '{"jsonrpc":"2.0","id":2,"method":"notifications/initialized","params":{}}' \
        '{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}' \
        | docker run --rm -i "$IMAGE" 2>/dev/null | tail -1)
    count=$(printf '%s' "$out" | grep -o '"name"' | wc -l | tr -d ' ')

    if [ "${count:-0}" -gt 0 ]; then
        echo "[+] OK: server responded with $count tools"
    else
        echo "[x] FAIL: no tools returned"
        printf '%s\n' "$out" | head -c 400
        exit 1
    fi
}

usage() {
    cat <<EOF
Usage: $0 <command>

Commands:
  build         Build the Docker image
  run           Run the MCP server (stdio) — connects to MCP client via stdin/stdout
  test          Smoke-test the image over stdio (initialize + tools/list)
  compose       Run via docker compose
  help          Show this help

Environment:
  KALI_MCP_AUTH_TOKEN    Optional auth token (passed to the server)

Examples:
  # Build and run
  ./docker-run.sh build
  ./docker-run.sh run

  # Run with auth
  KALI_MCP_AUTH_TOKEN=secret123 ./docker-run.sh run

  # MCP client config (Claude Desktop, OpenCode):
  # {
  #   "mcpServers": {
  #     "kali": {
  #       "command": "docker",
  #       "args": ["run", "--rm", "-i", "kali-mcp:latest"]
  #     }
  #   }
  # }
EOF
}

case "${1:-help}" in
    build)   build ;;
    run)     run ;;
    test)    test_image ;;
    compose) compose ;;
    *)       usage ;;
esac
