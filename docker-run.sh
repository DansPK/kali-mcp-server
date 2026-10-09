#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="kali-mcp:latest"

require_docker() {
    if ! docker info >/dev/null 2>&1; then
        echo "[error] Docker is not running. Start Docker, then retry." >&2
        exit 1
    fi
}

build() {
    require_docker
    docker build --platform linux/amd64 -t "$IMAGE" "$ROOT"
}

ensure_image() {
    require_docker
    if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
        build >&2
    fi
}

run() {
    ensure_image
    echo "[*] Starting $IMAGE (stdio) ..." >&2
    exec docker run --rm -i --platform linux/amd64 \
        --cap-add=NET_ADMIN --cap-add=NET_RAW \
        --mount type=volume,src=kali-mcp-cache,dst=/root/.cache \
        --mount type=volume,src=kali-nuclei-templates,dst=/root/nuclei-templates \
        -e KALI_MCP_AUTH_TOKEN "$IMAGE"
}

release() {
    ensure_image
    local image_id
    image_id="$(docker image inspect --format '{{.Id}}' "$IMAGE")"
    docker tag "$image_id" kali-worker:1.0
    echo "[+] Tagged $image_id as kali-worker:1.0"
}

case "${1:-help}" in
    build) build ;;
    run) run ;;
    release) release ;;
    compose) require_docker; docker compose -f "$ROOT/docker-compose.yml" run --rm kali-mcp ;;
    help) printf '%s\n' 'Usage: ./docker-run.sh build|release|run|compose' \
        'build: AMD64 Kali image; release: tag kali-worker:1.0' \
        'run: stdio MCP with optional KALI_MCP_AUTH_TOKEN' ;;
    *) echo "[error] unknown command: $1" >&2; exit 2 ;;
esac
