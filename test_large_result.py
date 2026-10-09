#!/usr/bin/env python3
"""Repro / verification for delivering large tool results over Streamable HTTP.

Background
----------
The Python MCP client used by the pentest harness parses responses as SSE.
Clients that derive from httpx-sse (e.g. httpx2) cap a *single* SSE event at
``DEFAULT_MAX_EVENT_SIZE_BYTES = 1024 * 1024`` (1 MiB). When a tool result is
framed as one SSE ``data:`` event bigger than that, the client aborts with:

    MCPError(-32000, 'SSE stream failed: Server-sent event exceeded the
    1048576 byte limit.')

This server now answers request/response calls with a single
``Content-Type: application/json`` reply instead of an SSE event
(``json_response=True``), which has no per-event cap. SSE is only used for
progress/notifications — of which this server sends none.

What this script checks
-----------------------
1. Root cause : the httpx2 SSE decoder really does cap an event at 1 MiB.
2. Fix        : a >1 MiB tool result arrives complete over Streamable HTTP.
3. Safety net : with KALI_MCP_MAX_RESULT_BYTES set, an oversized result is
                explicitly truncated (marker + full file on disk), never
                silently dropped.

Usage
-----
    python test_large_result.py
    # or point it at an already-running server:
    KALI_MCP_TEST_URL=http://127.0.0.1:8080/mcp KALI_MCP_AUTH_TOKEN=secret123 \
        python test_large_result.py --no-spawn
"""
from __future__ import annotations

import argparse
import asyncio
import os
import socket
import subprocess
import sys
import time

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

BIG_BYTES = 2_000_000  # ~2 MB, comfortably over the 1 MiB SSE event cap
TOKEN = os.environ.get("KALI_MCP_AUTH_TOKEN", "test-large")
BIG_COMMAND = f"yes KALI_MCP_LARGE_RESULT | head -c {BIG_BYTES}"


def demo_sse_event_cap() -> None:
    """Prove the exact 1 MiB limit that the harness client enforces."""
    try:
        from httpx2._config import DEFAULT_MAX_EVENT_SIZE_BYTES as cap
        from httpx2._sse import SSEError, _SSEEventDecoder
    except Exception as exc:  # pragma: no cover - depends on installed client
        print(f"[1] root cause: httpx2 SSE decoder unavailable ({exc}); skipped")
        return

    decoder = _SSEEventDecoder(max_event_size=cap)
    line = "data: " + ("A" * 131071)  # ~128 KiB per line
    try:
        for _ in range(20):  # ~2.5 MiB total
            decoder.decode(line)
    except SSEError as exc:
        print(f"[1] root cause confirmed: SSE event cap = {cap} bytes -> {exc}")
        return
    print("[1] root cause: no cap raised (unexpected)")


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_port(host: str, port: int, timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket() as s:
            s.settimeout(1.0)
            if s.connect_ex((host, port)) == 0:
                return
        time.sleep(0.25)
    raise TimeoutError(f"server did not open {host}:{port} in {timeout}s")


def _spawn_server(port: int, env_extra: dict) -> subprocess.Popen:
    env = {**os.environ, "KALI_MCP_AUTH_TOKEN": TOKEN, **env_extra}
    proc = subprocess.Popen(
        [sys.executable, "-m", "kali_mcp.server",
         "-t", "http", "-H", "127.0.0.1", "-p", str(port), "--auth-token", TOKEN],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
    )
    _wait_port("127.0.0.1", port)
    return proc


async def _call_big(url: str) -> str:
    headers = {"Authorization": f"Bearer {TOKEN}"}
    async with streamablehttp_client(url, headers=headers) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("run_command", {"command": BIG_COMMAND})
            if result.isError:
                raise RuntimeError(f"tool error: {result.content[0].text[:200]}")
            return result.content[0].text


async def check_delivery(port: int) -> bool:
    url = f"http://127.0.0.1:{port}/mcp"
    text = await _call_big(url)
    ok = len(text) >= BIG_BYTES - 100 and "truncated" not in text
    print(f"[2] fix: received {len(text)} bytes over Streamable HTTP "
          f"(requested {BIG_BYTES}); full={ok}")
    return ok


async def check_truncation(port: int) -> bool:
    url = f"http://127.0.0.1:{port}/mcp"
    text = await _call_big(url)
    marker = "…[truncated:"
    ok = marker in text and len(text) < BIG_BYTES
    print(f"[3] safety net: received {len(text)} bytes; truncation marker present={ok}")
    if ok:
        for line in text.splitlines():
            if "full output written to" in line:
                print(f"    {line.strip()}")
    return ok


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-spawn", action="store_true",
                        help="use KALI_MCP_TEST_URL instead of spawning a server")
    args = parser.parse_args()

    demo_sse_event_cap()

    results = []

    if args.no_spawn:
        url = os.environ.get("KALI_MCP_TEST_URL", "http://127.0.0.1:8080/mcp")
        text = await _call_big(url)
        ok = len(text) >= BIG_BYTES - 100 and "truncated" not in text
        print(f"[2] fix: received {len(text)} bytes from {url}; full={ok}")
        results.append(ok)
    else:
        # 2. Delivery with defaults (JSON response, no size cap).
        port = _free_port()
        proc = _spawn_server(port, {"KALI_MCP_JSON_RESPONSE": "true"})
        try:
            results.append(await check_delivery(port))
        finally:
            proc.terminate()
            proc.wait(timeout=10)

        # 3. Safety net with a 1 MiB cap.
        port2 = _free_port()
        proc2 = _spawn_server(port2, {"KALI_MCP_MAX_RESULT_BYTES": "1000000"})
        try:
            results.append(await check_truncation(port2))
        finally:
            proc2.terminate()
            proc2.wait(timeout=10)

    ok = all(results)
    print("\n=== " + ("PASS" if ok else "FAIL") + " ===")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
