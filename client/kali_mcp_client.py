#!/usr/bin/env python3
"""Kali MCP Client — cross-platform (Windows / Linux / macOS).

Connects to a kali-mcp server over stdio, SSE, or Streamable HTTP and lets you
list tools or call them from the command line or an interactive shell.

Examples:
  # List tools using a locally-spawned stdio server (default)
  python kali_mcp_client.py --list

  # Call a tool over stdio
  python kali_mcp_client.py --call nmap --kwargs '{"target": "127.0.0.1", "ports": "22,80"}'

  # Connect to a remote SSE server with auth
  python kali_mcp_client.py -t sse -u http://10.0.0.5:8080/sse --auth-token secret123 --list

  # Streamable HTTP transport
  python kali_mcp_client.py -t streamable-http -u http://10.0.0.5:8080/mcp --list

  # Interactive mode
  python kali_mcp_client.py -t sse -u http://10.0.0.5:8080/sse -i

Auth:
  Pass --auth-token or set KALI_MCP_AUTH_TOKEN. The token is sent as
  _meta.auth_token on every tools/list and tools/call request, matching the
  server's auth middleware. For stdio, the token is also forwarded to the
  spawned server process.
"""

import argparse
import asyncio
import json
import os
import sys

try:
    from mcp import ClientSession
    from mcp.client.stdio import stdio_client, StdioServerParameters
except ImportError:
    print("[error] the 'mcp' package is required: pip install mcp", file=sys.stderr)
    sys.exit(1)

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080
DEFAULT_CALL_TIMEOUT = 600  # seconds; server-side tool timeouts are 120-600s


# ---------------------------------------------------------------- helpers --

def result_to_dict(res):
    """Normalize an mcp result object or raw dict into a dict."""
    if isinstance(res, dict):
        return res
    return {
        "tools": getattr(res, "tools", None),
        "content": [
            {"type": getattr(c, "type", "text"), "text": getattr(c, "text", "")}
            for c in (getattr(res, "content", None) or [])
        ],
        "isError": getattr(res, "is_error", False),
    }


def format_tools(tools) -> str:
    lines = [f"{len(tools)} tools available:", ""]
    for t in tools:
        name = t.name if hasattr(t, "name") else t.get("name", "?")
        desc = (t.description if hasattr(t, "description") else t.get("description", "")) or ""
        required = []
        schema = t.inputSchema if hasattr(t, "inputSchema") else t.get("inputSchema", {}) or {}
        props = schema.get("properties", {})
        required = schema.get("required", [])
        args = ", ".join(
            f"{p}{'*' if p in required else ''}" for p in props
        )
        lines.append(f"  {name}({args})")
        # first sentence of description
        first = desc.split(". ")[0].strip()
        if first:
            lines.append(f"      {first}")
    lines.append("")
    lines.append("(* = required argument)")
    return "\n".join(lines)


def format_call_result(res) -> str:
    res = result_to_dict(res)
    if res.get("isError"):
        texts = [c.get("text", "") for c in res.get("content", [])]
        return "[tool error] " + ("\n".join(texts) or "unknown error")
    texts = [c.get("text", "") for c in res.get("content", [])]
    return "\n".join(texts) if texts else "[info] no content returned"


def format_rpc_error(exc) -> str:
    """Turn an MCP error into a friendly message."""
    msg = str(exc)
    if "-32001" in msg or "Unauthorized" in msg:
        return "[error] unauthorized — pass --auth-token (or set KALI_MCP_AUTH_TOKEN)"
    return f"[error] {msg}"


# ------------------------------------------------------------- connection --

class Client:
    def __init__(self, args):
        self.args = args
        self.token = args.auth_token or os.environ.get("KALI_MCP_AUTH_TOKEN", "")
        self._ctx = None

    async def __aenter__(self):
        a = self.args
        if a.transport == "stdio":
            server_args = list(a.server_args)
            if self.token and "--auth-token" not in server_args:
                server_args += ["--auth-token", self.token]
            params = StdioServerParameters(
                command=a.command,
                args=server_args,
            )
            self._ctx = stdio_client(params)
            read, write = await self._ctx.__aenter__()
        elif a.transport == "sse":
            from mcp.client.sse import sse_client
            self._ctx = sse_client(self._url())
            read, write = await self._ctx.__aenter__()
        elif a.transport == "streamable-http":
            from mcp.client.streamable_http import streamablehttp_client
            self._ctx = streamablehttp_client(self._url())
            read, write, _session_id = await self._ctx.__aenter__()
        else:
            raise ValueError(f"unknown transport: {a.transport}")

        self.session = ClientSession(read, write)
        await self.session.__aenter__()
        await self.session.initialize()
        return self

    async def __aexit__(self, *exc):
        try:
            await self.session.__aexit__(*exc)
        finally:
            await self._ctx.__aexit__(*exc)

    def _url(self) -> str:
        a = self.args
        if a.url:
            return a.url
        path = "/sse" if a.transport == "sse" else "/mcp"
        return f"http://{a.host}:{a.port}{path}"

    async def _rpc(self, method: str, params: dict | None = None):
        """Send a request, injecting _meta.auth_token when a token is set."""
        params = dict(params or {})
        if self.token:
            meta = dict(params.get("_meta") or {})
            meta["auth_token"] = self.token
            params["_meta"] = meta
            # Build the typed request and use send_request so _meta reaches
            # the server middleware (public helpers drop unknown _meta keys).
            from mcp.types import ListToolsRequest, CallToolRequest
            if method == "tools/list":
                request = ListToolsRequest.model_validate(
                    {"method": "tools/list", "params": params}
                )
                return await self.session.send_request(request, type(request))
            if method == "tools/call":
                request = CallToolRequest.model_validate(
                    {"method": "tools/call", "params": params}
                )
                return await self.session.send_request(request, type(request))
            raise ValueError(f"unsupported method: {method}")
        # No auth — use the public API.
        if method == "tools/list":
            return await self.session.list_tools()
        if method == "tools/call":
            return await self.session.call_tool(
                params["name"], params.get("arguments") or {}
            )
        raise ValueError(f"unsupported method: {method}")

    async def list_tools(self) -> str:
        res = await self._rpc("tools/list")
        res = result_to_dict(res)
        return format_tools(res.get("tools") or [])

    async def call_tool(self, name: str, arguments: dict) -> str:
        res = await asyncio.wait_for(
            self._rpc("tools/call", {"name": name, "arguments": arguments}),
            timeout=self.args.timeout,
        )
        return format_call_result(res)


# ------------------------------------------------------------------ modes --

async def run_one_shot(client: Client, args) -> int:
    if args.list:
        print(await client.list_tools())
        return 0
    if args.call:
        try:
            kwargs = json.loads(args.kwargs) if args.kwargs else {}
        except json.JSONDecodeError as e:
            print(f"[error] --kwargs is not valid JSON: {e}", file=sys.stderr)
            return 2
        if not isinstance(kwargs, dict):
            print("[error] --kwargs must be a JSON object", file=sys.stderr)
            return 2
        print(await client.call_tool(args.call, kwargs))
        return 0
    return 0


INTERACTIVE_HELP = """\
Interactive commands:
  list                          List available tools
  schema <tool>                 Show a tool's full description and arguments
  call <tool> [json-args]       Call a tool, e.g. call nmap {"target": "127.0.0.1"}
  help                          Show this help
  quit / exit                   Leave the client
"""


async def run_interactive(client: Client) -> int:
    tools = {}
    print("Kali MCP interactive client. Type 'help' for commands.\n")
    while True:
        try:
            raw = await asyncio.to_thread(input, "kali-mcp> ")
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        raw = raw.strip()
        if not raw:
            continue
        cmd, _, rest = raw.partition(" ")
        rest = rest.strip()
        try:
            if cmd in ("quit", "exit", "q"):
                return 0
            elif cmd == "help":
                print(INTERACTIVE_HELP)
            elif cmd in ("list", "ls"):
                listing = await client.list_tools()
                print(listing)
                # cache tool schemas for the 'schema' command
                res = result_to_dict(await client._rpc("tools/list"))
                tools = {t.name if hasattr(t, "name") else t.get("name", ""): t
                         for t in (res.get("tools") or [])}
            elif cmd == "schema":
                if not rest:
                    print("usage: schema <tool>")
                    continue
                if not tools:
                    res = result_to_dict(await client._rpc("tools/list"))
                    tools = {t.name if hasattr(t, "name") else t.get("name", ""): t
                             for t in (res.get("tools") or [])}
                t = tools.get(rest)
                if t is None:
                    print(f"[error] unknown tool: {rest} (try 'list')")
                    continue
                get = lambda o, k, d="": getattr(o, k, d) if not isinstance(o, dict) else o.get(k, d)
                print(f"{get(t, 'name')}\n{'=' * len(get(t, 'name'))}")
                print(get(t, "description", "(no description)"))
                schema = get(t, "inputSchema", {}) or {}
                props = schema.get("properties", {})
                required = schema.get("required", [])
                if props:
                    print("\nArguments:")
                    for p, spec in props.items():
                        star = "*" if p in required else " "
                        print(f"  {star}{p} ({spec.get('type', 'any')}): {spec.get('description', '')}")
            elif cmd == "call":
                if not rest:
                    print("usage: call <tool> [json-args]")
                    continue
                name, _, argstr = rest.partition(" ")
                kwargs = {}
                if argstr.strip():
                    try:
                        kwargs = json.loads(argstr)
                    except json.JSONDecodeError as e:
                        print(f"[error] arguments are not valid JSON: {e}")
                        continue
                if not isinstance(kwargs, dict):
                    print("[error] arguments must be a JSON object")
                    continue
                print(await client.call_tool(name, kwargs))
            else:
                print(f"unknown command: {cmd} (type 'help')")
        except asyncio.TimeoutError:
            print(f"[error] timed out after {client.args.timeout}s")
        except Exception as e:
            print(format_rpc_error(e))


# -------------------------------------------------------------------- main --

def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="kali-mcp-client",
        description="Client for the Kali MCP server (Windows / Linux / macOS)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Examples:")[1] if "Examples:" in __doc__ else None,
    )
    parser.add_argument(
        "-t", "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default=os.environ.get("KALI_MCP_TRANSPORT", "stdio"),
        help="Transport protocol (default: stdio). Env: KALI_MCP_TRANSPORT",
    )
    parser.add_argument(
        "-u", "--url", default="",
        help="Server URL for sse/streamable-http (e.g. http://10.0.0.5:8080/sse). "
             "Derived from --host/--port if omitted.",
    )
    parser.add_argument("--host", default=os.environ.get("KALI_MCP_HOST", DEFAULT_HOST),
                        help=f"Server host when --url is omitted (default: {DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=int(os.environ.get("KALI_MCP_PORT", DEFAULT_PORT)),
                        help=f"Server port when --url is omitted (default: {DEFAULT_PORT})")
    parser.add_argument(
        "--command", default=sys.executable,
        help="Server command for stdio transport (default: current python)",
    )
    parser.add_argument(
        "--server-args", nargs=argparse.REMAINDER, default=["-m", "kali_mcp.server"],
        help="Arguments for the stdio server process (default: -m kali_mcp.server)",
    )
    parser.add_argument(
        "--auth-token", default="",
        help="Auth token sent as _meta.auth_token (and forwarded to a stdio server). "
             "Env: KALI_MCP_AUTH_TOKEN",
    )
    parser.add_argument("--list", action="store_true", help="List tools and exit")
    parser.add_argument("--call", metavar="TOOL", help="Call a tool and exit")
    parser.add_argument("--kwargs", metavar="JSON", default="", help="Tool arguments as a JSON object")
    parser.add_argument("--timeout", type=int, default=DEFAULT_CALL_TIMEOUT,
                        help=f"Client-side timeout for --call in seconds (default: {DEFAULT_CALL_TIMEOUT})")
    parser.add_argument("-i", "--interactive", action="store_true", help="Interactive shell mode")
    args = parser.parse_args(argv)

    if not (args.list or args.call or args.interactive):
        args.interactive = True  # default to interactive when nothing else requested
    return args


async def async_main(argv=None) -> int:
    args = parse_args(argv)
    try:
        async with Client(args) as client:
            if args.interactive:
                return await run_interactive(client)
            return await run_one_shot(client, args)
    except ConnectionRefusedError:
        print(f"[error] connection refused — is the server running at {args.url or f'{args.host}:{args.port}'}?",
              file=sys.stderr)
        return 1
    except Exception as e:
        print(format_rpc_error(e), file=sys.stderr)
        return 1


def main() -> None:
    if sys.platform == "win32":
        # Subprocess + asyncio support on Windows
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    sys.exit(asyncio.run(async_main()))


if __name__ == "__main__":
    main()
