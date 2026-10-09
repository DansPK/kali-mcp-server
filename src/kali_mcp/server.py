import argparse
import asyncio
import contextvars
import functools
import hmac
import os
import sys
import tempfile
import urllib.parse
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.shared.exceptions import McpError
from mcp.types import (
    Tool,
    TextContent,
    ListToolsResult,
    CallToolResult,
    CallToolRequestParams,
    ListToolsRequest,
    ErrorData,
)

from kali_mcp.tools import ALL_TOOLS, TOOL_DISPATCH

server = Server("kali-mcp")
AUTH_TOKEN: str = ""
_AUTH_HEADER_OK: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "kali_mcp_auth_header_ok", default=False
)

# Return request responses as plain application/json instead of SSE frames.
# A single SSE event is capped at 1 MiB by common clients (httpx-sse /
# httpx2 DEFAULT_MAX_EVENT_SIZE_BYTES), which aborts large tool results with
# -32000; a JSON reply has no such per-event limit. SSE is only needed when the
# server streams progress/notifications, which this server does not. Set
# KALI_MCP_JSON_RESPONSE=false only for SSE-only clients.
JSON_RESPONSE = os.environ.get("KALI_MCP_JSON_RESPONSE", "true").strip().lower() not in (
    "0", "false", "no", "off",
)

# Optional safety net: cap the size of a single tool result (bytes). 0 = no
# limit (default) so arbitrarily large results are delivered verbatim. When
# set, an oversized result keeps the leading bytes plus a truncation marker and
# the full output is written to a file on the server — never silently dropped.
try:
    MAX_RESULT_BYTES = int(os.environ.get("KALI_MCP_MAX_RESULT_BYTES", "0"))
except ValueError:
    MAX_RESULT_BYTES = 0


def _limit_result(text: str) -> str:
    """Apply the optional result-size cap (see MAX_RESULT_BYTES)."""
    if MAX_RESULT_BYTES <= 0:
        return text
    data = text.encode("utf-8", "replace")
    if len(data) <= MAX_RESULT_BYTES:
        return text
    try:
        fd, location = tempfile.mkstemp(prefix="kali-mcp-result-", suffix=".txt")
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
    except Exception:
        location = "<unable to write overflow file>"
    head = data[:MAX_RESULT_BYTES].decode("utf-8", "ignore")
    return (
        f"{head}\n\n"
        f"…[truncated: {MAX_RESULT_BYTES} of {len(data)} bytes shown; "
        f"full output written to {location}]"
    )


async def handle_list_tools(ctx, _req: ListToolsRequest) -> ListToolsResult:
    return ListToolsResult(tools=ALL_TOOLS)


async def handle_call_tool(ctx, req: CallToolRequestParams) -> CallToolResult:
    handler = TOOL_DISPATCH.get(req.name)
    if not handler:
        return CallToolResult(
            content=[TextContent(type="text", text=f"[error] unknown tool: {req.name}")],
            isError=True,
        )

    args = req.arguments or {}
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, functools.partial(handler, **args))
    text = str(result)
    return CallToolResult(
        content=[TextContent(type="text", text=_limit_result(text))],
        isError=text.startswith("[error]"),
    )


def register_handlers() -> None:
    @server.list_tools()
    async def _list_tools() -> list[Tool]:
        return await handle_list_tools(None, ListToolsRequest())

    @server.call_tool()
    async def _call_tool(name: str, arguments: dict | None) -> CallToolResult:
        return await handle_call_tool(
            None, CallToolRequestParams(name=name, arguments=arguments)
        )


def register_auth_middleware() -> None:
    """Token auth via handler wrapping (mcp >= 1.9 has no middleware API).

    Replaces the handlers registered by register_handlers() so every
    tools/list and tools/call request must carry _meta.auth_token.
    """
    handlers = server.request_handlers
    from mcp.types import ListToolsRequest as _LTR, CallToolRequest as _CTR

    original_list = handlers.get(_LTR)
    original_call = handlers.get(_CTR)
    if original_list is None or original_call is None:
        raise RuntimeError(
            "register_handlers() must be called before register_auth_middleware()"
        )

    def _check(req) -> None:
        if not AUTH_TOKEN:
            return
        # HTTP-header auth (validated by HeaderAuthMiddleware) bypasses the
        # _meta.auth_token check for clients that only support custom headers.
        if _AUTH_HEADER_OK.get():
            return
        # Requests are pydantic models with a .params (or root.params) attribute;
        # _meta.auth_token arrives inside params.
        params = getattr(req, "params", None)
        if params is None and hasattr(req, "root"):
            params = getattr(req.root, "params", None)
        meta = getattr(params, "meta", None) if params is not None else None
        if meta is None and isinstance(params, dict):
            meta = params.get("_meta", {})
        token = ""
        if isinstance(meta, dict):
            token = meta.get("auth_token", "")
        elif meta is not None:
            token = getattr(meta, "auth_token", "") or ""
        if token != AUTH_TOKEN:
            raise McpError(
                ErrorData(
                    code=-32001,
                    message="Unauthorized: invalid or missing auth_token in _meta",
                )
            )

    async def authed_list(req):
        # The SDK passes None when refreshing its internal tool-schema cache.
        if req is not None:
            _check(req)
        return await original_list(req)

    async def authed_call(req):
        _check(req)
        return await original_call(req)

    handlers[_LTR] = authed_list
    handlers[_CTR] = authed_call


class HeaderAuthMiddleware:
    """ASGI middleware enabling HTTP header auth (e.g. ``Authorization: Bearer``).

    Clients that can only set request headers (OpenCode, IDEs, browsers) are
    validated here; the result is propagated to the JSON-RPC handler through a
    context variable so requests without ``_meta.auth_token`` still pass.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http" or not AUTH_TOKEN:
            await self.app(scope, receive, send)
            return

        token = ""
        for name, value in scope.get("headers") or []:
            lname = name.lower()
            val = value.decode("latin-1")
            if lname == b"authorization" and val.lower().startswith("bearer "):
                token = val[7:].strip()
            elif lname in (b"x-auth-token", b"x-kali-mcp-auth-token"):
                token = val.strip()

        if token and hmac.compare_digest(token, AUTH_TOKEN):
            ctx_token = _AUTH_HEADER_OK.set(True)
            try:
                await self.app(scope, receive, send)
            finally:
                _AUTH_HEADER_OK.reset(ctx_token)
            return

        await self.app(scope, receive, send)


# Friendly aliases accepted for --transport / KALI_MCP_TRANSPORT.
_TRANSPORT_ALIASES = {
    "http": "streamable-http",
    "https": "streamable-http",
    "streamable_http": "streamable-http",
    "streamablehttp": "streamable-http",
    "streamable": "streamable-http",
}


def _normalize_transport(value: str) -> str:
    v = (value or "stdio").strip().lower()
    return _TRANSPORT_ALIASES.get(v, v)


def _split_url(url: str) -> tuple[str, int]:
    """Return (host, port) from a URL, tolerant of a missing scheme."""
    if not url:
        return "", 0
    parsed = urllib.parse.urlparse(url if "://" in url else "http://" + url)
    return parsed.hostname or "", parsed.port or 0


def _parse_args() -> argparse.Namespace:
    """Parse command-line arguments with environment variable fallbacks."""
    parser = argparse.ArgumentParser(
        prog="kali-mcp",
        description="Kali MCP Server — expose Kali Linux security tools via Model Context Protocol",
    )

    # KALI_MCP_URL supplies the bind host/port when the more specific
    # KALI_MCP_HOST / KALI_MCP_PORT are not set.
    url_host, url_port = _split_url(os.environ.get("KALI_MCP_URL", ""))

    parser.add_argument(
        "--host", "-H",
        default=os.environ.get("KALI_MCP_HOST", url_host or "127.0.0.1"),
        help="Listening IP address (default: 127.0.0.1). Env: KALI_MCP_HOST, else KALI_MCP_URL host",
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=int(os.environ.get("KALI_MCP_PORT", url_port or 8080)),
        help="Listening port (default: 8080). Env: KALI_MCP_PORT, else KALI_MCP_URL port",
    )
    parser.add_argument(
        "--url", "-u",
        default="",
        help="Base URL whose host/port override --host/--port "
             "(e.g. http://192.168.1.5:8080/mcp). Env: KALI_MCP_URL",
    )
    parser.add_argument(
        "--transport", "-t",
        choices=["stdio", "sse", "streamable-http", "http", "https"],
        default=os.environ.get("KALI_MCP_TRANSPORT", "stdio"),
        help="Transport protocol: stdio, sse, streamable-http (aliases: http, https). "
             "Env: KALI_MCP_TRANSPORT",
    )
    parser.add_argument(
        "--ssl-certfile",
        default=os.environ.get("KALI_MCP_SSL_CERTFILE", ""),
        help="Path to SSL certificate file (PEM format) for HTTPS. Env: KALI_MCP_SSL_CERTFILE",
    )
    parser.add_argument(
        "--ssl-keyfile",
        default=os.environ.get("KALI_MCP_SSL_KEYFILE", ""),
        help="Path to SSL private key file (PEM format) for HTTPS. Env: KALI_MCP_SSL_KEYFILE",
    )
    parser.add_argument(
        "--auth-token",
        default=os.environ.get("KALI_MCP_AUTH_TOKEN", ""),
        help="Authentication token required by clients. Env: KALI_MCP_AUTH_TOKEN",
    )
    args = parser.parse_args()

    args.transport = _normalize_transport(args.transport)
    # An explicit URL (env KALI_MCP_URL is applied via defaults; the flag wins)
    # overrides host/port.
    if args.url:
        url_host, url_port = _split_url(args.url)
        if url_host:
            args.host = url_host
        if url_port:
            args.port = url_port

    if args.transport not in ("stdio", "sse", "streamable-http"):
        parser.error(f"invalid transport: {args.transport}")

    return args


async def _run_stdio_server() -> None:
    """Run the MCP server over standard input/output (default)."""
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


async def _run_sse_server(host: str, port: int, ssl_certfile: str, ssl_keyfile: str) -> None:
    """Run the MCP server over SSE (Server-Sent Events) via HTTP/HTTPS."""
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import Response
    from starlette.routing import Mount, Route
    from starlette.types import Receive, Scope, Send
    from mcp.server.sse import SseServerTransport

    sse_transport = SseServerTransport("/messages/")

    async def handle_sse(request: Request) -> Response:
        async with sse_transport.connect_sse(
            request.scope,
            request.receive,
            request._send,
        ) as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                server.create_initialization_options(),
            )
        # connect_sse already streamed the response; return an empty one so
        # Starlette doesn't try to serialize a None return value.
        return Response()

    app = Starlette(
        debug=False,
        routes=[
            Route("/sse", endpoint=handle_sse, methods=["GET"]),
            Mount("/messages/", app=sse_transport.handle_post_message),
        ],
    )
    app = HeaderAuthMiddleware(app)

    import uvicorn
    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        ssl_certfile=ssl_certfile or None,
        ssl_keyfile=ssl_keyfile or None,
        log_level="info",
    )
    srv = uvicorn.Server(config)
    await srv.serve()


async def _run_streamable_http_server(host: str, port: int, ssl_certfile: str, ssl_keyfile: str) -> None:
    """Run the MCP server over Streamable HTTP."""
    from contextlib import asynccontextmanager
    from starlette.applications import Starlette
    from starlette.routing import Mount
    from mcp.server.streamable_http_manager import StreamableHTTPSessionManager

    session_manager = StreamableHTTPSessionManager(
        app=server,
        # JSON replies avoid the client's per-SSE-event size cap (1 MiB) that
        # otherwise aborts large tool results with -32000. See JSON_RESPONSE.
        json_response=JSON_RESPONSE,
        stateless=True,  # stateless: no session persistence, fresh transport per request
    )

    @asynccontextmanager
    async def lifespan(app: Starlette):
        async with session_manager.run():
            yield

    app = Starlette(
        debug=False,
        lifespan=lifespan,
        routes=[
            # Mount the session manager's ASGI app directly. It writes the
            # response itself and returns None, so it must not be used as a
            # Route endpoint (Starlette would treat None as a Response and
            # raise TypeError). Root-mount (rather than "/mcp") so that a
            # request to "/mcp" is not 307-redirected to "/mcp/".
            Mount("", app=session_manager.handle_request),
        ],
    )
    app = HeaderAuthMiddleware(app)

    import uvicorn
    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        ssl_certfile=ssl_certfile or None,
        ssl_keyfile=ssl_keyfile or None,
        log_level="info",
    )
    srv = uvicorn.Server(config)
    await srv.serve()


def main() -> None:
    global AUTH_TOKEN
    args = _parse_args()
    AUTH_TOKEN = args.auth_token

    register_handlers()
    register_auth_middleware()

    # Diagnostics go to stderr: in stdio mode stdout carries the JSON-RPC
    # stream and must stay clean.
    if args.transport == "sse":
        protocol = "https" if args.ssl_certfile else "http"
        print(f"Kali MCP Server starting on {protocol}://{args.host}:{args.port} (SSE transport)", file=sys.stderr)
        asyncio.run(_run_sse_server(args.host, args.port, args.ssl_certfile, args.ssl_keyfile))
    elif args.transport == "streamable-http":
        protocol = "https" if args.ssl_certfile else "http"
        print(f"Kali MCP Server starting on {protocol}://{args.host}:{args.port} (Streamable HTTP transport)", file=sys.stderr)
        asyncio.run(_run_streamable_http_server(args.host, args.port, args.ssl_certfile, args.ssl_keyfile))
    else:
        print("Kali MCP Server starting (stdio transport)", file=sys.stderr)
        asyncio.run(_run_stdio_server())


if __name__ == "__main__":
    main()
