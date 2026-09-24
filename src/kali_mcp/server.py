import argparse
import asyncio
import functools
import os
import sys
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.shared.exceptions import MCPError as McpError
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


async def handle_list_tools(ctx, _req: ListToolsRequest) -> ListToolsResult:
    return ListToolsResult(tools=ALL_TOOLS)


async def handle_call_tool(ctx, req: CallToolRequestParams) -> CallToolResult:
    handler = TOOL_DISPATCH.get(req.name)
    if not handler:
        return CallToolResult(
            content=[TextContent(type="text", text=f"[error] unknown tool: {req.name}")],
            is_error=True,
        )

    args = req.arguments or {}
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, functools.partial(handler, **args))
    return CallToolResult(content=[TextContent(type="text", text=str(result))])


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
        _check(req)
        return await original_list(req)

    async def authed_call(req):
        _check(req)
        return await original_call(req)

    handlers[_LTR] = authed_list
    handlers[_CTR] = authed_call


def _parse_args() -> argparse.Namespace:
    """Parse command-line arguments with environment variable fallbacks."""
    parser = argparse.ArgumentParser(
        prog="kali-mcp",
        description="Kali MCP Server — expose Kali Linux security tools via Model Context Protocol",
    )
    parser.add_argument(
        "--host", "-H",
        default=os.environ.get("KALI_MCP_HOST", "127.0.0.1"),
        help="Listening IP address (default: 127.0.0.1). Env: KALI_MCP_HOST",
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=int(os.environ.get("KALI_MCP_PORT", "8080")),
        help="Listening port (default: 8080). Env: KALI_MCP_PORT",
    )
    parser.add_argument(
        "--transport", "-t",
        choices=["stdio", "sse", "streamable-http"],
        default=os.environ.get("KALI_MCP_TRANSPORT", "stdio"),
        help="Transport protocol (default: stdio). Env: KALI_MCP_TRANSPORT",
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
    return parser.parse_args()


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

    app = Starlette(
        debug=False,
        routes=[
            Route("/sse", endpoint=handle_sse, methods=["GET"]),
            Mount("/messages/", app=sse_transport.handle_post_message),
        ],
    )

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
    from starlette.routing import Route, Mount
    from mcp.server.streamable_http_manager import StreamableHTTPSessionManager

    session_manager = StreamableHTTPSessionManager(
        app=server,
        json_response=False,
        stateless=True,  # stateless: no session persistence, fresh transport per request
    )

    @asynccontextmanager
    async def lifespan(app: Starlette):
        async with session_manager.run():
            yield

    async def handle_http(request):
        await session_manager.handle_request(
            request.scope, request.receive, request._send
        )

    app = Starlette(
        debug=False,
        lifespan=lifespan,
        routes=[
            Route("/mcp", endpoint=handle_http, methods=["GET", "POST", "DELETE"]),
        ],
    )

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

    if args.transport == "sse":
        protocol = "https" if args.ssl_certfile else "http"
        print(f"Kali MCP Server starting on {protocol}://{args.host}:{args.port} (SSE transport)")
        asyncio.run(_run_sse_server(args.host, args.port, args.ssl_certfile, args.ssl_keyfile))
    elif args.transport == "streamable-http":
        protocol = "https" if args.ssl_certfile else "http"
        print(f"Kali MCP Server starting on {protocol}://{args.host}:{args.port} (Streamable HTTP transport)")
        asyncio.run(_run_streamable_http_server(args.host, args.port, args.ssl_certfile, args.ssl_keyfile))
    else:
        print("Kali MCP Server starting (stdio transport)")
        asyncio.run(_run_stdio_server())


if __name__ == "__main__":
    main()
