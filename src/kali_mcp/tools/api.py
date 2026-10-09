import os
import shlex

from mcp.types import Tool
from .base import require_target, run_tool

TOOLS = [
    Tool(
        name="schemathesis",
        description="Test an OpenAPI or GraphQL API for schema violations and server errors using generated requests. A local schema requires --url in opts. Failed checks return an error with the test report.",
        inputSchema={
            "type": "object",
            "properties": {
                "schema": {"type": "string", "description": "Schema URL or existing local schema file"},
                "opts": {"type": "string", "description": "Additional run options, including --url, --header, and --max-examples"},
            },
            "required": ["schema"],
        },
    ),
    Tool(
        name="newman",
        description="Run an exported Postman collection for API regression tests. Supports a local environment file. Failed assertions return an error with the test report.",
        inputSchema={
            "type": "object",
            "properties": {
                "collection": {"type": "string", "description": "Existing local Postman collection JSON file"},
                "environment": {"type": "string", "description": "Optional local Postman environment JSON file"},
                "opts": {"type": "string", "description": "Additional Newman run options"},
            },
            "required": ["collection"],
        },
    ),
]

DISPATCH = {
    "schemathesis": lambda **kw: schemathesis(**kw),
    "newman": lambda **kw: newman(**kw),
}


def schemathesis(schema: str, opts: str = "") -> str:
    if require_target(schema):
        return "[error] schema is required"
    if not schema.startswith(("http://", "https://")):
        if not os.path.isfile(schema):
            return "[error] schema must be a URL or existing local file"
        schema = os.path.abspath(schema)
    return run_tool(["schemathesis", "run", *shlex.split(opts), schema], timeout=600)


def newman(collection: str, environment: str = "", opts: str = "") -> str:
    if not collection or not os.path.isfile(collection):
        return "[error] collection must be an existing file"
    cmd = ["newman", "run", os.path.abspath(collection), "--color", "off"]
    if environment:
        if not os.path.isfile(environment):
            return "[error] environment must be an existing file"
        cmd.extend(["--environment", os.path.abspath(environment)])
    return run_tool([*cmd, *shlex.split(opts)], timeout=600)
