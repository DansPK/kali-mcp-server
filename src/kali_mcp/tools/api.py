import os
import re
import shlex
from pathlib import Path

from mcp.types import Tool
from .base import require_target, run_tool

TOOLS = [
    Tool(
        name="schemathesis",
        description="Test OpenAPI/GraphQL APIs with authentication, operation filters, stateful request sequences, reproducible seeds, and optional JSON/HAR/JUnit reports. A local schema needs base_url or --url in opts. Failed checks return an error with the report.",
        inputSchema={
            "type": "object",
            "properties": {
                "schema": {"type": "string", "description": "Schema URL or existing local schema file"},
                "base_url": {"type": "string", "description": "API base URL; required for local schemas unless supplied in opts"},
                "headers": {"type": "object", "additionalProperties": {"type": "string"}, "description": "Request headers, including Authorization or Cookie"},
                "basic_auth": {"type": "string", "description": "Optional username:password for HTTP basic authentication"},
                "include_paths": {"type": "array", "items": {"type": "string"}, "description": "Exact API paths to include, e.g. /users/{id}"},
                "include_methods": {"type": "array", "items": {"type": "string"}, "description": "HTTP methods to include, e.g. GET and POST"},
                "phases": {"type": "array", "items": {"type": "string", "enum": ["examples", "coverage", "fuzzing", "stateful"]}, "description": "Phases to run; omitted uses Schemathesis defaults"},
                "checks": {"type": "array", "items": {"type": "string"}, "description": "Response checks, e.g. not_a_server_error or ignored_auth"},
                "max_examples": {"type": "integer", "minimum": 1, "description": "Maximum generated examples per operation (default: 50)"},
                "seed": {"type": ["integer", "null"], "description": "Optional seed for reproducible data generation"},
                "report_dir": {"type": "string", "description": "Optional directory for JSON verdict, HAR requests, and JUnit reports"},
                "rate_limit": {"type": "string", "description": "Request budget, e.g. 5/s, 100/m, or auto (default: 5/s)"},
                "timeout": {"type": "integer", "minimum": 1, "maximum": 3600, "description": "Run time budget in seconds (default: 600)"},
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


def schemathesis(schema: str, opts: str = "", base_url: str = "", headers: dict | None = None,
                 basic_auth: str = "", include_paths: list[str] | None = None,
                 include_methods: list[str] | None = None, phases: list[str] | None = None,
                 checks: list[str] | None = None, max_examples: int = 50, seed: int | None = None,
                 report_dir: str = "", rate_limit: str = "5/s", timeout: int = 600) -> str:
    if require_target(schema):
        return "[error] schema is required"
    if not schema.startswith(("http://", "https://")):
        if not os.path.isfile(schema):
            return "[error] schema must be a URL or existing local file"
        schema = os.path.abspath(schema)
    if not 1 <= timeout <= 3600 or max_examples < 1:
        return "[error] timeout must be 1–3600 seconds and max_examples must be positive"
    if base_url and not base_url.startswith(("http://", "https://")):
        return "[error] base_url must be an HTTP(S) URL"
    if phases and any(item not in ("examples", "coverage", "fuzzing", "stateful") for item in phases):
        return "[error] invalid Schemathesis phase"
    command = ["schemathesis", "run", "--no-color", "--max-examples", str(max_examples),
               "--rate-limit", rate_limit]
    if base_url:
        command.extend(["--url", base_url])
    if basic_auth:
        command.extend(["--auth", basic_auth])
    for key, value in (headers or {}).items():
        if not isinstance(key, str) or not isinstance(value, str) or any(c in key + value for c in "\r\n"):
            return "[error] headers must contain string names/values without newlines"
        command.extend(["--header", f"{key}: {value}"])
    # Schemathesis ORs separate include flags. A combined operation-name
    # expression keeps path and method selection intersected as users expect.
    if include_paths and include_methods:
        methods = "|".join(re.escape(method.upper()) for method in include_methods)
        paths = "|".join(re.escape(path) for path in include_paths)
        command.extend(["--include-name-regex", f"^(?:{methods}) (?:{paths})$"])
    else:
        for path in include_paths or []:
            command.extend(["--include-path", path])
        for method in include_methods or []:
            command.extend(["--include-method", method.upper()])
    if phases:
        command.extend(["--phases", ",".join(phases)])
    if checks:
        command.extend(["--checks", ",".join(checks)])
    if seed is not None:
        command.extend(["--seed", str(seed)])
    if report_dir:
        try:
            Path(report_dir).mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return f"[error] report_dir is not writable: {exc}"
        report_dir = str(Path(report_dir).resolve())
        command.extend(["--report", "json,har,junit", "--report-dir", report_dir])
    output = run_tool([*command, *shlex.split(opts), schema], timeout=timeout)
    if report_dir:
        files = sorted(str(path) for path in Path(report_dir).iterdir() if path.is_file())
        output += "\nReports: " + (", ".join(files) if files else "no report files generated")
    return output


def newman(collection: str, environment: str = "", opts: str = "") -> str:
    if not collection or not os.path.isfile(collection):
        return "[error] collection must be an existing file"
    cmd = ["newman", "run", os.path.abspath(collection), "--color", "off"]
    if environment:
        if not os.path.isfile(environment):
            return "[error] environment must be an existing file"
        cmd.extend(["--environment", os.path.abspath(environment)])
    return run_tool([*cmd, *shlex.split(opts)], timeout=600)
