import os
import shlex

from mcp.types import Tool
from .base import run_tool

TOOLS = [
    Tool(
        name="semgrep",
        description="Scan local source code with Semgrep Community Edition. Returns JSON findings; no account required. Rules may be a local file or registry configuration.",
        inputSchema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Local source file or directory"},
                "config": {"type": "string", "description": "Rules file or registry configuration (default: auto; downloads rules)"},
                "opts": {"type": "string", "description": "Additional Semgrep scan options"},
            },
            "required": ["path"],
        },
    ),
    Tool(
        name="gitleaks",
        description="Scan files in a local directory for leaked secrets. Returns redacted JSON findings. Scans current files, not Git history.",
        inputSchema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Local directory to scan"},
                "opts": {"type": "string", "description": "Additional Gitleaks options (e.g. --config rules.toml)"},
            },
            "required": ["path"],
        },
    ),
    Tool(
        name="trivy",
        description="Scan a local directory's dependency manifests and lockfiles for known vulnerabilities. Returns JSON; downloads and caches the vulnerability database.",
        inputSchema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Local project directory"},
                "opts": {"type": "string", "description": "Additional Trivy filesystem options"},
            },
            "required": ["path"],
        },
    ),
]

DISPATCH = {
    "semgrep": lambda **kw: semgrep(**kw),
    "gitleaks": lambda **kw: gitleaks(**kw),
    "trivy": lambda **kw: trivy(**kw),
}


def semgrep(path: str, config: str = "auto", opts: str = "") -> str:
    if not path or not os.path.exists(path):
        return "[error] path must be an existing source file or directory"
    if not config or not config.strip():
        return "[error] config is required"
    return run_tool([
        "semgrep", "scan", "--config", config, "--json", "--metrics", "off",
        *shlex.split(opts), os.path.abspath(path),
    ], timeout=600)


def gitleaks(path: str, opts: str = "") -> str:
    if not path or not os.path.isdir(path):
        return "[error] path must be an existing directory"
    return run_tool([
        "gitleaks", "dir", "--no-banner", "--redact", "--exit-code", "0",
        "--report-format", "json", "--report-path", "/dev/stdout",
        *shlex.split(opts), os.path.abspath(path),
    ], timeout=600)


def trivy(path: str, opts: str = "") -> str:
    if not path or not os.path.isdir(path):
        return "[error] path must be an existing directory"
    return run_tool([
        "trivy", "fs", "--scanners", "vuln", "--format", "json",
        *shlex.split(opts), os.path.abspath(path),
    ], timeout=600)
