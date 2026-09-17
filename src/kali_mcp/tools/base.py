import subprocess
import os
import shlex

DEFAULT_TIMEOUT = 120  # seconds
BLOCKED_COMMANDS = {
    "rm", "mv", "cp", "dd", "mkfs", "shutdown", "reboot", "poweroff",
    "init", "systemctl", "chown", "chmod", "wget", "curl",
}


def run_tool(command: list[str], timeout: int = DEFAULT_TIMEOUT, input_data: str = "") -> str:
    executable = os.path.basename(command[0])
    if executable in BLOCKED_COMMANDS:
        return f"[error] command '{executable}' is blocked for safety"

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_data if input_data else None,
        )
        output = result.stdout.strip() or result.stderr.strip()
        if not output:
            return "[info] command produced no output"
        return output
    except subprocess.TimeoutExpired:
        return f"[error] command timed out after {timeout}s"
    except FileNotFoundError:
        return f"[error] tool '{command[0]}' not found — is it installed?"
    except Exception as e:
        return f"[error] {e}"


def run_bash(command: str, timeout: int = DEFAULT_TIMEOUT) -> str:
    if not command or not command.strip():
        return "[error] command is required"
    try:
        args = shlex.split(command)
    except ValueError as e:
        return f"[error] invalid command: {e}"
    if not args:
        return "[error] empty command"
    return run_tool(args, timeout=timeout)


def require_target(target: str | None) -> str | None:
    if not target or not target.strip():
        return "target is required"
    return None
