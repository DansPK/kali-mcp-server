import subprocess
import os
import re
import shlex

DEFAULT_TIMEOUT = 120  # seconds
BLOCKED_COMMANDS = {
    "rm", "mv", "cp", "dd", "mkfs", "shutdown", "reboot", "poweroff",
    "init", "systemctl", "chown", "chmod", "wget", "curl",
}

# Splits a command string into candidate tokens on whitespace and every
# shell metacharacter, so tokens hidden behind chaining or substitution
# (e.g. "echo hi; rm -rf /", "$(rm -rf /)", `rm -rf /`, "cat x | rm")
# are still checked against the denylist.
_SHELL_TOKEN_SPLIT = re.compile(r"[\s;|&><`$()]+")

# Commands that could damage the Kali system itself. Full shell syntax
# (pipes, chaining, redirection, substitution) is allowed; only these
# destructive binaries are refused.
DANGEROUS_PATTERNS = [
    r"\brm\b", r"\bmv\b", r"\bcp\b", r"\bdd\b", r"\bmkfs\b",
    r"\bshutdown\b", r"\breboot\b", r"\bpoweroff\b", r"\binit\b",
    r"\bsystemctl\b", r"\bchown\b", r"\bchmod\b", r"\bwget\b", r"\bcurl\b",
    r">\s*/dev/sd[a-z]", r"mkfs\.\w+", r":\(\)\s*\{.*\};\s*:",  # fork bomb
]

# Prefixes that are transparent wrappers: the next token is the real
# command and must itself be allowlisted.
_WRAPPER_COMMANDS = {"sudo", "timeout", "nice", "ionice", "stdbuf", "env", "nohup", "time"}

# Allowlist for run_command: only these binaries may be invoked. This is
# the primary gate; the denylist above remains as defense-in-depth.
# Anything not listed (interpreters, package managers, shells-as-command,
# file mutators, etc.) is rejected — use the dedicated MCP tools instead.
ALLOWED_COMMANDS = {
    # --- text / file inspection ---
    "cat", "head", "tail", "less", "more", "wc", "sort", "uniq", "cut",
    "awk", "sed", "grep", "egrep", "fgrep", "tr", "strings", "file",
    "diff", "comm", "join", "paste", "column", "fold", "fmt", "nl",
    "tac", "rev", "xxd", "hexdump", "od", "base64", "md5sum", "sha1sum",
    "sha256sum", "sha512sum", "stat", "readlink", "realpath", "basename",
    "dirname", "find", "locate", "which", "whereis", "whatweb",
    # --- directory listing / navigation (read-only usage) ---
    "ls", "pwd", "tree", "du", "df",
    # --- system info ---
    "uname", "hostname", "uptime", "whoami", "id", "groups", "date",
    "cal", "ps", "top", "free", "lscpu", "lsblk", "lspci", "lsusb",
    "env", "printenv", "arch", "nproc", "lsmod", "dmesg",
    # --- network info / recon (read-only) ---
    "ip", "ifconfig", "ss", "netstat", "arp", "route", "ping", "ping6",
    "traceroute", "tracepath", "dig", "nslookup", "host", "whois",
    "arping", "nc", "netcat", "ncat", "socat",
    # --- security tooling (Kali staples, non-mutating) ---
    "nmap", "masscan", "arp-scan", "onesixtyone", "dnsrecon", "dnsenum",
    "nikto", "whatweb", "wafw00f", "sublist3r", "amass", "subfinder",
    "enum4linux", "smbclient", "smbmap", "showmount", "rpcinfo",
    "snmpwalk", "snmpget", "searchsploit", "theHarvester", "exiftool",
    "hash-identifier", "hashid", "wafw00f",
    # --- misc safe utilities ---
    "echo", "printf", "seq", "yes", "true", "false", "sleep", "wait",
    "xargs", "touch", "mkdir", "ln",
    "tar", "gzip", "gunzip", "bzip2", "xz", "zip", "unzip", "7z",
    "git", "jq",
}
# NOTE: interpreters (python, perl, ruby, bash, sh, ...) are deliberately
# NOT allowlisted — they can execute arbitrary code (e.g.
# python3 -c 'os.system("rm -rf /")') and would bypass the denylist.
# Add them back only if you accept that tradeoff.


def _command_segments(command: str) -> list[str]:
    """Split a command string into individual pipeline segments.

    Handles chaining (&&, ||, ;) and command substitution ($(), ``) so
    every invoked binary is checked, not just the first.
    """
    # Normalize chained separators to newlines.
    text = re.sub(r"&&|\|\||;|\n", "\n", command)
    segments: list[str] = []
    # Walk the string, pulling out $() and `` substitutions as their own
    # segments while keeping the surrounding text as segments too.
    pos = 0
    for m in re.finditer(r"\$\(([^()]*)\)|`([^`]*)`", text):
        before = text[pos:m.start()]
        if before.strip():
            segments.extend(s.strip() for s in before.split("\n") if s.strip())
        inner = m.group(1) if m.group(1) is not None else m.group(2)
        if inner and inner.strip():
            segments.append(inner.strip())
        pos = m.end()
    tail = text[pos:]
    if tail.strip():
        segments.extend(s.strip() for s in tail.split("\n") if s.strip())
    return segments


def _segment_leads(segment: str) -> str | None:
    """Extract the leading binary name from one pipeline segment.

    Returns None if the segment is empty or contains no command.
    Skips redirections and wrapper prefixes (sudo, timeout, env, ...).
    """
    # Remove redirections (they don't change which binary runs).
    segment = re.sub(r"\d*>>?|\d*<", " ", segment)
    # Remove pipes within the segment: each side is its own command.
    try:
        tokens = shlex.split(segment, posix=True)
    except ValueError:
        # Unbalanced quotes — fall back to naive splitting; the denylist
        # layer still runs on the raw string afterwards.
        tokens = segment.split()
    if not tokens:
        return None
    # Skip leading variable assignments (FOO=bar cmd ...)
    idx = 0
    while idx < len(tokens) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tokens[idx]):
        idx += 1
    # Skip wrapper prefixes; the wrapped command must also be allowlisted.
    while idx < len(tokens) and os.path.basename(tokens[idx]) in _WRAPPER_COMMANDS:
        idx += 1
        # timeout takes a DURATION argument (e.g. "timeout 10 cmd");
        # nice/ionice take -n N; env may take NAME=VALUE pairs. Skip
        # options and their values until the wrapped command appears.
        while idx < len(tokens):
            tok = tokens[idx]
            if tok.startswith("-"):
                idx += 1  # an option flag
                # flags with separate values (-n 5): skip the value too
                if tok in ("-n", "-i", "-p", "-o", "--adjustment") and idx < len(tokens):
                    idx += 1
            elif re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tok):
                idx += 1  # env NAME=VALUE
            elif re.match(r"^\d+[smhd]?$", tok):
                idx += 1  # timeout duration like "10" or "90s"
            else:
                break
    if idx >= len(tokens):
        return None
    return os.path.basename(tokens[idx])


def _find_disallowed(command: str) -> str | None:
    """Return the first binary in the command that is not allowlisted."""
    for segment in _command_segments(command):
        for sub in segment.split("|"):
            lead = _segment_leads(sub)
            if lead and lead not in ALLOWED_COMMANDS:
                return lead
    return None


def _find_blocked(command: str) -> str | None:
    """Check every token of the command string against the denylist.

    Quoted strings are stripped first, so words inside quotes
    (e.g. grep 'mkfs', echo "rm") don't trigger false positives.
    The remaining string is split on whitespace and shell metacharacters
    so blocked commands can't be smuggled in via chaining (&&, ;, |)
    or substitution ($(), ``). Regex patterns additionally catch
    variants like mkfs.ext4 and raw-device redirections.
    """
    # Strip quoted strings (single and double) before any matching.
    unquoted = re.sub(r"'[^']*'|\"[^\"]*\"", "", command)

    for token in _SHELL_TOKEN_SPLIT.split(unquoted):
        token = token.strip("'\"")
        if not token:
            continue
        name = os.path.basename(token)  # catches /bin/rm, ./dd, sudo rm, etc.
        if name in BLOCKED_COMMANDS:
            return name
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, unquoted):
            return pattern
    return None


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

    # 1. Allowlist check (primary gate): every binary in every segment
    #    (chains, pipelines, substitutions) must be explicitly allowed.
    disallowed = _find_disallowed(command)
    if disallowed:
        return (
            f"[error] command '{disallowed}' is not in the allowed list. "
            f"run_command only permits known-safe tools; use a dedicated MCP tool if one exists."
        )

    # 2. Denylist check (defense-in-depth): blocks destructive patterns
    #    even if something slips into the allowlist later.
    blocked = _find_blocked(command)
    if blocked:
        return f"[error] command '{blocked}' is blocked for safety"

    try:
        result = subprocess.run(
            command,
            shell=True,
            executable="/bin/bash",
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = result.stdout.strip() or result.stderr.strip()
        if not output:
            return f"[info] command produced no output (exit code {result.returncode})"
        return output
    except subprocess.TimeoutExpired:
        return f"[error] command timed out after {timeout}s"
    except Exception as e:
        return f"[error] {e}"


def require_target(target: str | None) -> str | None:
    if not target or not target.strip():
        return "target is required"
    return None
