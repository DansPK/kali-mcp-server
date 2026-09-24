from mcp.types import Tool
from ..tools.base import run_tool, require_target

TOOLS = [
    Tool(
        name="hydra",
        description=(
            "Fast network login brute-force tool supporting 50+ protocols (SSH, FTP, HTTP, RDP, SMB, MySQL, etc.). "
            "Use for testing password strength on network services. Specify the target service and provide user/password lists. "
            "For offline hash cracking, use john or hashcat instead. "
            "Output: found credentials in login:password format, or 'no valid credentials found'."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target host or IP"},
                "service": {"type": "string", "description": "Service name (e.g. ssh, ftp, http-post-form, rdp, smb, mysql)"},
                "userlist": {"type": "string", "description": "Single username OR path to user wordlist file"},
                "passlist": {"type": "string", "description": "Path to password wordlist file"},
                "opts": {"type": "string", "description": "Additional hydra options (e.g. '-t 4' for threads, '-V' for verbose)"},
            },
            "required": ["target", "service", "userlist", "passlist"],
        },
    ),
    Tool(
        name="john",
        description=(
            "John the Ripper — offline password hash cracker. Supports hundreds of hash formats with auto-detection. "
            "Use for cracking password hashes extracted from /etc/shadow, SAM databases, or captured network hashes. "
            "CPU-based — better for smaller hash sets or when GPU is unavailable. "
            "For GPU-accelerated cracking of large hash sets, prefer hashcat. "
            "Output: cracked passwords with their corresponding hashes."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "hashfile": {"type": "string", "description": "Path to file containing hashes (one per line or colon-separated)"},
                "wordlist": {"type": "string", "description": "Path to wordlist for dictionary attack (optional — uses brute-force if omitted)"},
                "fmt": {"type": "string", "description": "Force hash format (e.g. 'raw-md5', 'sha256crypt', 'nt'). Auto-detect if omitted."},
                "opts": {"type": "string", "description": "Additional john options (e.g. '--rules' for word mangling, '--show' to display cracked)"},
            },
            "required": ["hashfile"],
        },
    ),
    Tool(
        name="hashcat",
        description=(
            "World's fastest GPU-accelerated password cracker with 300+ hash type modes. "
            "Use for high-performance cracking of large hash sets. REQUIRES the mode number matching the hash type. "
            "For CPU-only or auto-detect cracking, use john instead. Use hash_identifier first if unsure of hash type. "
            "Output: cracked hashes with their plaintext passwords. Status lines show cracking speed and progress."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "hashfile": {"type": "string", "description": "Path to file containing hashes"},
                "wordlist": {"type": "string", "description": "Path to wordlist file"},
                "mode": {"type": "integer", "description": "Hash type mode number. Key values: 0=MD5, 100=NTLM, 1000=SHA1, 1400=SHA256, 1800=sha512crypt"},
                "opts": {"type": "string", "description": "Additional hashcat options (e.g. '-r rules/best64.rule' for rules, '--show' for results)"},
            },
            "required": ["hashfile", "wordlist"],
        },
    ),
    Tool(
        name="crunch",
        description=(
            "Wordlist generator — creates custom password lists based on character sets, length ranges, and patterns. "
            "Use to generate targeted wordlists when you know password policy (min/max length, required characters). "
            "For generating wordlists from website content (password profiling), use cewl instead. "
            "Output: wordlist printed to stdout or written to a file."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "min_len": {"type": "integer", "description": "Minimum word length (e.g. 6)"},
                "max_len": {"type": "integer", "description": "Maximum word length (e.g. 8)"},
                "charset": {"type": "string", "description": "Character set to use (e.g. 'abc123!@#' or '0123456789' for numeric-only)"},
                "output": {"type": "string", "description": "Output file path to save generated wordlist"},
                "opts": {"type": "string", "description": "Additional crunch options (e.g. '-t @@@%%%' for pattern: 3 lowercase + 3 digits)"},
            },
            "required": ["min_len", "max_len"],
        },
    ),
]

DISPATCH = {
    "hydra": lambda **kw: hydra(**kw),
    "john": lambda **kw: john(**kw),
    "hashcat": lambda **kw: hashcat(**kw),
    "crunch": lambda **kw: crunch(**kw),
}


def hydra(target: str, service: str, userlist: str, passlist: str, opts: str = "") -> str:
    err = require_target(target)
    if err:
        return err
    if not service or not userlist or not passlist:
        return "service, userlist, and passlist are required"
    cmd = ["hydra", "-l" if "/" not in userlist else "-L", userlist,
           "-P", passlist, f"{service}://{target}"]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=600)


def john(hashfile: str, wordlist: str = "", fmt: str = "", opts: str = "") -> str:
    if not hashfile:
        return "hashfile is required"
    cmd = ["john", hashfile]
    if wordlist:
        cmd.extend(["--wordlist", wordlist])
    if fmt:
        cmd.extend(["--format", fmt])
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=600)


def hashcat(hashfile: str, wordlist: str, mode: int = 0, opts: str = "") -> str:
    if not hashfile or not wordlist:
        return "hashfile and wordlist are required"
    cmd = ["hashcat", "-m", str(mode), hashfile, wordlist]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=600)


def crunch(min_len: int, max_len: int, charset: str = "", output: str = "", opts: str = "") -> str:
    if min_len < 1 or max_len < min_len:
        return "invalid length range"
    cmd = ["crunch", str(min_len), str(max_len)]
    if charset:
        cmd.append(charset)
    if output:
        cmd.extend(["-o", output])
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=120)
