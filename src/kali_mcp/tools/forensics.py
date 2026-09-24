from mcp.types import Tool
from ..tools.base import run_tool, require_target

TOOLS = [
    Tool(
        name="binwalk",
        description=(
            "Firmware analysis tool — scans binary files for embedded file signatures, compressed data, "
            "and filesystem structures. Automatically extracts discovered files when using -e. "
            "Use for reverse engineering firmware images, IoT device binaries, or any blob that may contain embedded files. "
            "Output: offset map of discovered signatures and extracted file paths."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "filepath": {"type": "string", "description": "Path to firmware image or binary file to analyze"},
                "opts": {"type": "string", "description": "Additional binwalk options. Default: -e (extract embedded files). Use '-M' for recursive scan."},
            },
            "required": ["filepath"],
        },
    ),
    Tool(
        name="volatility",
        description=(
            "Memory forensics framework for analyzing RAM dumps. Extracts running processes, network connections, "
            "loaded DLLs, registry hives, injected code, and malware artifacts from memory images. "
            "Requires a memory profile matching the source OS version. "
            "Output: structured forensic data — process trees, network sockets, registry keys, or flagged anomalies."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "profile": {"type": "string", "description": "Memory profile matching the OS (e.g. 'Win7SP1x64', 'Win10x64_19041', 'Win2016x64')"},
                "image": {"type": "string", "description": "Path to memory dump file (.raw, .vmem, .mem)"},
                "plugin": {"type": "string", "description": "Plugin to run (e.g. pslist, pstree, netscan, malfind, cmdscan, hivelist, timeliner)"},
                "opts": {"type": "string", "description": "Additional volatility options (e.g. '-p PID' to filter by process ID)"},
            },
            "required": ["image", "plugin"],
        },
    ),
    Tool(
        name="foremost",
        description=(
            "File carving tool — recovers deleted files from disk images and raw data by searching for file headers, "
            "footers, and data structures. Supports common formats: images, documents, archives, executables. "
            "Use for data recovery from formatted drives, corrupted media, or when filesystem metadata is lost. "
            "Output: recovered files organized by type in the output directory."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "filepath": {"type": "string", "description": "Path to disk image or raw data file to carve"},
                "output_dir": {"type": "string", "description": "Output directory for recovered files (default: foremost_output)"},
                "opts": {"type": "string", "description": "Additional foremost options (e.g. '-t jpg,pdf,doc' to limit to specific file types)"},
            },
            "required": ["filepath"],
        },
    ),
    Tool(
        name="steghide",
        description=(
            "Steganography tool — hides data within image (JPEG, BMP) and audio (WAV, AU) files, "
            "or extracts hidden data from them. Uses passphrase-protected embedding. "
            "Use to detect hidden messages in files (CTF challenges) or to conceal data. "
            "Output: embedded file confirmation or extracted hidden content."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Operation: 'info' (check if file has hidden data), 'embed' (hide data), 'extract' (recover hidden data). Default: info"},
                "embed_file": {"type": "string", "description": "File to hide inside the cover file (for embed mode)"},
                "cover_file": {"type": "string", "description": "Cover image/audio file to hide data in (for embed) or stego file to analyze"},
                "stego_file": {"type": "string", "description": "Output stego file (for embed) or source stego file to extract from (for extract)"},
                "passphrase": {"type": "string", "description": "Passphrase used to embed or extract the hidden data"},
                "opts": {"type": "string", "description": "Additional steghide options"},
            },
            "required": [],
        },
    ),
]

DISPATCH = {
    "binwalk": lambda **kw: binwalk(**kw),
    "volatility": lambda **kw: volatility(**kw),
    "foremost": lambda **kw: foremost(**kw),
    "steghide": lambda **kw: steghide(**kw),
}


def binwalk(filepath: str, opts: str = "-e") -> str:
    if not filepath:
        return "filepath is required"
    cmd = ["binwalk", filepath]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=180)


def volatility(profile: str, image: str, plugin: str, opts: str = "") -> str:
    if not image or not plugin:
        return "image and plugin are required"
    cmd = ["volatility", "-f", image, "--profile", profile, plugin]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=600)


def foremost(filepath: str, output_dir: str = "foremost_output", opts: str = "") -> str:
    if not filepath:
        return "filepath is required"
    cmd = ["foremost", "-i", filepath, "-o", output_dir]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=600)


def steghide(command: str = "info", embed_file: str = "", cover_file: str = "", stego_file: str = "", passphrase: str = "", opts: str = "") -> str:
    cmd = ["steghide", command]
    if embed_file:
        cmd.extend(["-ef", embed_file])
    if cover_file:
        cmd.extend(["-cf", cover_file])
    if stego_file:
        cmd.extend(["-sf", stego_file])
    if passphrase:
        cmd.extend(["-p", passphrase])
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=120)
