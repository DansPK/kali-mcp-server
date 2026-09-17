from ..tools.base import run_tool, require_target


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
