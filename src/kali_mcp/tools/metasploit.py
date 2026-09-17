from ..tools.base import run_tool, require_target


def msfconsole(command: str, resource_file: str = "", opts: str = "") -> str:
    if not command:
        return "msfconsole command is required"
    cmd = ["msfconsole", "-q", "-x", f"{command}; exit"]
    if resource_file:
        cmd = ["msfconsole", "-q", "-r", resource_file]
    if opts:
        cmd[-1] = f"{command}; {opts}; exit"
    return run_tool(cmd, timeout=300)


def msfvenom(
    payload: str,
    lhost: str = "",
    lport: str = "",
    fmt: str = "raw",
    encoder: str = "",
    iterations: int = 1,
    platform: str = "",
    arch: str = "",
    template: str = "",
    outfile: str = "",
    badchars: str = "",
    opts: str = "",
) -> str:
    if not payload:
        return "payload is required (e.g. linux/x64/shell_reverse_tcp)"
    cmd = ["msfvenom", "-p", payload]
    if lhost:
        cmd.extend(["LHOST", lhost])
    if lport:
        cmd.extend(["LPORT", lport])
    if fmt:
        cmd.extend(["-f", fmt])
    if encoder:
        cmd.extend(["-e", encoder])
    if iterations > 1:
        cmd.extend(["-i", str(iterations)])
    if platform:
        cmd.extend(["--platform", platform])
    if arch:
        cmd.extend(["-a", arch])
    if template:
        cmd.extend(["-x", template])
    if outfile:
        cmd.extend(["-o", outfile])
    if badchars:
        cmd.extend(["-b", badchars])
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=120)


def msfdb(command: str = "status", opts: str = "") -> str:
    cmd = ["msfdb", command]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=30)


def search_module(query: str, module_type: str = "") -> str:
    if not query:
        return "search query is required"
    search_cmd = f"search {query}"
    if module_type:
        search_cmd += f" type:{module_type}"
    return run_tool(
        ["msfconsole", "-q", "-x", f"{search_cmd}; exit"],
        timeout=60,
    )


def show_module_info(module_path: str) -> str:
    if not module_path:
        return "module path is required"
    return run_tool(
        ["msfconsole", "-q", "-x", f"info {module_path}; exit"],
        timeout=30,
    )


def resource_script(script_path: str) -> str:
    if not script_path:
        return "resource script path is required"
    return run_tool(
        ["msfconsole", "-q", "-r", script_path],
        timeout=600,
    )
