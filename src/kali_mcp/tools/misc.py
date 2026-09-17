from ..tools.base import run_tool, require_target


def aircrack_ng(capture_file: str, wordlist: str = "", opts: str = "") -> str:
    if not capture_file:
        return "capture_file is required"
    cmd = ["aircrack-ng", capture_file]
    if wordlist:
        cmd.extend(["-w", wordlist])
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=600)


def responder(interface: str, opts: str = "") -> str:
    if not interface:
        return "interface is required"
    cmd = ["responder", "-I", interface]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=300)


def impacket(module: str, target: str, opts: str = "") -> str:
    if not module:
        return "impacket module is required"
    err = require_target(target)
    if err:
        return err
    script = f"impacket-{module}" if not module.startswith("impacket-") else module
    cmd = [script, target]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=120)


def mimikatz(opts: str = "") -> str:
    cmd = ["mimikatz"]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=60)


def bettercap(iface: str = "", caplet: str = "", opts: str = "") -> str:
    cmd = ["bettercap"]
    if iface:
        cmd.extend(["-iface", iface])
    if caplet:
        cmd.extend(["-caplet", caplet])
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=300)


def hash_identifier(hash_str: str = "", hashfile: str = "") -> str:
    if not hash_str and not hashfile:
        return "hash_str or hashfile is required"
    cmd = ["hash-identifier"]
    if hashfile:
        return run_tool(["hash-identifier", hashfile], timeout=30)
    return run_tool(cmd, timeout=30, input_data=hash_str)


def cewl(url: str, depth: int = 2, min_length: int = 3, outfile: str = "", opts: str = "") -> str:
    err = require_target(url)
    if err:
        return err
    cmd = ["cewl", url, "-d", str(depth), "-m", str(min_length)]
    if outfile:
        cmd.extend(["-w", outfile])
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=180)


def proxychains(command: str, opts: str = "") -> str:
    if not command:
        return "command is required"
    cmd = ["proxychains4"] + command.split()
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=300)


def wifite(opts: str = "--kill") -> str:
    cmd = ["wifite"]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=600)


def reaver(interface: str, bssid: str, channel: str = "", opts: str = "") -> str:
    if not interface or not bssid:
        return "interface and bssid are required"
    cmd = ["reaver", "-i", interface, "-b", bssid]
    if channel:
        cmd.extend(["-c", channel])
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=600)
