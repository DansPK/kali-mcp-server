from ..tools.base import run_tool, require_target


def nmap(target: str, ports: str = "", opts: str = "-sV -sC") -> str:
    err = require_target(target)
    if err:
        return err
    cmd = ["nmap"]
    if opts:
        cmd.extend(opts.split())
    if ports:
        cmd.extend(["-p", ports])
    cmd.append(target)
    return run_tool(cmd, timeout=300)


def masscan(target: str, ports: str = "1-65535", rate: int = 1000) -> str:
    err = require_target(target)
    if err:
        return err
    cmd = ["masscan", target, "-p", ports, "--rate", str(rate)]
    return run_tool(cmd, timeout=300)


def netcat(host: str, port: str, connect: bool = True) -> str:
    err = require_target(host)
    if err:
        return err
    cmd = ["nc", "-v"]
    if connect:
        cmd.append(host)
        cmd.append(port)
    else:
        cmd.extend(["-l", "-p", port])
    return run_tool(cmd, timeout=30)


def tcpdump(interface: str = "eth0", count: int = 50, filt: str = "") -> str:
    cmd = ["tcpdump", "-i", interface, "-c", str(count), "-n"]
    if filt:
        cmd.append(filt)
    return run_tool(cmd, timeout=60)


def arp_scan(target: str, iface: str = "", opts: str = "") -> str:
    err = require_target(target)
    if err:
        return err
    cmd = ["arp-scan", target]
    if iface:
        cmd.extend(["--interface", iface])
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=60)


def onesixtyone(target: str, community: str = "public", opts: str = "") -> str:
    err = require_target(target)
    if err:
        return err
    cmd = ["onesixtyone", "-c", community, target]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=60)


def dnsrecon(domain: str, opts: str = "-t std") -> str:
    err = require_target(domain)
    if err:
        return err
    cmd = ["dnsrecon", "-d", domain]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=120)


def tshark(iface: str = "eth0", count: int = 50, read_file: str = "", filt: str = "", opts: str = "") -> str:
    cmd = ["tshark"]
    if read_file:
        cmd.extend(["-r", read_file])
    else:
        cmd.extend(["-i", iface, "-c", str(count)])
    if filt:
        cmd.extend(["-f", filt])
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=60)
