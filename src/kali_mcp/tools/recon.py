from ..tools.base import run_tool, require_target


def enum4linux(target: str, opts: str = "") -> str:
    err = require_target(target)
    if err:
        return err
    cmd = ["enum4linux", target]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=180)


def searchsploit(query: str, opts: str = "") -> str:
    if not query:
        return "search query is required"
    cmd = ["searchsploit", query]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=60)


def subfinder(domain: str, opts: str = "") -> str:
    err = require_target(domain)
    if err:
        return err
    cmd = ["subfinder", "-d", domain]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=120)


def amass(domain: str, mode: str = "enum", opts: str = "") -> str:
    err = require_target(domain)
    if err:
        return err
    cmd = ["amass", mode, "-d", domain]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=300)


def exiftool(filepath: str, opts: str = "") -> str:
    if not filepath:
        return "filepath is required"
    cmd = ["exiftool", filepath]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=60)


def theHarvester(domain: str, source: str = "all", limit: int = 100, opts: str = "") -> str:
    err = require_target(domain)
    if err:
        return err
    cmd = ["theHarvester", "-d", domain, "-b", source, "-l", str(limit)]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=120)


def smbclient(target: str, share: str = "", user: str = "", password: str = "", command: str = "", opts: str = "") -> str:
    err = require_target(target)
    if err:
        return err
    cmd = ["smbclient"]
    if share:
        cmd.append(f"//{target}/{share}")
    if user:
        cmd.extend(["-U", user])
    if password:
        cmd.append(f"--password={password}")
    if command:
        cmd.extend(["-c", command])
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=60)
