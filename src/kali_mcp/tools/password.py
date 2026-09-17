from ..tools.base import run_tool, require_target


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
