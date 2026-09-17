from ..tools.base import run_tool, require_target


def sqlmap(url: str, opts: str = "--batch --random-agent") -> str:
    err = require_target(url)
    if err:
        return err
    cmd = ["sqlmap", "-u", url]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=300)


def nikto(host: str, port: str = "80", opts: str = "") -> str:
    err = require_target(host)
    if err:
        return err
    cmd = ["nikto", "-h", host, "-p", port]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=300)


def gobuster(target: str, wordlist: str, mode: str = "dir", opts: str = "") -> str:
    err = require_target(target)
    if err:
        return err
    if not wordlist:
        return "wordlist is required"
    cmd = ["gobuster", mode, "-u", target, "-w", wordlist]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=300)


def dirb(target: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", opts: str = "") -> str:
    err = require_target(target)
    if err:
        return err
    cmd = ["dirb", target, wordlist]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=300)


def wpscan(url: str, opts: str = "--random-user-agent") -> str:
    err = require_target(url)
    if err:
        return err
    cmd = ["wpscan", "--url", url]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=300)


def ffuf(target: str, wordlist: str, match_code: str = "200,301,302", opts: str = "") -> str:
    err = require_target(target)
    if err:
        return err
    if not wordlist:
        return "wordlist is required"
    cmd = ["ffuf", "-u", target, "-w", wordlist, "-mc", match_code]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=300)


def nuclei(target: str, opts: str = "-severity medium,high,critical") -> str:
    err = require_target(target)
    if err:
        return err
    cmd = ["nuclei", "-target", target]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=300)


def whatweb(target: str, opts: str = "") -> str:
    err = require_target(target)
    if err:
        return err
    cmd = ["whatweb", target]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=120)


def wfuzz(target: str, wordlist: str, filter_code: str = "", opts: str = "") -> str:
    err = require_target(target)
    if err:
        return err
    if not wordlist:
        return "wordlist is required"
    cmd = ["wfuzz", "-u", target, "-w", wordlist]
    if filter_code:
        cmd.extend(["--hc", filter_code])
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=300)


def xsser(url: str, opts: str = "--auto") -> str:
    err = require_target(url)
    if err:
        return err
    cmd = ["xsser", "-u", url]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=180)


def commix(url: str, opts: str = "--batch") -> str:
    err = require_target(url)
    if err:
        return err
    cmd = ["commix", "--url", url]
    if opts:
        cmd.extend(opts.split())
    return run_tool(cmd, timeout=300)
