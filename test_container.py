"""Container verification: inventory, MCP/auth/transports, and local functional fixtures.

Run inside the image using docker-run.sh test. --protocol-only runs the MCP
checks on a development machine without claiming the Kali tools were tested.
"""
import argparse
import asyncio
import gzip
import hashlib
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import platform
import shlex
import shutil
import socket
import ssl
import struct
import sys
import tempfile
import threading

import httpx
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamablehttp_client
from mcp.shared.exceptions import McpError
from mcp.types import CallToolRequest, CallToolResult, ListToolsRequest, ListToolsResult
from kali_mcp.tools import ALL_TOOLS, TOOL_DISPATCH
from kali_mcp.tools.base import run_tool, start_background, stop_background
from kali_mcp.tools.zap import _zap_script

TOKEN = "container-verification-token"
BIG_BYTES = 2_000_000

# Shared binaries are started once; every MCP name must appear in this map.
INVENTORY = [
    ("nmap", ["-h"], "nmap"),
    ("masscan", ["--help"], "masscan"),
    ("nc", ["-h"], "netcat"),
    ("tcpdump", ["--help"], "tcpdump"),
    ("arp-scan", ["--help"], "arp_scan"),
    ("onesixtyone", ["-h"], "onesixtyone"),
    ("dnsrecon", ["--help"], "dnsrecon"),
    ("tshark", ["--help"], "tshark"),
    ("sqlmap", ["--help"], "sqlmap"),
    ("nikto", ["-Help"], "nikto"),
    ("gobuster", ["--help"], "gobuster"),
    ("dirb", [], "dirb"),
    ("wpscan", ["--help"], "wpscan"),
    ("ffuf", ["-h"], "ffuf"),
    ("nuclei", ["-h"], "nuclei"),
    ("whatweb", ["--help"], "whatweb"),
    ("wfuzz", ["--help"], "wfuzz"),
    ("xsser", ["--help"], "xsser"),
    ("commix", ["--help"], "commix"),
    ("hydra", ["-h"], "hydra"),
    ("john", [], "john"),
    ("hashcat", ["--help"], "hashcat"),
    ("crunch", [], "crunch"),
    ("enum4linux", ["-h"], "enum4linux"),
    ("searchsploit", ["--help"], "searchsploit"),
    ("subfinder", ["-h"], "subfinder"),
    ("amass", ["-h"], "amass"),
    ("exiftool", ["-ver"], "exiftool"),
    ("theHarvester", ["-h"], "theHarvester"),
    ("smbclient", ["--help"], "smbclient"),
    ("msfconsole", ["--help"], "msfconsole msf_search msf_info msf_resource"),
    ("msfvenom", ["--help"], "msfvenom evasive_payload list_payloads list_encoders list_encryption shellcode_to_exe"),
    ("msfdb", ["--help"], "msfdb"),
    ("binwalk", ["--help"], "binwalk"),
    ("vol", ["--help"], "volatility"),
    ("foremost", ["-h"], "foremost"),
    ("steghide", ["--help"], "steghide"),
    ("crackmapexec", ["--help"], "crackmapexec"),
    ("evil-winrm", ["--help"], "evil_winrm"),
    ("chisel", ["--help"], "chisel"),
    ("aircrack-ng", ["--help"], "aircrack_ng"),
    ("responder", ["-h"], "responder"),
    ("impacket-secretsdump", ["-h"], "impacket"),
    ("mimikatz", [], "mimikatz"),
    ("bettercap", ["-h"], "bettercap"),
    ("hashid", ["--help"], "hash_identifier"),
    ("cewl", ["--help"], "cewl"),
    ("proxychains4", ["true"], "proxychains"),
    ("wifite", ["--help"], "wifite"),
    ("reaver", ["-h"], "reaver"),
    ("bash", ["--version"], "run_command"),
    ("zaproxy", ["-version"], "zap_start zap_stop zap_status zap_spider zap_active_scan zap_scan zap_alerts zap_report"),
    ("semgrep", ["--version"], "semgrep"),
    ("gitleaks", ["version"], "gitleaks"),
    ("trivy", ["--version"], "trivy"),
    ("httpx-toolkit", ["-version"], "httpx_probe"),
    ("testssl", ["--version"], "testssl"),
    ("schemathesis", ["--version"], "schemathesis"),
    ("newman", ["--version"], "newman"),
    ("naabu", ["-version"], "naabu"),
]


class Verification:
    def __init__(self):
        self.checks = []
        self.functional = set()

    def record(self, name, ok, detail=""):
        self.checks.append({"name": name, "passed": bool(ok), "detail": detail})
        print(f"[{'PASS' if ok else 'FAIL'}] {name}: {detail[:200]}", flush=True)

    def inventory(self):
        names = [tool.name for tool in ALL_TOOLS]
        expected = {name for _, _, tools in INVENTORY for name in tools.split()}
        self.record("registry", len(names) == len(set(names)) == 75 and set(names) == expected == set(TOOL_DISPATCH))
        self.record("architecture", platform.system() == "Linux" and platform.machine() == "x86_64", platform.platform())
        for binary, args, _ in INVENTORY:
            if not shutil.which(binary):
                self.record(f"startup:{binary}", False, "executable missing")
                continue
            output = run_tool([binary, *args], timeout=180, input_data="\n")
            # Some CLIs intentionally exit nonzero for help; crashes/timeouts are failures.
            fatal = ("[error] tool", "timed out", "traceback (most recent call last)", "modulenotfounderror", "importerror:", "syntaxerror:", "segmentation fault", "cannot load such file", "unrecognized option", "unknown flag")
            ok = bool(output.strip()) and not any(marker in output.lower() for marker in fatal)
            if output.startswith("[error]"):
                ok = ok and any(marker in output.lower() for marker in ("usage", "options", "help"))
            self.record(f"startup:{binary}", ok, output[:300])
        java = run_tool(["java", "-version"])
        self.record("java-21", 'version "21.' in java, java)
        self.record("zap-launcher", bool(_zap_script()), _zap_script())
        self.record("mimikatz-resources", Path("/usr/share/windows-resources/mimikatz/x64/mimikatz.exe").is_file())
        self.record("default-wordlist", Path("/usr/share/wordlists/dirb/common.txt").is_file())

    async def call(self, session, name, arguments, expect, error=False, label=""):
        try:
            result = await asyncio.wait_for(session.call_tool(name, arguments), timeout=650)
            text = "\n".join(c.text for c in result.content if hasattr(c, "text"))
            assert result.isError == error, text[:500]
            assert expect(text), text[:500]
            self.functional.add(name)
            self.record(label or f"functional:{name}", True)
            return text
        except Exception as exc:
            self.record(label or f"functional:{name}", False, str(exc))
            return ""

    async def stdio(self, fixtures):
        params = StdioServerParameters(command=sys.executable, args=["-m", "kali_mcp.server", "--auth-token", TOKEN], env=dict(os.environ))
        async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
            await session.initialize()
            try:
                await session.list_tools()
                self.record("stdio-reject-missing-token", False)
            except McpError as exc:
                self.record("stdio-reject-missing-token", exc.error.code == -32001)
            call = CallToolRequest.model_validate({"method": "tools/call", "params": {"name": "run_command", "arguments": {"command": "echo AUTH_FIRST_CALL"}, "_meta": {"auth_token": TOKEN}}})
            result = await session.send_request(call, CallToolResult)
            self.record("stdio-authenticated-call-before-list", not result.isError and result.content[0].text == "AUTH_FIRST_CALL")
            call.params.meta.auth_token = "wrong-token"
            try:
                await session.send_request(call, CallToolResult)
                self.record("stdio-reject-wrong-token", False)
            except McpError as exc:
                self.record("stdio-reject-wrong-token", exc.error.code == -32001)
            req = ListToolsRequest.model_validate({"method": "tools/list", "params": {"_meta": {"auth_token": TOKEN}}})
            result = await session.send_request(req, ListToolsResult)
            self.record("stdio-discovery", {t.name for t in result.tools} == set(TOOL_DISPATCH) and len(result.tools) == 75)
        # Functional calls use the normal public API on a separate no-auth stdio server.
        params.args[-1] = ""
        async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
            await session.initialize()
            await self.call(session, "run_command", {"command": "echo KALI_FIXTURE"}, lambda s: s == "KALI_FIXTURE", label="stdio-call")
            if fixtures:
                await self.fixtures(session, fixtures)

    async def http(self, cap=0):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        with tempfile.TemporaryDirectory() as location:
            log = Path(location) / "http.log"
            env = {**os.environ, "KALI_MCP_JSON_RESPONSE": "true", "KALI_MCP_MAX_RESULT_BYTES": str(cap)}
            proc = start_background([sys.executable, "-m", "kali_mcp.server", "-t", "http", "-p", str(port), "--auth-token", TOKEN], env=env, log_file=str(log))
            url = f"http://127.0.0.1:{port}/mcp"
            try:
                for _ in range(120):
                    with socket.socket() as sock:
                        ready = sock.connect_ex(("127.0.0.1", port)) == 0
                    if ready:
                        break
                    if proc.poll() is not None:
                        raise RuntimeError(log.read_text()[-1000:])
                    await asyncio.sleep(0.25)
                else:
                    raise TimeoutError("HTTP server did not start")
                headers = {"Authorization": f"Bearer {TOKEN}"}
                async with streamablehttp_client(url, headers=headers) as (read, write, _), ClientSession(read, write) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    self.record(f"http-discovery:cap={cap}", len(tools.tools) == 75 and {t.name for t in tools.tools} == set(TOOL_DISPATCH))
                    text = await self.call(session, "run_command", {"command": f"yes KALI_LARGE_FIXTURE | head -c {BIG_BYTES}"},
                                           lambda s: "…[truncated:" in s if cap else len(s.encode()) >= BIG_BYTES - 100,
                                           label=f"http-large-result:cap={cap}")
                    if cap and text:
                        overflow = text.split("full output written to ", 1)[1].rsplit("]", 1)[0]
                        self.record("overflow-file", Path(overflow).stat().st_size >= BIG_BYTES - 100)
                        Path(overflow).unlink()
                if not cap:
                    async with httpx.AsyncClient() as client:
                        response = await client.post(url, headers={**headers, "Accept": "application/json, text/event-stream"}, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
                        self.record("http-json-framing", response.status_code == 200 and response.headers.get("content-type", "").startswith("application/json") and len(response.json().get("result", {}).get("tools", [])) == 75)
                    async with streamablehttp_client(url) as (read, write, _), ClientSession(read, write) as session:
                        await session.initialize()
                        try:
                            await session.list_tools()
                            self.record("http-reject-missing-token", False)
                        except McpError as exc:
                            self.record("http-reject-missing-token", exc.error.code == -32001)
            finally:
                stop_background(proc)

    async def fixtures(self, session, f):
        path, url, tls_port, http_port = f
        q = lambda name: shlex.quote(str(path / name))
        await self.call(session, "semgrep", {"path": str(path / "source"), "config": str(path / "rules.yaml")}, lambda s: any(r["check_id"].split(".")[-1] == "fixture-eval" for r in json.loads(s)["results"]))
        await self.call(session, "gitleaks", {"path": str(path / "source"), "opts": f"--config {q('gitleaks.toml')}"}, lambda s: any(r["RuleID"] == "fixture-secret" for r in json.loads(s)) and "fixture_secret_123456" not in s)
        await self.call(session, "trivy", {"path": str(path / "dependencies")}, lambda s: any(v.get("PkgName") == "lodash" for r in json.loads(s).get("Results", []) for v in r.get("Vulnerabilities", [])))
        await self.call(session, "httpx_probe", {"target": url}, lambda s: any(json.loads(line).get("status_code") == 200 for line in s.splitlines()))
        await self.call(session, "testssl", {"target": f"127.0.0.1:{tls_port}", "opts": "--protocols --nodns none"}, lambda s: "TLS 1.2" in s or "TLSv1.2" in s)
        await self.call(session, "schemathesis", {"schema": url + "/openapi.json", "opts": "--max-examples 2 --phases examples,fuzzing --checks not_a_server_error"}, lambda s: "500" in s and "fail" in s.lower(), error=True)
        await self.call(session, "newman", {"collection": str(path / "collection.json")}, lambda s: "fixture-status" in s and "200" in s)
        await self.call(session, "newman", {"collection": str(path / "failing-collection.json")}, lambda s: "AssertionError" in s, error=True, label="newman-reject-failed-assertion")
        await self.call(session, "naabu", {"target": "127.0.0.1", "ports": str(http_port), "opts": "-Pn -retries 1 -warm-up-time 0"}, lambda s: any(json.loads(line).get("port") == http_port for line in s.splitlines()))
        await self.call(session, "nmap", {"target": "127.0.0.1", "ports": str(http_port), "opts": "-sT -Pn -n"}, lambda s: f"{http_port}/tcp open" in s)
        await self.call(session, "whatweb", {"target": url}, lambda s: "200 OK" in s)
        await self.call(session, "ffuf", {"target": url + "/FUZZ", "wordlist": str(path / "words.txt"), "opts": "-noninteractive -s"}, lambda s: "hidden" in s)
        await self.call(session, "cewl", {"url": url, "depth": 0}, lambda s: "fixtureword" in s)
        await self.call(session, "crunch", {"min_len": 1, "max_len": 1, "charset": "ab"}, lambda s: s.splitlines() == ["a", "b"])
        await self.call(session, "hash_identifier", {"hash_str": "5f4dcc3b5aa765d61d8327deb882cf99"}, lambda s: "MD5" in s)
        await self.call(session, "john", {"hashfile": str(path / "hash.txt"), "wordlist": str(path / "passwords.txt"), "fmt": "raw-md5", "opts": f"--pot={q('john.pot')}"}, lambda s: "kali_fixture" in s)
        await self.call(session, "hashcat", {"hashfile": str(path / "hash.txt"), "wordlist": str(path / "passwords.txt"), "mode": 0, "opts": "-D 1 --potfile-disable --restore-disable -w 1"}, lambda s: "kali_fixture" in s and "Cracked" in s)
        await self.call(session, "exiftool", {"filepath": str(path / "sample.gz")}, lambda s: "gzip" in s.lower())
        await self.call(session, "binwalk", {"filepath": str(path / "sample.gz"), "opts": ""}, lambda s: "gzip" in s.lower())
        await self.call(session, "tshark", {"read_file": str(path / "sample.pcap"), "opts": "-T fields -e ip.dst"}, lambda s: s.strip() == "127.0.0.1")
        capture = asyncio.create_task(self.call(session, "tcpdump", {"interface": "lo", "count": 1}, lambda s: "127.0.0.1" in s))
        await asyncio.sleep(1)
        async with httpx.AsyncClient() as client:
            await client.get(url)
        await capture
        await self.call(session, "foremost", {"filepath": str(path / "sample.pdf"), "output_dir": str(path / "carved"), "opts": "-t pdf"}, lambda s: bool(list((path / "carved" / "pdf").glob("*.pdf"))))
        await self.call(session, "steghide", {"command": "embed", "embed_file": str(path / "message.txt"), "cover_file": str(path / "cover.bmp"), "stego_file": str(path / "stego.bmp"), "passphrase": "fixture", "opts": "-q"}, lambda s: (path / "stego.bmp").is_file(), label="steghide-embed")
        await self.call(session, "steghide", {"command": "extract", "stego_file": str(path / "stego.bmp"), "passphrase": "fixture", "opts": f"-q -xf {q('extracted.txt')}"}, lambda s: (path / "extracted.txt").read_text() == "fixture message", label="steghide-extract")
        await self.call(session, "mimikatz", {}, lambda s: "mimikatz.exe" in s)
        await self.call(session, "searchsploit", {"query": "eternalblue"}, lambda s: "eternalblue" in s.lower() and "exploit" in s.lower())
        started = await self.call(session, "zap_start", {}, lambda s: "ZAP" in s and "[error]" not in s)
        if started:
            try:
                await self.call(session, "zap_status", {}, lambda s: "ZAP" in s)
                await self.call(session, "zap_spider", {"url": url, "timeout": 60}, lambda s: "completed" in s and url in s)
            finally:
                await self.call(session, "zap_stop", {}, lambda s: "stop" in s.lower() or "shutdown" in s.lower())


class FixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        route = self.path.split("?", 1)[0]
        if route == "/openapi.json":
            body = json.dumps({"openapi": "3.0.3", "info": {"title": "fixture", "version": "1"}, "servers": [{"url": f"http://127.0.0.1:{self.server.server_port}"}], "paths": {"/bug": {"get": {"responses": {"200": {"description": "OK"}}}}}}).encode()
            status, kind = 200, "application/json"
        elif route == "/bug":
            body, status, kind = b'{"error":"intentional fixture bug"}', 500, "application/json"
        elif route in ("/", "/hidden"):
            body, status, kind = b'<html><title>Kali Fixture</title><a href="/hidden">fixtureword</a></html>', 200, "text/html"
        else:
            body, status, kind = b"missing", 404, "text/plain"
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def create_fixtures(path):
    (path / "source").mkdir()
    (path / "source" / "unsafe.py").write_text('eval(input())\napi_key = "fixture_secret_123456"\n')
    (path / "rules.yaml").write_text('rules:\n- id: fixture-eval\n  languages: [python]\n  message: fixture finding\n  severity: ERROR\n  pattern: eval(...)\n')
    (path / "gitleaks.toml").write_text('[[rules]]\nid = "fixture-secret"\ndescription = "dummy fixture only"\nregex = "fixture_secret_[0-9]+"\n')
    (path / "dependencies").mkdir()
    (path / "dependencies" / "package-lock.json").write_text(json.dumps({"name": "fixture", "version": "1.0.0", "lockfileVersion": 2, "packages": {"": {"name": "fixture", "version": "1.0.0", "dependencies": {"lodash": "4.17.20"}}, "node_modules/lodash": {"version": "4.17.20", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"}}, "dependencies": {"lodash": {"version": "4.17.20"}}}))
    (path / "words.txt").write_text("hidden\nmissing\n")
    (path / "passwords.txt").write_text("kali_fixture\n")
    (path / "hash.txt").write_text(hashlib.md5(b"kali_fixture").hexdigest() + "\n")
    (path / "sample.gz").write_bytes(gzip.compress(b"fixture" * 100))
    (path / "sample.pdf").write_bytes(b"%PDF-1.4\n" + b"fixture " * 500 + b"\n%%EOF\n")
    (path / "message.txt").write_text("fixture message")
    pixels = bytes((i * 47) % 256 for i in range(128 * 128 * 3))
    bmp = struct.pack("<2sIHHI", b"BM", 54 + len(pixels), 0, 0, 54) + struct.pack("<IiiHHIIiiII", 40, 128, 128, 1, 24, 0, len(pixels), 2835, 2835, 0, 0)
    (path / "cover.bmp").write_bytes(bmp + pixels)
    packet = bytes.fromhex("00000000000100000000000208004500001d00000000401100007f0000017f00000104d2162e00090000") + b"X"
    (path / "sample.pcap").write_bytes(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1) + struct.pack("<IIII", 1, 0, len(packet), len(packet)) + packet)
    http = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    tls = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    cert, key = str(path / "cert.pem"), str(path / "key.pem")
    output = run_tool(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost", "-keyout", key, "-out", cert])
    if not Path(cert).is_file():
        http.server_close()
        tls.server_close()
        raise RuntimeError(output)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    tls.socket = context.wrap_socket(tls.socket, server_side=True)
    for service in (http, tls):
        threading.Thread(target=service.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{http.server_port}"
    for filename, expected in (("collection.json", 200), ("failing-collection.json", 201)):
        (path / filename).write_text(json.dumps({"info": {"name": "fixture", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"}, "item": [{"name": "fixture-status", "request": {"method": "GET", "url": url}, "event": [{"listen": "test", "script": {"type": "text/javascript", "exec": [f'pm.test("fixture-status", function () {{ pm.response.to.have.status({expected}); }});']}}]}]}))
    return (path, url, tls.server_port, http.server_port), (http, tls)


async def main(args):
    verification = Verification()
    services = ()
    with tempfile.TemporaryDirectory(prefix="kali-fixtures-") as location:
        try:
            fixtures = None
            if not args.protocol_only:
                verification.inventory()
                fixtures, services = create_fixtures(Path(location))
            await verification.stdio(fixtures)
            await verification.http()
            await verification.http(cap=1024)
        except Exception as exc:
            verification.record("verification-harness", False, str(exc))
        finally:
            for service in services:
                service.shutdown()
                service.server_close()
    passed = bool(verification.checks) and all(c["passed"] for c in verification.checks)
    report = {
        "mode": "protocol-only" if args.protocol_only else "container",
        "passed": passed,
        "checks": verification.checks,
        "functional_tools": sorted(verification.functional),
        "installation_startup_only": sorted(set(TOOL_DISPATCH) - verification.functional) if not args.protocol_only else [],
        "limits": ["Windows execution/AD credentials, physical wireless interfaces, GPU acceleration, real memory images and external OSINT data are not verified by local fixtures.", "Other tools listed under installation_startup_only have executable/startup coverage, not full workflow coverage."],
        "installed_versions": {p.name: p.read_text() for p in Path("/opt/kali-versions").glob("*.txt")},
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(f"{'PASS' if passed else 'FAIL'} — report: {args.report}")
    return 0 if passed else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol-only", action="store_true")
    parser.add_argument("--report", type=Path, default=Path("test-results/verification.json"))
    sys.exit(asyncio.run(main(parser.parse_args())))
