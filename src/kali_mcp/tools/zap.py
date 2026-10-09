import json
import os
import re
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from mcp.types import Tool
from ..tools.base import require_target, start_background, stop_background

# ---------------------------------------------------------------------------
# OWASP ZAP integration
#
# ZAP is driven through its REST API (no third-party client needed — stdlib
# only). A headless ZAP daemon is auto-started on demand via the sanitized
# start_background() gateway and reused across calls.
#
# Java note: ZAP 2.17 hangs on Java 25; we pin a 17/21 LTS JVM when available.
# ---------------------------------------------------------------------------

DEFAULT_HOST = os.environ.get("KALI_ZAP_HOST", "127.0.0.1")
DEFAULT_PORT = int(os.environ.get("KALI_ZAP_PORT", "8090"))

_ZAP_SCRIPTS = [
    "/usr/share/zaproxy/zap.sh",
    "/opt/zaproxy/zap.sh",
    "/usr/local/bin/zap.sh",
    "/usr/bin/zap.sh",
]

# Preferred LTS JVMs (ZAP 2.17 is unstable on Java 25).
_JAVA_HOMES = [
    "/usr/lib/jvm/java-21-openjdk-amd64",
    "/usr/lib/jvm/java-17-openjdk-amd64",
    "/usr/lib/jvm/java-21-openjdk",
    "/usr/lib/jvm/java-17-openjdk",
]

_daemon_proc = None
_daemon_addr = ("", 0)
_ajax_lock = threading.Lock()


def _zap_script() -> str:
    for path in _ZAP_SCRIPTS:
        if os.path.isfile(path):
            return path
    return ""


def _java_home() -> str:
    for path in _JAVA_HOMES:
        if os.path.isdir(path):
            return path
    # Fall back to a user-provided JAVA_HOME only if it is an LTS (17/21).
    env_home = os.environ.get("JAVA_HOME", "")
    if env_home and any(v in env_home for v in ("java-17", "java-21")):
        return env_home
    return ""


def _base(host: str, port: int) -> str:
    return f"http://{host}:{port}"


def _api(host: str, port: int, component: str, kind: str, name: str,
         params: dict | None = None, timeout: int = 30):
    """Call a ZAP REST endpoint and return the decoded JSON."""
    url = f"{_base(host, port)}/JSON/{component}/{kind}/{name}/"
    data = None
    if kind == "action":
        data = urllib.parse.urlencode(params or {}).encode()
    elif params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, data=data, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        result = json.loads(resp.read().decode("utf-8", "replace"))
    if isinstance(result, dict) and "code" in result and "message" in result:
        raise RuntimeError(f"ZAP API error: {result['code']}")
    return result


def _version(host: str, port: int) -> str | None:
    try:
        return _api(host, port, "core", "view", "version", timeout=5).get("version")
    except Exception:
        return None


def _ensure_daemon(host: str, port: int, timeout: int = 120) -> str | None:
    """Ensure a ZAP daemon is reachable, starting one if necessary.

    Returns None on success, or an error string.
    """
    global _daemon_proc, _daemon_addr

    if _version(host, port):
        return None

    script = _zap_script()
    if not script:
        return ("[error] OWASP ZAP not found. Install it (e.g. `apt install zaproxy`) "
                "or set KALI_ZAP_HOST/PORT to a running daemon.")

    env = os.environ.copy()
    java = _java_home()
    if java:
        env["JAVA_HOME"] = java
        env["PATH"] = f"{java}/bin:" + env.get("PATH", "")

    log_file = os.path.join(tempfile.gettempdir(), "kali-mcp-zap.log")
    command = [
        script, "-daemon",
        "-host", host,
        "-port", str(port),
        "-config", "api.disablekey=true",
        "-config", "start.checkForUpdates=false",
    ]
    try:
        _daemon_proc = start_background(command, env=env, log_file=log_file)
    except Exception as e:
        return f"[error] could not start ZAP daemon: {e}"
    _daemon_addr = (host, port)

    deadline = time.time() + timeout
    while time.time() < deadline:
        if _daemon_proc.poll() is not None:
            return (f"[error] ZAP daemon exited early (rc={_daemon_proc.returncode}); "
                    f"see {log_file}")
        if _version(host, port):
            return None
        time.sleep(2)

    return f"[error] ZAP daemon did not become ready within {timeout}s; see {log_file}"


def _poll_status(host: str, port: int, component: str, scan_id: str,
                 deadline: float, interval: float = 2.0) -> tuple[int, bool]:
    """Poll a scan's progress. Returns (percent, finished)."""
    last = 0
    while time.time() < deadline:
        try:
            last = int(_api(host, port, component, "view", "status",
                            {"scanId": scan_id}).get("status", "0"))
        except Exception:
            pass
        if last >= 100:
            return 100, True
        time.sleep(interval)
    return last, False


def _format_alerts(alerts: list, limit: int = 100) -> str:
    if not alerts:
        return "(no alerts)"
    lines = []
    for a in alerts[:limit]:
        line = f"[{a.get('risk', '?')}] {a.get('name', '?')} ({a.get('confidence', '?')}) — {a.get('url', '')}"
        detail = []
        if a.get("param"):
            detail.append(f"param={a['param']}")
        if a.get("evidence"):
            detail.append(f"evidence={a['evidence'][:120]}")
        if a.get("cweid") and a["cweid"] not in ("", "-1", "0"):
            detail.append(f"CWE-{a['cweid']}")
        if detail:
            line += "\n    " + "  ".join(detail)
        lines.append(line)
    extra = "" if len(alerts) <= limit else f"\n... and {len(alerts) - limit} more"
    return "\n".join(lines) + extra


def _fetch_alerts(host: str, port: int, base_url: str, risk: str = "",
                  limit: int = 100) -> list:
    params = {"start": "0", "count": str(max(limit, 500))}
    if base_url:
        params["baseurl"] = base_url
    data = _api(host, port, "core", "view", "alerts", params)
    alerts = data.get("alerts", [])
    if risk:
        wanted = risk.strip().lower()
        alerts = [a for a in alerts if str(a.get("risk", "")).lower() == wanted]
    return alerts


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

TOOLS = [
    Tool(
        name="zap_start",
        description=(
            "Start (or verify) a headless OWASP ZAP daemon used by all other zap_* tools. "
            "Normally you do not need to call this — every zap_* tool auto-starts the daemon. "
            "Java 17/21 is selected automatically (ZAP 2.17 is unstable on Java 25). "
            "Output: ZAP version and address once the daemon is ready."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": f"ZAP daemon bind address (default: {DEFAULT_HOST})"},
                "port": {"type": "integer", "description": f"ZAP daemon port (default: {DEFAULT_PORT})"},
            },
            "required": [],
        },
    ),
    Tool(
        name="zap_stop",
        description=(
            "Shut down the OWASP ZAP daemon started by this server. "
            "Use to free resources when finished scanning. Output: confirmation."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": f"ZAP daemon address (default: {DEFAULT_HOST})"},
                "port": {"type": "integer", "description": f"ZAP daemon port (default: {DEFAULT_PORT})"},
            },
            "required": [],
        },
    ),
    Tool(
        name="zap_status",
        description=(
            "Check whether the OWASP ZAP daemon is running and reachable, and report its version. "
            "Output: running/stopped status and ZAP version."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": f"ZAP daemon address (default: {DEFAULT_HOST})"},
                "port": {"type": "integer", "description": f"ZAP daemon port (default: {DEFAULT_PORT})"},
            },
            "required": [],
        },
    ),
    Tool(
        name="zap_spider",
        description=(
            "Crawl (spider) a web application with OWASP ZAP to enumerate URLs, forms, and endpoints. "
            "Use as the FIRST ZAP step to map the application before active scanning. "
            "For a complete scan in one call, use zap_scan. "
            "Output: number of URLs discovered and a sample of the results."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL to spider (e.g. http://192.168.1.10)"},
                "recurse": {"type": "boolean", "description": "Recurse into discovered URLs (default: true)"},
                "timeout": {"type": "integer", "description": "Max seconds to wait for the spider (default: 300)"},
                "host": {"type": "string", "description": f"ZAP daemon address (default: {DEFAULT_HOST})"},
                "port": {"type": "integer", "description": f"ZAP daemon port (default: {DEFAULT_PORT})"},
            },
            "required": ["url"],
        },
    ),
    Tool(
        name="zap_active_scan",
        description=(
            "Run an OWASP ZAP active scan against a target URL. Active scanning sends real attack "
            "payloads (SQLi, XSS, path traversal, etc.) and is intrusive — only use on systems you are "
            "authorized to test. Run zap_spider first to populate the site tree for better coverage. "
            "For spider + active scan + alert report in one call, use zap_scan. "
            "Output: scan progress and the alerts discovered."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL to actively scan (e.g. http://192.168.1.10)"},
                "recurse": {"type": "boolean", "description": "Scan URLs discovered under the target (default: true)"},
                "timeout": {"type": "integer", "description": "Max seconds to wait for the scan (default: 600)"},
                "host": {"type": "string", "description": f"ZAP daemon address (default: {DEFAULT_HOST})"},
                "port": {"type": "integer", "description": f"ZAP daemon port (default: {DEFAULT_PORT})"},
            },
            "required": ["url"],
        },
    ),
    Tool(
        name="zap_scan",
        description=(
            "Full OWASP ZAP web application scan in one call: spider, wait for passive scanning, "
            "active scan, then return the findings. Intrusive — authorized targets only. "
            "This is the primary ZAP tool; use zap_spider/zap_active_scan for finer control. "
            "Output: discovered URLs, scan progress, and the alert list with risk levels."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL to scan (e.g. http://192.168.1.10)"},
                "recurse": {"type": "boolean", "description": "Recurse into discovered URLs (default: true)"},
                "timeout": {"type": "integer", "description": "Max seconds for the active scan phase (default: 900)"},
                "host": {"type": "string", "description": f"ZAP daemon address (default: {DEFAULT_HOST})"},
                "port": {"type": "integer", "description": f"ZAP daemon port (default: {DEFAULT_PORT})"},
            },
            "required": ["url"],
        },
    ),
    Tool(
        name="zap_alerts",
        description=(
            "List the security alerts (findings) OWASP ZAP has recorded, optionally filtered by "
            "target base URL and risk level. Use after a spider/active scan to review results. "
            "Output: alerts with risk, confidence, affected URL, parameter, and evidence."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "base_url": {"type": "string", "description": "Filter alerts to this target base URL (optional)"},
                "risk": {"type": "string", "description": "Filter by risk: High, Medium, Low, Informational (optional)"},
                "limit": {"type": "integer", "description": "Max alerts to display (default: 100)"},
                "host": {"type": "string", "description": f"ZAP daemon address (default: {DEFAULT_HOST})"},
                "port": {"type": "integer", "description": f"ZAP daemon port (default: {DEFAULT_PORT})"},
            },
            "required": [],
        },
    ),
    Tool(
        name="zap_report",
        description=(
            "Generate an OWASP ZAP report for the findings collected so far and save it to disk. "
            "Working templates: traditional-html, traditional-md, modern, high-level-report, sarif-json. "
            "(ZAP 2.17's traditional-json/xml templates are broken when alerts exist.) "
            "Output: path to the generated report file and a summary of the alert count."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "template": {"type": "string", "description": "Report template (default: traditional-html)"},
                "report_dir": {"type": "string", "description": "Directory to write the report (default: /tmp)"},
                "file_name": {"type": "string", "description": "Report file name without extension (default: zap-report)"},
                "host": {"type": "string", "description": f"ZAP daemon address (default: {DEFAULT_HOST})"},
                "port": {"type": "integer", "description": f"ZAP daemon port (default: {DEFAULT_PORT})"},
            },
            "required": [],
        },
    ),
]

_DAEMON_PROPERTIES = {
    "host": {"type": "string", "description": f"ZAP daemon address (default: {DEFAULT_HOST})"},
    "port": {"type": "integer", "description": f"ZAP daemon port (default: {DEFAULT_PORT})"},
}
_CONTEXT_ID_SCHEMA = {"type": "string", "description": "Optional context ID returned by zap_context"}
_USER_ID_SCHEMA = {"type": "string", "description": "Optional user ID from zap_context; requires context_id"}
for _tool in TOOLS:
    if _tool.name in ("zap_spider", "zap_active_scan", "zap_scan"):
        _tool.inputSchema["properties"].update(context_id=_CONTEXT_ID_SCHEMA, user_id=_USER_ID_SCHEMA)

TOOLS.extend([
    Tool(name="zap_context", description="Create a scoped ZAP context with optional form, JSON, HTTP, browser, or script authentication and an enabled user. Returns context/user IDs for authenticated scans. Authentication configuration values use the installed ZAP method's parameter names.", inputSchema={
        "type": "object", "properties": {
            "name": {"type": "string", "description": "Unique context name"},
            "url": {"type": "string", "description": "HTTP(S) base URL whose subtree is in scope; no query or fragment"},
            "exclude": {"type": "array", "items": {"type": "string"}, "description": "URL regexes to exclude, e.g. logout or destructive routes"},
            "authentication_method": {"type": "string", "description": "ZAP method name, e.g. formBasedAuthentication, jsonBasedAuthentication, browserBasedAuthentication, or httpAuthentication; omitted leaves manual authentication"},
            "authentication_params": {"type": "object", "additionalProperties": {"type": "string"}, "description": "Method parameters such as loginUrl and loginRequestData; values are URL-encoded by the wrapper"},
            "user_name": {"type": "string", "description": "Optional name for a new context user"},
            "credentials": {"type": "object", "additionalProperties": {"type": "string"}, "description": "Credential parameters, typically username and password; requires user_name and authentication_method"},
            "logged_in_regex": {"type": "string", "description": "Response regex indicating a successful login"},
            "logged_out_regex": {"type": "string", "description": "Response regex indicating an unauthenticated session"},
            **_DAEMON_PROPERTIES,
        }, "required": ["name", "url"]}),
    Tool(name="zap_openapi_import", description="Import an OpenAPI definition from a URL or local file into ZAP. Optionally override the API base URL and import in a context/as a user. Returns import results and discovered API URLs.", inputSchema={
        "type": "object", "properties": {
            "schema": {"type": "string", "description": "OpenAPI URL or existing file accessible to the ZAP daemon"},
            "base_url": {"type": "string", "description": "Optional HTTP(S) API base URL override"},
            "context_id": _CONTEXT_ID_SCHEMA, "user_id": _USER_ID_SCHEMA,
            "max_messages": {"type": "integer", "minimum": 1, "maximum": 10000, "description": "Maximum import requests (default: 1000)"},
            **_DAEMON_PROPERTIES,
        }, "required": ["schema"]}),
    Tool(name="zap_ajax_spider", description="Crawl JavaScript-rendered applications using ZAP's AJAX spider and headless Chromium. Optional context/user names select authenticated crawling. Only one AJAX crawl runs per daemon; a timeout stops the crawl and returns an error with partial results.", inputSchema={
        "type": "object", "properties": {
            "url": {"type": "string", "description": "HTTP(S) start URL"},
            "context_name": {"type": "string", "description": "Optional context name from zap_context"},
            "user_name": {"type": "string", "description": "Optional context user name; requires context_name"},
            "max_depth": {"type": "integer", "minimum": 1, "maximum": 20, "description": "Maximum crawl depth (default: 5)"},
            "timeout": {"type": "integer", "minimum": 1, "maximum": 600, "description": "Maximum crawl wait in seconds (default: 300)"},
            **_DAEMON_PROPERTIES,
        }, "required": ["url"]}),
])


def _validate_scope(context_id: str, user_id: str) -> str | None:
    if user_id and not context_id:
        return "[error] user_id requires context_id"
    return None


def _context_name(host: str, port: int, context_id: str) -> str:
    names = _api(host, port, "context", "view", "contextList")["contextList"]
    for name in names:
        context = _api(host, port, "context", "view", "context", {"contextName": name})["context"]
        if str(context["id"]) == str(context_id):
            return name
    raise ValueError("context_id does not identify an existing context")


def _start_scan(host: str, port: int, component: str, url: str, recurse: bool,
                context_id: str, user_id: str) -> str:
    error = _validate_scope(context_id, user_id)
    if error:
        raise ValueError(error.removeprefix("[error] "))
    params = {"url": url, "recurse": str(recurse).lower()}
    if user_id:
        params.update(contextId=context_id, userId=user_id)
        action = "scanAsUser"
    else:
        action = "scan"
        if context_id:
            if component == "spider":
                params["contextName"] = _context_name(host, port, context_id)
            else:
                params["contextId"] = context_id
    result = _api(host, port, component, "action", action, params)
    scan_id = result.get("scan", result.get(action))
    if scan_id is None:
        raise RuntimeError("ZAP did not return a scan ID")
    return str(scan_id)


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

def zap_start(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> str:
    err = _ensure_daemon(host, port)
    if err:
        return err
    return f"OWASP ZAP {_version(host, port)} running at {_base(host, port)}"


def zap_stop(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> str:
    global _daemon_proc

    if not _version(host, port):
        return f"[info] no ZAP daemon reachable at {_base(host, port)}"

    try:
        _api(host, port, "core", "action", "shutdown")
    except Exception:
        # ZAP often drops the connection as it shuts down; that is expected.
        pass
    try:
        stop_background(_daemon_proc)
    except Exception:
        pass
    _daemon_proc = None

    deadline = time.time() + 15
    while time.time() < deadline:
        if not _version(host, port):
            return f"ZAP daemon at {_base(host, port)} stopped"
        time.sleep(1)
    return f"ZAP daemon at {_base(host, port)} shut down (still finishing)"


def zap_status(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> str:
    version = _version(host, port)
    if not version:
        return f"ZAP daemon: NOT running at {_base(host, port)}"
    return f"ZAP daemon: running at {_base(host, port)} (version {version})"


def zap_spider(url: str, recurse: bool = True, timeout: int = 300,
               host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
               context_id: str = "", user_id: str = "") -> str:
    err = require_target(url) or _validate_scope(context_id, user_id)
    if err:
        return err
    err = _ensure_daemon(host, port)
    if err:
        return err

    try:
        scan_id = _start_scan(host, port, "spider", url, recurse, context_id, user_id)
    except Exception as e:
        return f"[error] could not start spider: {e}"

    pct, done = _poll_status(host, port, "spider", scan_id, time.time() + timeout)
    try:
        results = _api(host, port, "spider", "view", "results",
                       {"scanId": scan_id}).get("results", [])
    except Exception:
        results = []

    status = "completed" if done else f"still running ({pct}%)"
    head = f"ZAP spider {status}: {len(results)} URL(s) discovered for {url}"
    sample = "\n".join(f"  {u}" for u in results[:50])
    if len(results) > 50:
        sample += f"\n  ... and {len(results) - 50} more"
    return f"{head}\n{sample}" if sample else head


def zap_active_scan(url: str, recurse: bool = True, timeout: int = 600,
                    host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
                    context_id: str = "", user_id: str = "") -> str:
    err = require_target(url) or _validate_scope(context_id, user_id)
    if err:
        return err
    err = _ensure_daemon(host, port)
    if err:
        return err

    try:
        scan_id = _start_scan(host, port, "ascan", url, recurse, context_id, user_id)
    except Exception as e:
        return f"[error] could not start active scan: {e}"

    pct, done = _poll_status(host, port, "ascan", scan_id, time.time() + timeout)
    try:
        alerts = _fetch_alerts(host, port, url)
    except Exception as e:
        return f"[error] active scan started (id={scan_id}) but could not fetch alerts: {e}"

    status = "completed" if done else f"still running after {timeout}s ({pct}%)"
    return (f"ZAP active scan {status}: {len(alerts)} alert(s) for {url}\n"
            f"{_format_alerts(alerts)}")


def zap_scan(url: str, recurse: bool = True, timeout: int = 900,
             host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
             context_id: str = "", user_id: str = "") -> str:
    err = require_target(url) or _validate_scope(context_id, user_id)
    if err:
        return err
    err = _ensure_daemon(host, port)
    if err:
        return err

    parts = []

    # 1. Spider
    try:
        spider_id = _start_scan(host, port, "spider", url, recurse, context_id, user_id)
        _poll_status(host, port, "spider", spider_id, time.time() + min(timeout, 300))
        urls = _api(host, port, "spider", "view", "results",
                    {"scanId": spider_id}).get("results", [])
        parts.append(f"Spider: {len(urls)} URL(s) discovered")
    except Exception as e:
        return f"[error] spider could not start: {e}"

    # 2. Wait for passive scan queue to drain (bounded).
    pdeadline = time.time() + 60
    while time.time() < pdeadline:
        try:
            remaining = int(_api(host, port, "pscan", "view",
                                 "recordsToScan").get("recordsToScan", "0"))
        except Exception:
            break
        if remaining == 0:
            break
        time.sleep(2)

    # 3. Active scan
    try:
        ascan_id = _start_scan(host, port, "ascan", url, recurse, context_id, user_id)
        pct, done = _poll_status(host, port, "ascan", ascan_id, time.time() + timeout)
        parts.append(f"Active scan: {'completed' if done else f'still running ({pct}%)'}")
    except Exception as e:
        return "[error] " + "\n".join(parts) + f"\nActive scan could not start: {e}"

    # 4. Alerts
    try:
        alerts = _fetch_alerts(host, port, url)
    except Exception as e:
        return "\n".join(parts) + f"\n[error] could not fetch alerts: {e}"

    return ("\n".join(parts) + f"\n\nAlerts ({len(alerts)}):\n{_format_alerts(alerts)}")


def zap_alerts(base_url: str = "", risk: str = "", limit: int = 100,
               host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> str:
    err = _ensure_daemon(host, port)
    if err:
        return err
    try:
        alerts = _fetch_alerts(host, port, base_url, risk, limit)
    except Exception as e:
        return f"[error] could not fetch alerts: {e}"
    scope = f" for {base_url}" if base_url else ""
    rscope = f" (risk={risk})" if risk else ""
    return f"ZAP alerts{scope}{rscope}: {len(alerts)}\n{_format_alerts(alerts, limit)}"


def zap_report(template: str = "traditional-html", report_dir: str = "/tmp",
               file_name: str = "zap-report",
               host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> str:
    err = _ensure_daemon(host, port)
    if err:
        return err
    try:
        os.makedirs(report_dir, exist_ok=True)
    except Exception as e:
        return f"[error] report_dir '{report_dir}' is not usable: {e}"

    try:
        n = _api(host, port, "core", "view", "numberOfAlerts").get("numberOfAlerts", "0")
        resp = _api(host, port, "reports", "action", "generate", {
            "title": "Kali MCP ZAP Report",
            "template": template,
            "reportDir": report_dir,
            "reportFileName": file_name,
            "overwrite": "true",
        })
    except urllib.error.HTTPError as e:
        return (f"[error] report generation failed (HTTP {e.code}) for template '{template}'. "
                f"This template is unsupported/broken in this ZAP build; try traditional-html, "
                f"traditional-md, modern, high-level-report or sarif-json.")
    except Exception as e:
        return f"[error] could not generate report: {e}"

    if "generate" not in resp:
        return (f"[error] report generation failed ({resp.get('code', 'unknown')}). "
                f"The '{template}' template may be unsupported in this ZAP build; "
                f"try traditional-html, traditional-md, modern, high-level-report or sarif-json.")

    path = resp["generate"]
    # Some templates return the path without the file extension; resolve it.
    if not os.path.isfile(path):
        import glob
        matches = glob.glob(path + ".*")
        if matches:
            path = matches[0]
    return f"ZAP report written to {path} ({n} alert(s), template={template})"


def zap_context(name: str, url: str, exclude: list[str] | None = None,
                authentication_method: str = "", authentication_params: dict | None = None,
                user_name: str = "", credentials: dict | None = None,
                logged_in_regex: str = "", logged_out_regex: str = "",
                host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> str:
    parsed = urllib.parse.urlsplit(url)
    if not name.strip() or parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.query or parsed.fragment:
        return "[error] name and an HTTP(S) base URL without query/fragment are required"
    if credentials and (not user_name or not authentication_method):
        return "[error] credentials require user_name and authentication_method"
    if authentication_params and not authentication_method:
        return "[error] authentication_params require authentication_method"
    error = _ensure_daemon(host, port)
    if error:
        return error
    created = False
    try:
        if name in _api(host, port, "context", "view", "contextList")["contextList"]:
            return "[error] context name already exists; use a unique name"
        if authentication_method:
            supported = _api(host, port, "authentication", "view", "getSupportedAuthenticationMethods")["supportedMethods"]
            if authentication_method not in supported:
                return "[error] unsupported authentication method; supported: " + ", ".join(supported)
        context_id = str(_api(host, port, "context", "action", "newContext", {"contextName": name})["contextId"])
        created = True
        scope = re.escape(url.rstrip("/")) + r"(?:/.*)?"
        _api(host, port, "context", "action", "includeInContext", {"contextName": name, "regex": scope})
        for pattern in exclude or []:
            _api(host, port, "context", "action", "excludeFromContext", {"contextName": name, "regex": pattern})
        _api(host, port, "context", "action", "setContextInScope", {"contextName": name, "booleanInScope": "true"})
        if authentication_method:
            _api(host, port, "authentication", "action", "setAuthenticationMethod", {
                "contextId": context_id, "authMethodName": authentication_method,
                "authMethodConfigParams": urllib.parse.urlencode(authentication_params or {}),
            })
        for indicator, action, parameter in (
            (logged_in_regex, "setLoggedInIndicator", "loggedInIndicatorRegex"),
            (logged_out_regex, "setLoggedOutIndicator", "loggedOutIndicatorRegex"),
        ):
            if indicator:
                _api(host, port, "authentication", "action", action, {"contextId": context_id, parameter: indicator})
        user_id = ""
        if user_name:
            user_id = str(_api(host, port, "users", "action", "newUser", {"contextId": context_id, "name": user_name})["userId"])
            if credentials:
                _api(host, port, "users", "action", "setAuthenticationCredentials", {
                    "contextId": context_id, "userId": user_id,
                    "authCredentialsConfigParams": urllib.parse.urlencode(credentials),
                })
            _api(host, port, "users", "action", "setUserEnabled", {"contextId": context_id, "userId": user_id, "enabled": "true"})
        return json.dumps({"context_id": context_id, "context_name": name, "user_id": user_id,
                           "user_name": user_name, "scope": scope, "authentication_method": authentication_method or "manualAuthentication"})
    except Exception as exc:
        if created:
            try:
                _api(host, port, "context", "action", "removeContext", {"contextName": name})
            except Exception:
                pass
        return f"[error] could not configure context: {exc}"


def zap_openapi_import(schema: str, base_url: str = "", context_id: str = "", user_id: str = "",
                       max_messages: int = 1000, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> str:
    error = require_target(schema) or _validate_scope(context_id, user_id)
    if error:
        return error
    if not 1 <= max_messages <= 10000:
        return "[error] max_messages must be 1–10000"
    if base_url and not base_url.startswith(("http://", "https://")):
        return "[error] base_url must be an HTTP(S) URL"
    remote = schema.startswith(("http://", "https://"))
    if not remote and not os.path.isfile(schema):
        return "[error] schema must be an HTTP(S) URL or existing local file"
    error = _ensure_daemon(host, port)
    if error:
        return error
    params = {"url" if remote else "file": schema if remote else os.path.abspath(schema), "maxMessages": str(max_messages)}
    if base_url:
        params["hostOverride" if remote else "target"] = base_url
    if context_id:
        params["contextId"] = context_id
    if user_id:
        params["userId"] = user_id
    try:
        result = _api(host, port, "openapi", "action", "importUrl" if remote else "importFile", params, timeout=120)
        urls = _api(host, port, "core", "view", "urls", {"baseurl": base_url} if base_url else {})["urls"]
        return json.dumps({"import": result, "urls": urls[:500], "url_count": len(urls)})
    except Exception as exc:
        return f"[error] could not import OpenAPI definition: {exc}"


def zap_ajax_spider(url: str, context_name: str = "", user_name: str = "", max_depth: int = 5,
                    timeout: int = 300, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> str:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return "[error] url must be an HTTP(S) URL"
    if user_name and not context_name:
        return "[error] user_name requires context_name"
    if not 1 <= max_depth <= 20 or not 1 <= timeout <= 600:
        return "[error] max_depth must be 1–20 and timeout must be 1–600 seconds"
    error = _ensure_daemon(host, port)
    if error:
        return error
    if not _ajax_lock.acquire(blocking=False):
        return "[error] an AJAX crawl is already in progress"
    started = False
    try:
        if _api(host, port, "ajaxSpider", "view", "status")["status"] == "running":
            return "[error] this ZAP daemon already has an AJAX crawl running"
        local_daemon = host in ("127.0.0.1", "localhost")
        if local_daemon and os.path.isfile("/usr/bin/chromium"):
            _api(host, port, "selenium", "action", "setOptionChromeBinaryPath", {"String": "/usr/bin/chromium"})
        if local_daemon and os.path.isfile("/usr/bin/chromedriver"):
            _api(host, port, "selenium", "action", "setOptionChromeDriverPath", {"String": "/usr/bin/chromedriver"})
        arguments = _api(host, port, "selenium", "view", "getBrowserArguments", {"browser": "chrome"}).get("getBrowserArguments", [])
        existing = {entry.get("argument") for entry in arguments}
        required = ["--disable-dev-shm-usage"]
        if local_daemon and hasattr(os, "geteuid") and os.geteuid() == 0:
            required.append("--no-sandbox")
        for argument in required:
            action = "setBrowserArgumentEnabled" if argument in existing else "addBrowserArgument"
            _api(host, port, "selenium", "action", action, {"browser": "chrome", "argument": argument, "enabled": "true"})
        _api(host, port, "ajaxSpider", "action", "setOptionBrowserId", {"String": "chrome-headless"})
        _api(host, port, "ajaxSpider", "action", "setOptionMaxCrawlDepth", {"Integer": str(max_depth)})
        _api(host, port, "ajaxSpider", "action", "setOptionMaxDuration", {"Integer": str((timeout + 59) // 60)})
        params = {"url": url, "subtreeOnly": "true"}
        if context_name:
            params["contextName"] = context_name
        if user_name:
            params["userName"] = user_name
        _api(host, port, "ajaxSpider", "action", "scanAsUser" if user_name else "scan", params)
        started = True
        deadline = time.monotonic() + timeout
        done = False
        while time.monotonic() < deadline:
            if _api(host, port, "ajaxSpider", "view", "status")["status"] == "stopped":
                done = True
                break
            time.sleep(min(2, max(0, deadline - time.monotonic())))
        if not done:
            _api(host, port, "ajaxSpider", "action", "stop")
        messages = _api(host, port, "ajaxSpider", "view", "results", {"start": "0", "count": "500"}).get("results", [])
        # Browser background traffic is also recorded by ZAP. Return only the
        # target subtree and do not expose session headers or response bodies.
        results = []
        seen = set()
        for message in messages:
            request = message.get("requestHeader", "").splitlines()
            if not request:
                continue
            fields = request[0].split(" ", 2)
            if len(fields) < 2:
                continue
            endpoint = urllib.parse.urljoin(url, fields[1])
            candidate = urllib.parse.urlsplit(endpoint)
            root = parsed.path.rstrip("/")
            if (candidate.scheme, candidate.netloc) != (parsed.scheme, parsed.netloc):
                continue
            if root and candidate.path != root and not candidate.path.startswith(root + "/"):
                continue
            key = (fields[0], endpoint)
            if key in seen:
                continue
            seen.add(key)
            response = message.get("responseHeader", "").splitlines()
            status = response[0].split(" ", 2)[1] if response and len(response[0].split(" ", 2)) > 1 else ""
            results.append({"method": fields[0], "url": endpoint, "status_code": status})
        report = json.dumps({"completed": done, "results": results})
        if done and not results:
            return f"[error] AJAX crawl finished without target requests; check browser configuration\n{report}"
        return report if done else f"[error] AJAX spider timed out after {timeout}s; stopped crawl\n{report}"
    except Exception as exc:
        if started:
            try:
                _api(host, port, "ajaxSpider", "action", "stop")
            except Exception:
                pass
        return f"[error] AJAX spider failed: {exc}"
    finally:
        _ajax_lock.release()


DISPATCH = {
    "zap_context": lambda **kw: zap_context(**kw),
    "zap_openapi_import": lambda **kw: zap_openapi_import(**kw),
    "zap_ajax_spider": lambda **kw: zap_ajax_spider(**kw),
    "zap_start": lambda **kw: zap_start(**kw),
    "zap_stop": lambda **kw: zap_stop(**kw),
    "zap_status": lambda **kw: zap_status(**kw),
    "zap_spider": lambda **kw: zap_spider(**kw),
    "zap_active_scan": lambda **kw: zap_active_scan(**kw),
    "zap_scan": lambda **kw: zap_scan(**kw),
    "zap_alerts": lambda **kw: zap_alerts(**kw),
    "zap_report": lambda **kw: zap_report(**kw),
}
