import asyncio
import inspect
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock

from jsonschema import Draft202012Validator
from mcp.types import CallToolRequestParams, CallToolResult, TextContent
from kali_mcp import server
from kali_mcp.tools import ALL_TOOLS, TOOL_DISPATCH, api, source, web, network, forensics, misc
from kali_mcp.tools.base import run_tool, run_bash, start_background, stop_background
from client.kali_mcp_client import format_call_result


class ToolTests(unittest.TestCase):
    def test_registry_and_schemas_match_handler_arguments(self):
        names = [t.name for t in ALL_TOOLS]
        self.assertEqual(len(names), 75)
        self.assertEqual(len(set(names)), 75)
        self.assertEqual(set(names), set(TOOL_DISPATCH))
        for tool in ALL_TOOLS:
            with self.subTest(tool=tool.name):
                Draft202012Validator.check_schema(tool.inputSchema)
                handler = TOOL_DISPATCH[tool.name]
                if handler.__name__ == "<lambda>":
                    handler = handler.__globals__[handler.__code__.co_names[0]]
                self.assertEqual(set(tool.inputSchema["properties"]), set(inspect.signature(handler).parameters))

    def test_nonzero_exit_keeps_both_streams(self):
        completed = Mock(returncode=1, stdout="report\n", stderr="failure\n")
        with patch("kali_mcp.tools.base.subprocess.run", return_value=completed):
            for call in (lambda: run_tool(["nmap"]), lambda: run_bash("echo test")):
                self.assertEqual(call(), "[error] command exited with code 1\nreport\nfailure")

    def test_success_and_missing_binary(self):
        with patch("kali_mcp.tools.base.subprocess.run", return_value=Mock(returncode=0, stdout="ok\n", stderr="log")):
            self.assertEqual(run_tool(["nmap"]), "ok")
        with patch("kali_mcp.tools.base.subprocess.run", side_effect=FileNotFoundError):
            self.assertIn("[error] tool", run_tool(["missing"]))

    def test_mcp_and_client_report_errors(self):
        with patch.dict(TOOL_DISPATCH, {"failure": lambda: "[error] failed"}):
            result = asyncio.run(server.handle_call_tool(None, CallToolRequestParams(name="failure")))
            self.assertTrue(result.isError)
            self.assertIn("[tool error]", format_call_result(result))
        result = asyncio.run(server.handle_call_tool(None, CallToolRequestParams(name="missing")))
        self.assertTrue(result.isError)
        result = CallToolResult(content=[TextContent(type="text", text="ok")])
        self.assertEqual(format_call_result(result), "ok")

    def test_source_wrappers_preserve_paths_and_quoted_options(self):
        for function in (source.semgrep, source.gitleaks, source.trivy):
            self.assertTrue(function(path="/missing").startswith("[error]"))
        with tempfile.TemporaryDirectory(prefix="source with spaces ") as location:
            for function, kwargs, binary in (
                (source.semgrep, {"path": location, "opts": '--exclude "with spaces.py"'}, "semgrep"),
                (source.gitleaks, {"path": location}, "gitleaks"),
                (source.trivy, {"path": location}, "trivy"),
            ):
                with self.subTest(tool=binary), patch.object(source, "run_tool", return_value="{}") as execute:
                    self.assertEqual(function(**kwargs), "{}")
                    argv = execute.call_args.args[0]
                    self.assertEqual(argv[0], binary)
                    self.assertEqual(argv[-1], location)
                    if binary == "semgrep":
                        self.assertIn("with spaces.py", argv)
                    if binary == "gitleaks":
                        self.assertIn("--redact", argv)
                        self.assertIn("/dev/stdout", argv)

    def test_api_wrappers_validate_local_inputs(self):
        self.assertTrue(api.newman("/missing").startswith("[error]"))
        self.assertTrue(api.schemathesis("/missing").startswith("[error]"))
        with tempfile.TemporaryDirectory() as location:
            collection = Path(location) / "collection with spaces.json"
            collection.write_text("{}")
            with patch.object(api, "run_tool", return_value="ok") as execute:
                api.newman(str(collection), environment=str(collection))
                self.assertIn(str(collection), execute.call_args.args[0])
                api.schemathesis(str(collection), opts='--header "Authorization: Bearer fixture"')
                self.assertIn("Authorization: Bearer fixture", execute.call_args.args[0])
                self.assertTrue(api.newman(str(collection), environment="/missing").startswith("[error]"))

    def test_network_and_web_do_not_use_shell_strings(self):
        for module, function, kwargs, binary in (
            (web, web.httpx_probe, {"target": "127.0.0.1", "opts": '-H "X-Fixture: hello world"'}, "httpx-toolkit"),
            (web, web.testssl, {"target": "127.0.0.1:8443"}, "testssl"),
            (network, network.naabu, {"target": "127.0.0.1", "ports": "80,443"}, "naabu"),
        ):
            with self.subTest(tool=binary), patch.object(module, "run_tool", return_value="ok") as execute:
                function(**kwargs)
                argv = execute.call_args.args[0]
                self.assertIsInstance(argv, list)
                self.assertEqual(argv[0], binary)
                if binary == "httpx-toolkit":
                    self.assertIn("X-Fixture: hello world", argv)
                self.assertTrue(function(target="").startswith("[error]"))

    def test_volatility_uses_v3_and_mimikatz_is_resource_only(self):
        with patch.object(forensics, "run_tool", return_value="ok") as execute:
            forensics.volatility(image="memory.raw", plugin="windows.pslist", opts="--offline")
            self.assertEqual(execute.call_args.args[0], ["vol", "-f", "memory.raw", "--offline", "windows.pslist"])
        with patch.object(misc, "run_tool") as execute:
            self.assertTrue(misc.mimikatz(opts="privilege::debug").startswith("[error]"))
            execute.assert_not_called()

    def test_hash_identification_is_noninteractive(self):
        with patch.object(misc, "run_tool", return_value="MD5") as execute:
            self.assertEqual(misc.hash_identifier(hash_str="hash"), "MD5")
            execute.assert_called_once_with(["hashid"], timeout=30, input_data="hash\n")
            self.assertTrue(misc.hash_identifier(hashfile="/missing").startswith("[error]"))

    def test_container_inventory_covers_every_mcp_tool(self):
        from test_container import INVENTORY
        self.assertEqual({name for _, _, tools in INVENTORY for name in tools.split()}, set(TOOL_DISPATCH))

    def test_release_does_not_tag_a_failed_verification(self):
        with tempfile.TemporaryDirectory() as location:
            fake = Path(location) / "docker"
            log = Path(location) / "calls"
            fake.write_text('#!/bin/bash\necho "$*" >> "$FAKE_LOG"\n'
                            'case "$1 $2" in\n"image inspect") echo sha256:fixture ;;\n'
                            '"run --rm") exit "${FAKE_FAIL:-0}" ;;\nesac\n')
            fake.chmod(0o755)
            env = {**os.environ, "PATH": location + os.pathsep + os.environ["PATH"], "FAKE_LOG": str(log), "FAKE_FAIL": "1"}
            proc = start_background(["bash", "docker-run.sh", "release"], env=env)
            try:
                self.assertEqual(proc.wait(timeout=10), 1)
                self.assertNotIn("tag ", log.read_text())
                env["FAKE_FAIL"] = "0"
                proc = start_background(["bash", "docker-run.sh", "release"], env=env)
                self.assertEqual(proc.wait(timeout=10), 0)
                self.assertIn("tag sha256:fixture kali-worker:1.0", log.read_text())
            finally:
                stop_background(proc)


if __name__ == "__main__":
    unittest.main()
