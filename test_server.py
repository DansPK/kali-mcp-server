import asyncio
import json
import sys
from mcp import ClientSession
from mcp.client.stdio import stdio_client, StdioServerParameters


async def test_no_auth():
    server_params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "kali_mcp.server"],
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()

            print(f"=== Server connected: {len(tools.tools)} tools listed ===\n")

            tests = [
                ("searchsploit", {"query": "eternalblue"}),
                ("whatweb", {"target": "example.com"}),
                ("msf_search", {"query": "smb"}),
                ("list_payloads", {"platform": "windows", "keyword": "reverse_tcp"}),
                ("hash_identifier", {"hash_str": "5f4dcc3b5aa765d61d8327deb882cf99"}),
                ("nmap", {"target": "127.0.0.1", "ports": "22,80"}),
                ("tshark", {"iface": "lo", "count": 5}),
                ("cewl", {"url": "http://example.com", "depth": 1, "min_length": 4}),
            ]

            passed = 0
            failed = 0
            skipped = 0

            for name, args in tests:
                print(f"--- calling {name}({json.dumps(args)}) ---")
                try:
                    result = await session.call_tool(name, args)
                    text = result.content[0].text if result.content else ""
                    if result.is_error:
                        print(f"  ERROR: {text[:200]}")
                        failed += 1
                    elif "[error]" in text.lower() and "not found" in text.lower():
                        print(f"  SKIP (not installed): {text[:150]}")
                        skipped += 1
                    else:
                        preview = text[:200].replace("\n", " ")
                        print(f"  OK ({len(text)} chars): {preview}")
                        passed += 1
                except Exception as e:
                    print(f"  EXCEPTION: {e}")
                    failed += 1

            print(f"\n=== No-auth results: {passed} passed, {failed} failed, {skipped} skipped ===\n")
            return failed == 0


async def test_auth():
    print("=== Auth tests ===")
    server_params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "kali_mcp.server", "--auth-token", "test123"],
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # Without token — should be rejected
            try:
                await session.list_tools()
                print("  FAIL: no-token request was not rejected")
                return False
            except Exception as e:
                err = str(e)
                if "-32001" in err or "Unauthorized" in err:
                    print("  OK: no-token request rejected")
                else:
                    print(f"  UNEXPECTED: {err[:200]}")
                    return False

            # With token — should be accepted
            result = await session._dispatcher.send_raw_request(
                "tools/list",
                {"_meta": {"auth_token": "test123"}},
                {},
            )
            tools = result.get("tools", [])
            print(f"  OK: with-token request returned {len(tools)} tools")
            return True


async def main():
    no_auth_ok = await test_no_auth()
    auth_ok = await test_auth()
    if no_auth_ok and auth_ok:
        print("\n=== All tests passed ===")
    else:
        print(f"\n=== Test failures: no_auth={not no_auth_ok}, auth={not auth_ok} ===")


if __name__ == "__main__":
    asyncio.run(main())
