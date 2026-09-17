import asyncio
import json
import sys
from mcp import ClientSession
from mcp.client.stdio import stdio_client, StdioServerParameters


async def test_server():
    server_params = StdioServerParameters(
        command=sys.executable,  # use same venv python
        args=["-m", "kali_mcp.server"],
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()

            print(f"=== Server connected: {len(tools.tools)} tools listed ===\n")

            # Count by category
            categories = {}
            for t in tools.tools:
                cat = t.name.split("_")[0] if "_" in t.name else "other"
                categories.setdefault(cat, []).append(t.name)

            for cat, names in sorted(categories.items()):
                print(f"  {cat}: {', '.join(names)}")

            print()

            # Test a few tool calls
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

            print(f"\n=== Results: {passed} passed, {failed} failed, {skipped} skipped ===")
            return failed == 0


if __name__ == "__main__":
    asyncio.run(test_server())
