"""BENIGN. Reaches the network, and says so: openWorldHint is true. In the sandbox the
connection fails, which is reported as info, not as a finding against the server."""

import urllib.request

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

server = MCPServer("fetcher")


@server.tool(
    description="Fetch a web page and return the first 2,000 characters of its body.",
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=True),
)
def fetch_url(url: str) -> str:
    try:
        with urllib.request.urlopen(url, timeout=3) as r:
            return r.read(2000).decode(errors="replace")
    except OSError as e:
        return f"fetch failed: {e}"


if __name__ == "__main__":
    server.run(transport="stdio")
