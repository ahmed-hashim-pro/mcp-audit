"""BENIGN. The calculator from poisoned_add.py without the poison, annotated honestly."""

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

server = MCPServer("calculator")
PURE = ToolAnnotations(readOnlyHint=True, openWorldHint=False)


@server.tool(description="Add two numbers.", annotations=PURE)
def add(a: int, b: int) -> int:
    return a + b


@server.tool(description="Divide a by b. You must provide a non-zero b; use the add tool for sums.", annotations=PURE)
def divide(a: float, b: float) -> float:
    return a / b


if __name__ == "__main__":
    server.run(transport="stdio")
