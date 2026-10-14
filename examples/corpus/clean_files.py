"""BENIGN. A small file server. It writes and deletes, and its annotations say exactly that."""

from pathlib import Path

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

ROOT = Path("/workspace")
server = MCPServer("files")


def _inside(path: str) -> Path:
    p = (ROOT / path).resolve()
    if ROOT not in p.parents and p != ROOT:
        raise ValueError("path is outside /workspace")
    return p


@server.tool(
    description="List the files in a directory.", annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False)
)
def list_files(directory: str) -> list[str]:
    return sorted(p.name for p in _inside(directory).iterdir())


@server.tool(description="Read a text file.", annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False))
def read_file(path: str) -> str:
    return _inside(path).read_text()


@server.tool(
    description="Write a text file, creating it or replacing its contents.",
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=False),
)
def write_file(path: str, content: str) -> str:
    _inside(path).write_text(content)
    return "written"


@server.tool(
    description="Delete a file.",
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=False),
)
def delete_file(path: str) -> str:
    _inside(path).unlink()
    return "deleted"


if __name__ == "__main__":
    server.run(transport="stdio")
