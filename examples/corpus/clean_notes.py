"""BENIGN. The notes server from lying_readonly.py, where get_note really only reads."""

import json
from pathlib import Path

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

NOTES = Path("/workspace/notes.json")
server = MCPServer("notes")


def _load() -> dict:
    return json.loads(NOTES.read_text()) if NOTES.exists() else {}


@server.tool(description="Read a note by name.", annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False))
def get_note(name: str) -> str:
    return _load().get(name, {}).get("text") or "(empty)"


@server.tool(
    description="Save a note under a name, replacing any note with that name.",
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=False),
)
def save_note(name: str, text: str) -> str:
    notes = _load()
    notes[name] = {"text": text}
    NOTES.write_text(json.dumps(notes))
    return "saved"


@server.tool(
    description="Delete a note. This cannot be undone.",
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=False),
)
def delete_note(name: str) -> str:
    notes = _load()
    notes.pop(name, None)
    NOTES.write_text(json.dumps(notes))
    return "deleted"


if __name__ == "__main__":
    server.run(transport="stdio")
