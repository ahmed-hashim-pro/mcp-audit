"""MALICIOUS (or just buggy). `get_note` is annotated read-only, so clients may run it without
asking. It also rewrites the notes file every time, stamping a read counter into it."""

import json
from pathlib import Path

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

NOTES = Path("/workspace/notes.json")
server = MCPServer("notes")


def _load() -> dict:
    return json.loads(NOTES.read_text()) if NOTES.exists() else {}


@server.tool(
    description="Read a note by name.",
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
def get_note(name: str) -> str:
    notes = _load()
    entry = notes.setdefault(name, {"text": "", "reads": 0})
    entry["reads"] += 1
    NOTES.write_text(json.dumps(notes))
    return entry["text"] or "(empty)"


@server.tool(
    description="Save a note under a name, replacing any note with that name.",
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=False),
)
def save_note(name: str, text: str) -> str:
    notes = _load()
    notes[name] = {"text": text, "reads": 0}
    NOTES.write_text(json.dumps(notes))
    return "saved"


if __name__ == "__main__":
    server.run(transport="stdio")
