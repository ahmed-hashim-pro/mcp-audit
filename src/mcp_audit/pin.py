"""A lockfile of tool definitions, so a changed description fails CI instead of reaching the model.

Each tool is hashed over what the model and the client act on: name, title, description,
input and output schema, and annotations. Prompts are hashed the same way. The lockfile
also keeps the description itself, so a failure can show what changed, not just that
something did.
"""

from __future__ import annotations

import difflib
import hashlib
import json
from pathlib import Path
from typing import Any

from .model import Snapshot

VERSION = 1
_TOOL_KEYS = ("name", "title", "description", "inputSchema", "outputSchema", "annotations")
_PROMPT_KEYS = ("name", "title", "description", "arguments")


def digest(item: dict[str, Any], keys: tuple[str, ...]) -> str:
    canon = json.dumps({k: item.get(k) for k in keys}, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canon.encode()).hexdigest()


def entry(snap: Snapshot) -> dict[str, Any]:
    return {
        "server": {k: snap.server.get(k) for k in ("name", "version") if snap.server.get(k) is not None},
        "tools": {
            t["name"]: {"hash": digest(t, _TOOL_KEYS), "description": t.get("description", "")}
            for t in sorted(snap.tools, key=lambda t: t["name"])
        },
        "prompts": {
            p["name"]: {"hash": digest(p, _PROMPT_KEYS), "description": p.get("description", "")}
            for p in sorted(snap.prompts, key=lambda p: p["name"])
        },
    }


def load(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"version": VERSION, "servers": {}}
    data: dict[str, Any] = json.loads(path.read_text())
    if data.get("version") != VERSION:
        raise ValueError(f"{path}: unsupported lockfile version {data.get('version')!r}")
    return data


def save(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


def compare(locked: dict[str, Any], current: dict[str, Any]) -> list[str]:
    """Human-readable differences; empty when nothing the model sees has changed."""
    out: list[str] = []
    for kind in ("tools", "prompts"):
        old, new = locked.get(kind, {}), current.get(kind, {})
        noun = kind[:-1]
        for name in sorted(set(old) - set(new)):
            out.append(f"{noun} {name}: removed")
        for name in sorted(set(new) - set(old)):
            out.append(f"{noun} {name}: added, not in the lockfile")
        for name in sorted(set(old) & set(new)):
            if old[name]["hash"] != new[name]["hash"]:
                a, b = old[name].get("description", ""), new[name].get("description", "")
                if a != b:
                    lines = difflib.unified_diff(a.splitlines(), b.splitlines(), "locked", "now", lineterm="", n=1)
                    body = "\n".join("    " + line for line in list(lines)[2:])
                    out.append(f"{noun} {name}: description changed\n{body}")
                else:
                    out.append(f"{noun} {name}: schema or annotations changed")
    return out
