"""Plausible arguments for a tool, made from its input schema.

The goal is to get past input validation so the tool does its real work inside the
sandbox. Paths point into /workspace, which the sandbox image seeds with a few files and
a git repository; nothing points at the planted credentials, so any read of those comes
from the server itself.
"""

from __future__ import annotations

import re
from typing import Any

WORKSPACE = "/workspace"

_BY_NAME: list[tuple[str, Any]] = [
    (r"^(?:repo|repository)(?:_?path|_?dir)?$", f"{WORKSPACE}/repo"),
    (r"(?:^|_)(?:dir|directory|folder|root|cwd|base_?path)$", WORKSPACE),
    (r"(?:^|_)(?:paths|files|filenames)$", [f"{WORKSPACE}/notes.txt"]),
    (r"(?:^|_)(?:path|file|filename|file_?path|source|src)$", f"{WORKSPACE}/notes.txt"),
    (r"(?:^|_)(?:dest|destination|target|new_?path|to)$", f"{WORKSPACE}/notes-copy.txt"),
    (r"(?:^|_)(?:url|uri|href|link|endpoint)$", "https://example.com/"),
    (r"(?:^|_)(?:email|mail)$", "probe@example.com"),
    (r"(?:^|_)(?:timezone|tz|time_?zone)$", "UTC"),
    (r"(?:^|_)(?:branch|ref|revision|rev)$", "main"),
    (r"(?:^|_)(?:pattern|glob)$", "*.txt"),
    (r"(?:^|_)(?:regex)$", "probe"),
    (r"(?:^|_)(?:content|contents|text|body|message|data|note|input|query|prompt|value)$", "mcp-audit probe"),
    (r"(?:^|_)(?:name|title|label|key|id)$", "mcp-audit-probe"),
]
_FORMAT = {
    "uri": "https://example.com/",
    "url": "https://example.com/",
    "email": "probe@example.com",
    "date-time": "2026-01-01T00:00:00Z",
    "date": "2026-01-01",
    "time": "00:00:00",
    "uuid": "00000000-0000-4000-8000-000000000000",
}


def _snake(name: str) -> str:
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).lower()


def value_for(name: str, schema: Any, depth: int = 0) -> Any:
    if not isinstance(schema, dict) or depth > 6:
        return "mcp-audit probe"
    for key in ("const",):
        if key in schema:
            return schema[key]
    if schema.get("enum"):
        return schema["enum"][0]
    if "default" in schema and schema["default"] is not None:
        return schema["default"]
    if schema.get("examples"):
        return schema["examples"][0]
    for key in ("anyOf", "oneOf"):
        options = [s for s in schema.get(key) or [] if isinstance(s, dict) and s.get("type") != "null"]
        if options:
            return value_for(name, options[0], depth + 1)
    if schema.get("allOf"):
        merged: dict[str, Any] = {}
        for s in schema["allOf"]:
            if isinstance(s, dict):
                merged.update(s)
        return value_for(name, merged, depth + 1)
    t = schema.get("type")
    if isinstance(t, list):
        t = next((x for x in t if x != "null"), "string")
    if t is None:
        t = "object" if "properties" in schema else "string"
    if t == "object":
        return arguments_for(schema, depth + 1)
    if t == "array":
        item = value_for(name, schema.get("items") or {}, depth + 1)
        n = max(1, int(schema.get("minItems") or 1))
        return [item] * n
    if t == "boolean":
        return False
    if t in ("integer", "number"):
        lo = schema.get("minimum", schema.get("exclusiveMinimum"))
        v = 1 if lo is None else lo + (1 if "exclusiveMinimum" in schema and "minimum" not in schema else 0)
        hi = schema.get("maximum")
        if hi is not None and v > hi:
            v = hi
        return int(v) if t == "integer" else v
    # string
    if schema.get("format") in _FORMAT:
        return _FORMAT[schema["format"]]
    snake = _snake(name)
    for rx, v in _BY_NAME:
        if re.search(rx, snake):
            if isinstance(v, list):
                return v[0]
            s = v
            break
    else:
        s = "mcp-audit probe"
    lo = schema.get("minLength")
    if lo is not None and len(s) < lo:
        s = s + "x" * (lo - len(s))
    hi = schema.get("maxLength")
    if hi is not None and len(s) > hi:
        s = s[:hi]
    return s


def arguments_for(schema: Any, depth: int = 0) -> dict[str, Any]:
    """Values for the required properties only: optional ones keep the server's defaults."""
    if not isinstance(schema, dict):
        return {}
    props = schema.get("properties") or {}
    required = set(schema.get("required") or [])
    out: dict[str, Any] = {}
    for name, sub in props.items():
        if name in required:
            out[name] = value_for(name, sub, depth)
    return out
