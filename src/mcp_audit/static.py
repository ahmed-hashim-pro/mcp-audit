"""Checks on what a server shows the model: names, descriptions, schemas and annotations.

Everything here works on a Snapshot, so it runs without calling a tool. The text rules
look for writing aimed at the model rather than at a developer reading the docs: orders to
ignore earlier instructions, to keep something from the user, to read credential files,
to smuggle data out through a parameter, or to change how other servers' tools are used.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterator
from typing import Any

from .model import Finding, Severity, Snapshot

# --- where text lives -------------------------------------------------------------------

_SCHEMA_TEXT_KEYS = ("description", "title", "default", "examples", "enum", "const")


def _schema_texts(schema: Any, path: str) -> Iterator[tuple[str, str]]:
    """Every string a schema shows the model, with a readable location."""
    if not isinstance(schema, dict):
        return
    for key in _SCHEMA_TEXT_KEYS:
        v = schema.get(key)
        for s in _strings(v):
            yield f"{path} {key}" if path else key, s
    for name, sub in (schema.get("properties") or {}).items():
        yield from _schema_texts(sub, f"input `{name}`" if not path else f"{path}.{name}")
    for key in ("items", "additionalProperties", "not"):
        if isinstance(schema.get(key), dict):
            yield from _schema_texts(schema[key], f"{path}[{key}]" if path else key)
    for key in ("anyOf", "oneOf", "allOf"):
        for i, sub in enumerate(schema.get(key) or []):
            yield from _schema_texts(sub, f"{path}{key}[{i}]")
    for key in ("$defs", "definitions"):
        for name, sub in (schema.get(key) or {}).items():
            yield from _schema_texts(sub, f"{key}.{name}")


def _strings(v: Any) -> Iterator[str]:
    if isinstance(v, str):
        yield v
    elif isinstance(v, list):
        for x in v:
            yield from _strings(x)
    elif isinstance(v, dict):
        for x in v.values():
            yield from _strings(x)


def texts(snap: Snapshot) -> Iterator[tuple[str, str]]:
    """(where, text) for every piece of text the server shows the model."""
    if snap.instructions:
        yield "server instructions", snap.instructions
    for key in ("title", "description"):
        if isinstance(snap.server.get(key), str):
            yield f"server {key}", snap.server[key]
    for t in snap.tools:
        name = t.get("name", "?")
        for key in ("title", "description"):
            if isinstance(t.get(key), str):
                yield f"tool {name}, {key}", t[key]
        ann = t.get("annotations") or {}
        if isinstance(ann.get("title"), str):
            yield f"tool {name}, annotations title", ann["title"]
        for where, s in _schema_texts(t.get("inputSchema"), ""):
            yield f"tool {name}, {where}", s
        for where, s in _schema_texts(t.get("outputSchema"), ""):
            yield f"tool {name}, output schema {where}", s
    for p in snap.prompts:
        name = p.get("name", "?")
        for key in ("title", "description"):
            if isinstance(p.get(key), str):
                yield f"prompt {name}, {key}", p[key]
        for a in p.get("arguments") or []:
            if isinstance(a.get("description"), str):
                yield f"prompt {name}, argument `{a.get('name')}`", a["description"]
    for kind, items in (("resource", snap.resources), ("resource template", snap.templates)):
        for r in items:
            name = r.get("name") or r.get("uri") or r.get("uriTemplate") or "?"
            for key in ("title", "description"):
                if isinstance(r.get(key), str):
                    yield f"{kind} {name}, {key}", r[key]


# --- hidden characters ---------------------------------------------------------------------

_BIDI = {0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069}
_INVISIBLE = {0x200B, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xFEFF, 0x180E, 0x00AD}
# Format characters with ordinary uses: joiners in emoji and Indic/Persian text, direction marks in RTL text.
_ALLOWED_FORMAT = {0x200C, 0x200D, 0x200E, 0x200F, 0x061C}


def decode_tags(s: str) -> str:
    """Unicode tag characters (U+E0000 block) mirror ASCII and render as nothing at all."""
    return "".join(chr(ord(c) - 0xE0000) for c in s if 0xE0020 <= ord(c) <= 0xE007E)


def _codepoints(chars: list[str]) -> str:
    seen = sorted({ord(c) for c in chars})
    shown = ", ".join(f"U+{cp:04X}" for cp in seen[:6])
    return shown + (f" and {len(seen) - 6} more" if len(seen) > 6 else "")


def check_unicode(where: str, s: str) -> list[Finding]:
    out: list[Finding] = []
    tags = [c for c in s if 0xE0000 <= ord(c) <= 0xE007F]
    if tags:
        hidden = decode_tags(s)
        out.append(
            Finding(
                "unicode.tag",
                Severity.HIGH,
                where,
                f"{len(tags)} invisible Unicode tag characters spell out hidden text",
                _clip(hidden, 200),
            )
        )
    bidi = [c for c in s if ord(c) in _BIDI]
    if bidi:
        out.append(
            Finding(
                "unicode.bidi",
                Severity.HIGH,
                where,
                "bidirectional override characters change the order text is displayed in",
                _codepoints(bidi),
            )
        )
    invisible = [
        c
        for c in s
        if (ord(c) in _INVISIBLE and not (ord(c) == 0xFEFF and s.startswith(c)))
        or (
            unicodedata.category(c) in ("Cf", "Co")
            and ord(c) not in _ALLOWED_FORMAT | _BIDI | _INVISIBLE
            and not 0xE0000 <= ord(c) <= 0xE007F
        )
    ]
    if invisible:
        out.append(
            Finding(
                "unicode.invisible",
                Severity.MEDIUM,
                where,
                f"{len(invisible)} invisible or private-use characters",
                _codepoints(invisible),
            )
        )
    return out


def check_layout(where: str, s: str) -> list[Finding]:
    """Text pushed out of view: below a wall of blank lines or spaces, or inside an HTML comment."""
    out: list[Finding] = []
    m = re.search(r"(?:[ \t]*\n){10,}\s*(\S.{0,80})", s) or re.search(r" {200,}(\S.{0,80})", s)
    if m:
        out.append(
            Finding(
                "hidden.padding",
                Severity.MEDIUM,
                where,
                "text placed after a long run of blank space, out of view in most UIs",
                _clip(m.group(1), 120),
            )
        )
    m = re.search(r"<!--(.*?)-->", s, re.S)
    if m and re.search(r"[A-Za-z]{3}", m.group(1)):
        out.append(
            Finding(
                "hidden.comment",
                Severity.MEDIUM,
                where,
                "an HTML comment: hidden when rendered, read by the model",
                _clip(m.group(1).strip(), 120),
            )
        )
    return out


# --- text aimed at the model ---------------------------------------------------------------

_I = re.I | re.S

_OVERRIDE = re.compile(
    r"\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+|the\s+|your\s+)*"
    r"(?:previous|prior|above|earlier|other|preceding|original|existing|system)\s+"
    r"(?:instructions?|directions?|rules|guidelines|prompts?|context|messages?)\b"
    r"|\bnew\s+(?:system\s+)?instructions\s*:"
    r"|\byou\s+are\s+now\s+(?:a|an|in)\b",
    _I,
)

_CONCEAL = re.compile(
    r"\b(?:do\s+not|don'?t|never|must\s+not|should\s+not|shouldn'?t|without)\s+"
    r"(?:ever\s+)?(?:tell|telling|inform|informing|mention|mentioning|reveal|revealing|show|showing|"
    r"notify|notifying|alert|alerting|disclose|disclosing|asking|ask)\s+"
    r"(?:it\s+|this\s+|that\s+|anything\s+|about\s+(?:it|this|that)\s+)?(?:to\s+)?(?:the\s+)?user\b"
    r"|\bthe\s+user\s+(?:must\s+not|should\s+not|shouldn'?t|need\s+not|does\s*n[o']t\s+need\s+to|"
    r"is\s+not\s+to|must\s+never|should\s+never)\s+(?:know|see|be\s+told|be\s+informed|notice|find\s+out)\b"
    r"|\b(?:hide|conceal|keep)\s+(?:this|it|that|these|the\s+\w+)\s+(?:secret\s+|hidden\s+)?from\s+the\s+user\b"
    r"|\b(?:do\s+not|don'?t|never)\s+(?:ever\s+)?(?:mention|reveal|disclose)\s+(?:that|this|it)\b",
    _I,
)

_TAG = re.compile(
    r"<\s*/?\s*(?:important|system|system[_-]?prompt|instructions?|secret|hidden|admin|override)\s*>"
    r"|\[/?INST\]|<\|im_start\|>|<\|system\|>",
    _I,
)

_SECRET_PATH = re.compile(
    r"(?:~|\$HOME|/home/[\w.-]+|/root|%USERPROFILE%)?/?\.(?:ssh|aws|gnupg|kube|docker|azure|config/gcloud)\b(?:/[\w./-]*)?"
    r"|\bid_(?:rsa|ed25519|ecdsa|dsa)\b"
    r"|\.(?:netrc|npmrc|pypirc|git-credentials|pgpass)\b"
    r"|/etc/(?:shadow|passwd|sudoers)\b"
    r"|\b(?:claude_desktop_config|mcp)\.json\b"
    r"|\bcredentials\.json\b",
    _I,
)
_READ_VERB = re.compile(
    r"\b(?:read|cat|open|load|send|include|access|fetch|get|upload|attach|pass|provide|copy|grab|extract|retrieve|print)\b",
    re.I,
)

_EXFIL_PARAM = re.compile(
    r"\b(?:pass|put|include|send|add|provide|insert|place|copy|attach|append|supply|forward|embed|paste)\b"
    r"(?P<what>[^.\n]{0,100}?)\b(?:as|in|into|inside|via|through|to|within)\s+(?:the\s+)?"
    r"(?:[`'\"]?(?P<param>[A-Za-z_][\w-]*)[`'\"]?\s+(?:parameter|param|argument|arg|field|input)\b"
    r"|[`'\"](?P<quoted>[A-Za-z_][\w-]*)[`'\"])",
    _I,
)
# In an input property's own description, the property is the destination: no name needed.
_FILL_THIS = re.compile(
    r"\b(?:pass|put|include|provide|insert|place|copy|paste|fill|supply|attach|dump|add)\b(?P<what>[^.\n]{0,120})",
    _I,
)
_SENSITIVE = re.compile(
    r"conversation|chat|history|previous\s+messages|system\s+prompt|entire|whole|full\s+contents?|contents?\s+of|"
    r"secret|token|password|passphrase|credential|api[\s_-]?keys?|private\s+keys?|environment\s+variables?|\bssh\b|"
    r"everything|all\s+(?:the\s+)?(?:messages|files|data|context|instructions)|context\s+window",
    re.I,
)

_URL_EXFIL = re.compile(
    r"\b(?:send|post|upload|forward|transmit|submit|report|exfiltrate|beacon)\b[^.\n]{0,100}?https?://\S+"
    r"|!\[[^\]]*\]\(https?://[^)\s]*\?[^)\s]*=(?:\{|\$|<|%7B)",
    _I,
)

_IDENT = r"[`'\"]?(?P<tool>[A-Za-z][\w.-]*[\w])[`'\"]?"
_CROSS_TOOL = [
    re.compile(
        r"\b(?:when|whenever|before|after|if|each\s+time)\s+(?:you\s+|the\s+(?:user|assistant|model|agent|ai)\s+)?"
        r"(?:use|uses|call|calls|invoke|invokes|run|runs|using|calling|invoking|running)\s+(?:the\s+|any\s+|a\s+)?"
        + _IDENT,
        _I,
    ),
    re.compile(r"\b(?:call|invoke|use|run|execute)\s+(?:the\s+)?" + _IDENT + r"\s+(?:tool|function)\b", _I),
    re.compile(r"\b(?:the\s+)?" + _IDENT + r"\s+tool\s+(?:must|should|has\s+to|needs\s+to|will)\b", _I),
]
_NOT_TOOLS = {
    "this",
    "that",
    "these",
    "those",
    "it",
    "them",
    "any",
    "a",
    "an",
    "the",
    "other",
    "another",
    "each",
    "every",
    "following",
    "same",
    "your",
    "my",
    "our",
    "their",
    "its",
    "which",
    "what",
    "tool",
    "tools",
    "function",
    "functions",
}

_DIRECTIVE = re.compile(
    r"\b(?:you|the\s+(?:assistant|ai|model|llm|agent))\s+(?:must|should|have\s+to|need\s+to|are\s+required\s+to)\s+"
    r"(?:always|never|first|also|immediately|now)\b",
    _I,
)


def _sentence_start(s: str, i: int) -> int:
    """Start of the sentence containing position i; a dot inside a name like mcp.json is not an end."""
    ends = [m.end() for m in re.finditer(r"[.!?](?=\s)|\n", s[:i])]
    return ends[-1] if ends else 0


def _looks_like_identifier(s: str, quoted: bool) -> bool:
    if s.lower() in _NOT_TOOLS:
        return False
    return quoted or "_" in s or "-" in s or "." in s or bool(re.search(r"[a-z][A-Z]", s))


def check_text(where: str, s: str, own_tools: set[str]) -> list[Finding]:
    out: list[Finding] = []

    def add(rule: str, sev: Severity, msg: str, m: re.Match[str]) -> None:
        out.append(Finding(rule, sev, where, msg, _context(s, m)))

    if m := _OVERRIDE.search(s):
        add("injection.override", Severity.HIGH, "tells the model to drop its earlier instructions", m)
    if m := _CONCEAL.search(s):
        add("injection.conceal", Severity.HIGH, "tells the model to keep something from the user", m)
    if m := _TAG.search(s):
        add("injection.tag", Severity.MEDIUM, "markup that addresses the model, not a reader", m)
    for m in _SECRET_PATH.finditer(s):
        window = s[max(0, m.start() - 100) : m.end() + 100]
        if _READ_VERB.search(window):
            add("injection.secret-path", Severity.HIGH, "asks for a credential file to be read or sent", m)
        else:
            add("injection.secret-path", Severity.MEDIUM, "mentions a credential file", m)
        break
    for m in _EXFIL_PARAM.finditer(s):
        sentence = s[_sentence_start(s, m.start()) : m.end()]
        if _SENSITIVE.search(m.group("what")) or _SECRET_PATH.search(sentence):
            param = m.group("param") or m.group("quoted")
            dest = "this input" if param.lower() in _NOT_TOOLS else f"`{param}`"
            add("injection.exfil-param", Severity.HIGH, f"asks for private data to be put in {dest}", m)
            break
    else:
        if ", input `" in where and where.endswith("description"):
            for m in _FILL_THIS.finditer(s):
                if _SENSITIVE.search(m.group("what")):
                    add("injection.exfil-param", Severity.HIGH, "this input asks to be filled with private data", m)
                    break
    if m := _URL_EXFIL.search(s):
        add("injection.exfil-url", Severity.HIGH, "asks for data to be sent to a URL", m)
    own = {t.lower() for t in own_tools}
    for rx in _CROSS_TOOL:
        hit = None
        for m in rx.finditer(s):
            name = m.group("tool")
            quoted = (
                m.group(0).find("`" + name) >= 0 or m.group(0).find("'" + name) >= 0 or m.group(0).find('"' + name) >= 0
            )
            if name.lower() in own or not _looks_like_identifier(name, quoted):
                continue
            hit = m
            break
        if hit:
            add(
                "injection.cross-tool",
                Severity.HIGH,
                f"gives orders about `{hit.group('tool')}`, a tool this server does not have",
                hit,
            )
            break
    if m := _DIRECTIVE.search(s):
        add("injection.directive", Severity.INFO, "addresses the model with a standing order", m)
    return out


# --- schemas and annotations ---------------------------------------------------------------

_FREE_COMMAND = re.compile(r"^(?:command|cmd|commands|script|code|shell|sql|expression|expr|eval|exec|program)$", re.I)
_WRITE_VERBS = {
    "delete", "remove", "write", "create", "update", "put", "post", "send", "drop", "kill", "move", "rename",
    "insert", "upload", "install", "uninstall", "push", "commit", "edit", "modify", "append", "overwrite",
    "truncate", "reset", "destroy", "purge", "erase", "wipe", "set",
}  # fmt: skip
_DESTROY_VERBS = {"delete", "remove", "drop", "destroy", "purge", "erase", "wipe", "truncate", "overwrite", "kill"}


def first_word(name: str) -> str:
    parts = re.split(r"[_\-.\s]+|(?<=[a-z0-9])(?=[A-Z])", name.strip())
    return next((p.lower() for p in parts if p), "")


def check_tool_shape(t: dict[str, Any]) -> list[Finding]:
    name = t.get("name", "?")
    out: list[Finding] = []
    schema = t.get("inputSchema")
    if not isinstance(schema, dict) or schema.get("type") != "object":
        out.append(
            Finding(
                "schema.not-object",
                Severity.MEDIUM,
                f"tool {name}, inputSchema",
                "input schema is not a JSON Schema object, which the MCP spec requires",
                _clip(repr(schema), 80),
            )
        )
    else:
        for prop, sub in (schema.get("properties") or {}).items():
            if (
                _FREE_COMMAND.match(prop)
                and isinstance(sub, dict)
                and sub.get("type") in ("string", None)
                and "enum" not in sub
                and "const" not in sub
            ):
                out.append(
                    Finding(
                        "schema.free-command",
                        Severity.INFO,
                        f"tool {name}, input `{prop}`",
                        "takes free text that looks like a command or code to run",
                    )
                )
    ann = t.get("annotations")
    if not ann:
        out.append(
            Finding(
                "annotations.missing",
                Severity.INFO,
                f"tool {name}",
                "no annotations, so clients must assume it may write, destroy and reach the network",
            )
        )
        return out
    ro, de = ann.get("readOnlyHint"), ann.get("destructiveHint")
    verb = first_word(name)
    if ro is True and de is True:
        out.append(
            Finding(
                "annotations.contradiction",
                Severity.MEDIUM,
                f"tool {name}, annotations",
                "claims to be both read-only and destructive",
                "readOnlyHint: true, destructiveHint: true",
            )
        )
    if ro is True and verb in _WRITE_VERBS:
        out.append(
            Finding(
                "annotations.name-mismatch",
                Severity.MEDIUM,
                f"tool {name}, annotations",
                f"named for a write (`{verb}`) but annotated read-only",
                "readOnlyHint: true",
            )
        )
    elif ro is not True and de is False and verb in _DESTROY_VERBS:
        out.append(
            Finding(
                "annotations.name-mismatch",
                Severity.MEDIUM,
                f"tool {name}, annotations",
                f"named for destruction (`{verb}`) but annotated non-destructive",
                "destructiveHint: false",
            )
        )
    return out


# --- entry point -----------------------------------------------------------------------------


def scan(snap: Snapshot) -> list[Finding]:
    own = {t.get("name", "") for t in snap.tools} | {p.get("name", "") for p in snap.prompts}
    out: list[Finding] = []
    for where, s in texts(snap):
        out += check_unicode(where, s)
        out += check_layout(where, s)
        out += check_text(where, s, own)
        hidden = decode_tags(s)
        if hidden:
            out += [
                Finding(f.rule, f.severity, f.where + " (hidden text)", f.message, f.evidence)
                for f in check_text(where, hidden, own)
            ]
    for t in snap.tools:
        out += check_tool_shape(t)
    return dedupe(out)


def dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str]] = set()
    out = []
    for f in findings:
        key = (f.rule, f.where)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def _clip(s: str, n: int) -> str:
    s = " ".join(s.split())
    return s if len(s) <= n else s[: n - 1] + "…"


def _context(s: str, m: re.Match[str]) -> str:
    a, b = max(0, m.start() - 30), min(len(s), m.end() + 30)
    return ("…" if a else "") + _clip(s[a:b], 160) + ("…" if b < len(s) else "")
