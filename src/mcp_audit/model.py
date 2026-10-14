"""What a scan collects (a snapshot of the server's surface) and what it reports (findings)."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class Severity(enum.IntEnum):
    INFO = 0
    MEDIUM = 1
    HIGH = 2

    def __str__(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, s: str) -> Severity:
        try:
            return cls[s.upper()]
        except KeyError:
            raise ValueError(f"unknown severity {s!r}: use info, medium or high") from None


@dataclass(frozen=True)
class Finding:
    rule: str  # stable id, e.g. "injection.conceal"; what the corpus and CI match on
    severity: Severity
    where: str  # e.g. "tool add_numbers, description" or "tool get_note, call 1"
    message: str  # one line, says what is wrong
    evidence: str = ""  # the text, path or address that triggered it

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "severity": str(self.severity),
            "where": self.where,
            "message": self.message,
            "evidence": self.evidence,
        }


@dataclass
class Snapshot:
    """Everything a client can see without calling a tool, as plain JSON (camelCase, as on the wire)."""

    server: dict[str, Any] = field(default_factory=dict)  # serverInfo
    instructions: str | None = None
    tools: list[dict[str, Any]] = field(default_factory=list)
    prompts: list[dict[str, Any]] = field(default_factory=list)
    resources: list[dict[str, Any]] = field(default_factory=list)
    templates: list[dict[str, Any]] = field(default_factory=list)

    def tool(self, name: str) -> dict[str, Any] | None:
        return next((t for t in self.tools if t.get("name") == name), None)

    def as_dict(self) -> dict[str, Any]:
        return {
            "server": self.server,
            "instructions": self.instructions,
            "tools": self.tools,
            "prompts": self.prompts,
            "resources": self.resources,
            "resourceTemplates": self.templates,
        }


@dataclass
class CallRecord:
    """One tool call made during the dynamic phase, with the host-clock window it ran in."""

    tool: str
    arguments: dict[str, Any]
    started: float
    ended: float
    is_error: bool = False
    output: str = ""
    error: str = ""  # transport or protocol failure, not a tool-reported error


@dataclass
class Report:
    target: str
    snapshot: Snapshot
    findings: list[Finding] = field(default_factory=list)
    calls: list[CallRecord] = field(default_factory=list)
    dynamic: bool = False
    notes: list[str] = field(default_factory=list)  # what was skipped and why

    def worst(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)

    def count(self, severity: Severity) -> int:
        return sum(1 for f in self.findings if f.severity == severity)

    def as_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "dynamic": self.dynamic,
            "summary": {str(s): self.count(s) for s in reversed(Severity)},
            "findings": [f.as_dict() for f in self.findings],
            "calls": [
                {
                    "tool": c.tool,
                    "arguments": c.arguments,
                    "isError": c.is_error,
                    "error": c.error,
                    "seconds": round(c.ended - c.started, 3),
                }
                for c in self.calls
            ],
            "notes": self.notes,
            "snapshot": self.snapshot.as_dict(),
        }
