"""The human-readable report."""

from __future__ import annotations

import os
import sys
from typing import TextIO

from .model import Report, Severity

_COLOR = {Severity.HIGH: "\033[1;31m", Severity.MEDIUM: "\033[33m", Severity.INFO: "\033[2m"}
_RESET = "\033[0m"


def _n(count: int, noun: str) -> str:
    return f"{count} {noun}" + ("" if count == 1 else "s")


def _use_color(out: TextIO) -> bool:
    return out.isatty() and "NO_COLOR" not in os.environ


def render(report: Report, show_info: bool = False, out: TextIO | None = None) -> None:
    out = out or sys.stdout
    color = _use_color(out)

    def paint(sev: Severity, s: str) -> str:
        return f"{_COLOR[sev]}{s}{_RESET}" if color else s

    snap = report.snapshot
    srv = snap.server
    name = f"{srv.get('name', '?')} {srv.get('version', '')}".strip()
    print(f"server   {name}", file=out)
    print(f"target   {report.target}", file=out)
    surface = f"{_n(len(snap.tools), 'tool')}, {_n(len(snap.prompts), 'prompt')}, {_n(len(snap.resources), 'resource')}"
    if report.dynamic:
        failed = sum(1 for c in report.calls if c.is_error or c.error)
        surface += f"; {_n(len(report.calls), 'call')} made ({failed} returned errors)"
    print(f"surface  {surface}", file=out)
    print(file=out)
    shown = [f for f in report.findings if show_info or f.severity > Severity.INFO]
    for f in shown:
        label = f"{str(f.severity).upper():<6}"
        print(f"{paint(f.severity, label)} {f.rule}  {f.where}", file=out)
        print(f"       {f.message}", file=out)
        if f.evidence:
            print(f"       {f.evidence}", file=out)
    if shown:
        print(file=out)
    for note in report.notes:
        print(f"note: {note}", file=out)
    hidden = 0 if show_info else report.count(Severity.INFO)
    summary = ", ".join(f"{report.count(s)} {s}" for s in reversed(Severity))
    print(summary + (f"  ({hidden} info not shown; --show-info)" if hidden else ""), file=out)
