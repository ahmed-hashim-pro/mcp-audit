"""Scan real MCP servers in the sandbox and print every medium/high finding with its verdict.

    python scripts/realworld.py                 # scan all of examples/realworld.toml
    python scripts/realworld.py --only git      # one server
    python scripts/realworld.py --check         # exit 1 if a medium/high finding has no verdict

Verdicts live in examples/realworld-labels.toml, written by hand after reading each finding:
"correct" means the server really does what the finding says (whether or not that matters);
"false-alarm" means it does not. A new or changed finding has no verdict until someone reads it.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
import tomllib
from pathlib import Path

from mcp_audit.model import Severity
from mcp_audit.scan import ConnectError, Options, Target, audit

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", action="append")
    ap.add_argument("--check", action="store_true")
    ns = ap.parse_args()
    servers = tomllib.loads((ROOT / "examples/realworld.toml").read_text())["server"]
    labels = tomllib.loads((ROOT / "examples/realworld-labels.toml").read_text()).get("label", [])
    verdicts = {(lab["server"], lab["rule"], lab["where"]): lab for lab in labels}
    rows, details = [], []
    unlabelled = 0
    totals: dict[str, dict[str, int]] = {}
    for s in servers:
        if ns.only and s["name"] not in ns.only:
            continue
        t0 = time.time()
        try:
            report = asyncio.run(
                audit(
                    Target(command=s["command"], sandbox=s["image"]),
                    Options(exercise=True, timeout=15, startup_timeout=240),
                )
            )
        except ConnectError as e:
            rows.append((s["name"], s["set"], "-", "-", "-", "-", f"did not start: {str(e).splitlines()[0][:60]}"))
            continue
        loud = [f for f in report.findings if f.severity >= Severity.MEDIUM]
        counts = totals.setdefault(s["set"], {"servers": 0, "tools": 0, "findings": 0, "correct": 0, "false-alarm": 0})
        counts["servers"] += 1
        counts["tools"] += len(report.snapshot.tools)
        verdict_counts = {"correct": 0, "false-alarm": 0}
        for f in loud:
            lab = verdicts.get((s["name"], f.rule, f.where))
            v = lab["verdict"] if lab else "UNLABELLED"
            unlabelled += lab is None
            if v in verdict_counts:
                verdict_counts[v] += 1
                counts[v] += 1
            counts["findings"] += 1
            details.append(
                f"{s['name']:<18} {str(f.severity).upper():<6} {f.rule}  {f.where}\n"
                f"{'':<18}        {f.evidence[:150]}\n"
                f"{'':<18}        verdict: {v}" + (f": {lab['why']}" if lab else "")
            )
        errors = sum(1 for c in report.calls if c.is_error or c.error)
        rows.append(
            (
                s["name"],
                s["set"],
                str(len(report.snapshot.tools)),
                f"{len(report.calls)} ({errors} err)",
                f"{report.count(Severity.HIGH)}/{report.count(Severity.MEDIUM)}",
                f"{verdict_counts['correct']}/{verdict_counts['false-alarm']}",
                f"{time.time() - t0:.0f}s",
            )
        )
    head = ("server", "set", "tools", "calls", "high/med", "correct/false", "time")
    w = [max(len(r[i]) for r in [*rows, head]) for i in range(len(head))]
    for r in [head, *rows]:
        print("  ".join(f"{c:<{w[i]}}" for i, c in enumerate(r)).rstrip())
    print()
    for name, c in totals.items():
        print(
            f"{name}: {c['servers']} servers, {c['tools']} tools, {c['findings']} medium/high findings: "
            f"{c['correct']} correct, {c['false-alarm']} false alarms"
        )
    print()
    print("\n".join(details))
    if unlabelled:
        print(f"\n{unlabelled} finding(s) have no verdict in examples/realworld-labels.toml", file=sys.stderr)
    return 1 if ns.check and unlabelled else 0


if __name__ == "__main__":
    sys.exit(main())
