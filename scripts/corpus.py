"""Run mcp-audit over the corpus (examples/corpus) in the sandbox and score it.

    python scripts/corpus.py            # print the table
    python scripts/corpus.py --check    # also exit 1 unless every server scores as expected

A malicious server counts as caught when a finding with one of its expected rules reaches its
minimum severity. A benign server counts as clean when nothing is medium or above.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import tomllib
from pathlib import Path

from mcp_audit.model import Severity
from mcp_audit.scan import Options, Target, audit

ROOT = Path(__file__).resolve().parent.parent
IMAGE = "mcp-audit-corpus"


async def run_one(file: str, exercise: bool) -> list[tuple[str, Severity]]:
    report = await audit(Target(command=["python", f"/corpus/{file}"], sandbox=IMAGE), Options(exercise=exercise))
    return [(f.rule, f.severity) for f in report.findings]


def judge(entry: dict, findings: list[tuple[str, Severity]]) -> tuple[bool, list[str]]:
    if entry["kind"] == "malicious":
        floor = Severity.parse(entry.get("min", "high"))
        hits = sorted({r for r, s in findings if r in entry["expect"] and s >= floor})
        return bool(hits), hits
    loud = sorted({r for r, s in findings if s >= Severity.MEDIUM})
    return not loud, loud


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ns = ap.parse_args()
    manifest = tomllib.loads((ROOT / "examples/corpus/manifest.toml").read_text())["server"]
    rows = []
    ok_all = True
    caught = clean = malicious = benign = listed_caught = 0
    for entry in manifest:
        findings = asyncio.run(run_one(entry["file"], exercise=True))
        listing_ok, _ = judge(entry, asyncio.run(run_one(entry["file"], exercise=False)))
        ok, rules = judge(entry, findings)
        name = entry["file"].removesuffix(".py")
        if entry["kind"] == "malicious":
            malicious += 1
            caught += ok
            listed_caught += listing_ok
            verdict, listed = ("caught" if ok else "MISSED"), ("caught" if listing_ok else "missed")
        else:
            benign += 1
            clean += ok
            verdict = "clean" if ok else "FALSE ALARM"
            listed = "clean" if listing_ok else "false alarm"
        ok_all &= ok
        hi = sum(1 for _, s in findings if s == Severity.HIGH)
        med = sum(1 for _, s in findings if s == Severity.MEDIUM)
        rows.append((name, entry["kind"], listed, verdict, f"{hi}/{med}", ", ".join(rules) or "-"))
    head = ("server", "kind", "listing only", "with calls", "high/med", "matched rules")
    w = [max(len(r[i]) for r in [*rows, head]) for i in range(5)]
    for r in [head, *rows]:
        print("  ".join(f"{r[i]:<{w[i]}}" for i in range(5)) + "  " + r[5])
    print(
        f"\nwith calls: {caught}/{malicious} malicious caught, {clean}/{benign} benign clean"
        f"\nlisting only: {listed_caught}/{malicious} malicious caught"
    )
    return 0 if ok_all or not ns.check else 1


if __name__ == "__main__":
    sys.exit(main())
