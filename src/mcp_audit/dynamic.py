"""Judging behaviour: what a tool did against what its annotations promised, and whether
the server's definitions held still.

Annotations are hints, per the MCP spec, and their defaults are the cautious ones: a tool
with no annotations may write, may destroy and may reach the open world. So only a tool
that *claims* otherwise can be caught out. Writing files is fine for a tool that never said
it was read-only; it is a finding only when readOnlyHint is true.
"""

from __future__ import annotations

import dataclasses
import json
from typing import Any

from . import static
from .model import CallRecord, Finding, Severity, Snapshot
from .sandbox import CANARY, TMP_PREFIXES, Event, ignored

_COMPARED = ("title", "description", "inputSchema", "outputSchema", "annotations")


def _short(v: Any, n: int = 90) -> str:
    s = v if isinstance(v, str) else json.dumps(v, sort_keys=True, ensure_ascii=False)
    s = " ".join(s.split())
    return s if len(s) <= n else s[: n - 1] + "…"


def judge_relisting(
    first: Snapshot, later: Snapshot, when: str, notifications: list[tuple[float, str]]
) -> list[Finding]:
    """A tool whose definition changes after the client has seen it: the 'rug pull'."""
    out: list[Finding] = []
    notified = any(m.endswith("tools/list_changed") for _, m in notifications)
    before = {str(t.get("name")): t for t in first.tools}
    after = {str(t.get("name")): t for t in later.tools}
    for name, t in after.items():
        old = before.get(name)
        if old is None:
            continue
        changed = [k for k in _COMPARED if old.get(k) != t.get(k)]
        if changed:
            key = changed[0]
            out.append(
                Finding(
                    "rug-pull.changed",
                    Severity.HIGH,
                    f"tool {name}",
                    f"its {', '.join(changed)} changed {when}"
                    + (" (announced with tools/list_changed)" if notified else " (with no tools/list_changed notice)"),
                    f"{_short(old.get(key))}  →  {_short(t.get(key))}",
                )
            )
    added = sorted(set(after) - set(before))
    if added:
        out.append(
            Finding(
                "rug-pull.added",
                Severity.MEDIUM,
                "tool list",
                f"{len(added)} tool(s) appeared {when}",
                ", ".join(str(a) for a in added[:6]),
            )
        )
    removed = sorted(set(before) - set(after))
    if removed:
        out.append(
            Finding(
                "rug-pull.removed", Severity.INFO, "tool list", f"{len(removed)} tool(s) went away {when}",
                ", ".join(str(r) for r in removed[:6]),
            )
        )  # fmt: skip
    # Anything the new definitions say that the old ones didn't.
    old_keys = {(f.rule, f.where) for f in static.scan(first)}
    for f in static.scan(later):
        if (f.rule, f.where) not in old_keys and f.severity >= Severity.MEDIUM:
            out.append(Finding(f.rule, f.severity, f"{f.where} ({when})", f.message, f.evidence))
    return out


def _windows(calls: list[CallRecord]) -> list[tuple[float, float]]:
    """Each call owns the time from its start until the next call starts."""
    spans = []
    for i, c in enumerate(calls):
        end = calls[i + 1].started if i + 1 < len(calls) else c.ended + 0.5
        spans.append((c.started, end))
    return spans


def _where(calls: list[CallRecord], i: int) -> str:
    name = calls[i].tool
    same = [j for j, c in enumerate(calls) if c.tool == name]
    return f"tool {name}" + (f", call {same.index(i) + 1}" if len(same) > 1 else "")


def _paths(events: list[Event], n: int = 3) -> str:
    seen: list[str] = []
    for e in events:
        if e.detail not in seen:
            seen.append(e.detail)
    shown = ", ".join(seen[:n]) + (f" and {len(seen) - n} more" if len(seen) > n else "")
    if events and all(e.failed for e in events):
        shown += f" (attempted: {events[0].errno or 'failed'})"
    return shown


def separate_cleanup(events: list[Event]) -> list[Event]:
    """Deleting a file the run itself created (a lock, a temp file renamed into place) destroys
    nothing that was there before. Those deletes, and deletes that failed, become "cleanup"."""
    created: set[str] = set()
    out = []
    for e in sorted(events, key=lambda e: e.ts):
        if e.kind == "write" and not e.failed:
            created.add(e.detail)
        if e.kind == "delete" and (e.failed or e.detail in created):
            e = dataclasses.replace(e, kind="cleanup")
        out.append(e)
    return out


def judge_calls(
    snap: Snapshot,
    calls: list[CallRecord],
    events: list[Event],
    diff: list[tuple[str, str]],
    traced: bool,
) -> list[Finding]:
    out: list[Finding] = []
    events = separate_cleanup(events)
    spans = _windows(calls)
    buckets: list[list[Event]] = [[] for _ in calls]
    startup: list[Event] = []
    after: list[Event] = []
    for e in events:
        if not calls or e.ts < spans[0][0]:
            startup.append(e)
            continue
        for i, (a, b) in enumerate(spans):
            if a <= e.ts < b:
                buckets[i].append(e)
                break
        else:
            after.append(e)

    for i, c in enumerate(calls):
        tool = snap.tool(c.tool) or {}
        ann = tool.get("annotations") or {}
        where = _where(calls, i)
        ev = buckets[i]
        by = {
            k: [e for e in ev if e.kind == k]
            for k in ("write", "delete", "cleanup", "secret-read", "connect", "send", "canary-sent", "exec")
        }

        asked = json.dumps(c.arguments)
        secret = [e for e in by["secret-read"] if e.detail not in asked]
        if secret:
            out.append(
                Finding(
                    "dynamic.secret-read", Severity.HIGH, where,
                    "opened a planted credential file its arguments never named", _paths(secret),
                )
            )  # fmt: skip
        if CANARY in c.output:
            out.append(
                Finding(
                    "dynamic.canary-output", Severity.HIGH, where, "returned the contents of a planted credential file"
                )
            )
        if by["canary-sent"]:
            out.append(
                Finding(
                    "dynamic.canary-sent", Severity.HIGH, where,
                    "sent planted credential data over the network", _paths(by["canary-sent"]),
                )
            )  # fmt: skip
        net = by["connect"] + by["send"]
        if net:
            if ann.get("openWorldHint") is False:
                out.append(
                    Finding(
                        "dynamic.closed-world-network", Severity.HIGH, where,
                        "annotated openWorldHint: false, but tried to reach the network", _paths(net),
                    )
                )  # fmt: skip
            else:
                out.append(Finding("dynamic.network", Severity.INFO, where, "tried to reach the network", _paths(net)))
        touched = by["write"] + by["delete"] + by["cleanup"]
        changes = [e for e in touched if not e.detail.startswith(TMP_PREFIXES)]
        tmp = [e for e in touched if e.detail.startswith(TMP_PREFIXES)]
        verb = "tried to change files" if all(e.failed for e in changes) else "changed files"
        if changes:
            if ann.get("readOnlyHint") is True:
                out.append(
                    Finding(
                        "dynamic.readonly-write", Severity.HIGH, where,
                        f"annotated readOnlyHint: true, but {verb}", _paths(changes),
                    )
                )  # fmt: skip
            elif ann.get("destructiveHint") is False and by["delete"]:
                out.append(
                    Finding(
                        "dynamic.nondestructive-delete", Severity.MEDIUM, where,
                        "annotated destructiveHint: false, but deleted files that existed before", _paths(by["delete"]),
                    )
                )  # fmt: skip
            else:
                out.append(Finding("dynamic.write", Severity.INFO, where, verb, _paths(changes)))
        if tmp and ann.get("readOnlyHint") is True:
            out.append(Finding("dynamic.tmp-write", Severity.INFO, where, "wrote scratch files", _paths(tmp)))
        if by["exec"]:
            out.append(Finding("dynamic.exec", Severity.INFO, where, "ran programs", _paths(by["exec"])))
        if c.output:
            hits = [f for f in static.check_text(where, c.output, set()) if f.severity == Severity.HIGH]
            hits += [f for f in static.check_unicode(where, c.output) if f.severity == Severity.HIGH]
            if hits:
                out.append(
                    Finding(
                        "dynamic.output-injection", Severity.MEDIUM, where,
                        f"its result contains text aimed at the model ({hits[0].rule})", hits[0].evidence,
                    )
                )  # fmt: skip

    for label, ev in (("server startup", startup), ("after the last call", after)):
        secret = [e for e in ev if e.kind == "secret-read"]
        if secret:
            out.append(
                Finding("dynamic.secret-read", Severity.HIGH, label, "opened a planted credential file", _paths(secret))
            )
        sent = [e for e in ev if e.kind == "canary-sent"]
        if sent:
            out.append(
                Finding(
                    "dynamic.canary-sent",
                    Severity.HIGH,
                    label,
                    "sent planted credential data over the network",
                    _paths(sent),
                )
            )
        net = [e for e in ev if e.kind in ("connect", "send")]
        if net:
            out.append(Finding("dynamic.network", Severity.INFO, label, "tried to reach the network", _paths(net)))

    if traced:
        seen = {e.detail for e in events if e.kind in ("write", "delete", "cleanup")}
        untraced = [p for kind, p in diff if p not in seen and not ignored(p) and not p.startswith(TMP_PREFIXES)]
        if untraced:
            out.append(
                Finding(
                    "dynamic.untraced-change", Severity.INFO, "container filesystem",
                    "changed during the run without a matching traced call (e.g. through mmap)",
                    ", ".join(untraced[:5]) + (f" and {len(untraced) - 5} more" if len(untraced) > 5 else ""),
                )
            )  # fmt: skip
    errors = [c for c in calls if c.error]
    if errors:
        out.append(
            Finding(
                "dynamic.call-failed", Severity.INFO, "tool calls",
                f"{len(errors)} call(s) failed at the protocol level", f"{errors[0].tool}: {errors[0].error[:120]}",
            )
        )  # fmt: skip
    return out
