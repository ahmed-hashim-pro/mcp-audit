"""mcp-audit's command line: scan, snapshot, pin, verify."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__, pin, static
from .model import Report, Severity, Snapshot
from .report import render
from .sandbox import docker_available, image_exists
from .scan import ConnectError, Options, Target, as_connect_error, audit, connect, snapshot

EPILOG = """\
examples:
  mcp-audit scan -- npx -y @modelcontextprotocol/server-everything
  mcp-audit scan --sandbox mcp-audit-reference -- mcp-server-git
  mcp-audit scan --url http://127.0.0.1:8000/mcp
  mcp-audit pin -- python my_server.py && mcp-audit verify -- python my_server.py
"""


def _target_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--url", help="a streamable HTTP server to connect to, instead of a command")
    p.add_argument(
        "--sandbox",
        metavar="IMAGE",
        help="run the command inside this Docker image, with no network and syscall tracing "
        "(build one FROM mcp-audit-sandbox; see docker/)",
    )
    p.add_argument("command", nargs=argparse.REMAINDER, help="the server command, after --")


def _target(ns: argparse.Namespace) -> Target:
    command = list(ns.command)
    if command and command[0] == "--":
        command = command[1:]
    if ns.url and command:
        raise SystemExit("mcp-audit: give either --url or a command, not both")
    if not ns.url and not command:
        raise SystemExit("mcp-audit: give the server command after --, or --url")
    if ns.url and ns.sandbox:
        raise SystemExit("mcp-audit: --sandbox runs a command; it cannot wrap --url")
    if ns.sandbox:
        if not docker_available():
            raise SystemExit("mcp-audit: --sandbox needs Docker, and `docker info` failed")
        if not image_exists(ns.sandbox):
            raise SystemExit(f"mcp-audit: no Docker image {ns.sandbox!r}; `make images` builds the bundled ones")
    return Target(command=command, url=ns.url, sandbox=ns.sandbox)


def _load_calls(path: str | None) -> dict[str, list[dict[str, Any]]]:
    if not path:
        return {}
    data = json.loads(Path(path).read_text())
    if not isinstance(data, dict):
        raise SystemExit(f"mcp-audit: {path}: expected an object of tool name -> arguments")
    return {k: (v if isinstance(v, list) else [v]) for k, v in data.items()}


def _n(count: int, noun: str) -> str:
    return f"{count} {noun}" + ("" if count == 1 else "s")


def _write_json(report: Report, dest: str) -> None:
    text = json.dumps(report.as_dict(), indent=2, ensure_ascii=False)
    if dest == "-":
        print(text)
    else:
        Path(dest).write_text(text + "\n")


def cmd_scan(ns: argparse.Namespace) -> int:
    if ns.snapshot:
        snap = _snapshot_from_file(Path(ns.snapshot))
        report = Report(ns.snapshot, snap, static.scan(snap))
        report.findings.sort(key=lambda f: -f.severity)
        report.notes.append("scanned a saved snapshot: no relisting and no tool calls")
    else:
        target = _target(ns)
        exercise = ns.exercise if ns.exercise is not None else bool(target.sandbox)
        opts = Options(
            exercise=exercise,
            calls=_load_calls(ns.calls),
            skip=set(ns.skip or []),
            timeout=ns.timeout,
            startup_timeout=ns.startup_timeout,
            unsafe_host_calls=ns.unsafe_host_calls,
            keep_trace=Path(ns.keep_trace) if ns.keep_trace else None,
        )
        if not target.sandbox and not target.url:
            print("mcp-audit: starting the server on this machine (no --sandbox): its code runs here", file=sys.stderr)
        try:
            report = asyncio.run(audit(target, opts))
        except ConnectError as e:
            print(f"mcp-audit: {e}", file=sys.stderr)
            return 2
        if not exercise:
            report.notes.append("tools were not called; --sandbox IMAGE exercises them and traces what they do")
    if ns.json:
        _write_json(report, ns.json)
    if ns.json != "-":
        render(report, show_info=ns.show_info)
    if ns.fail_on == "never":
        return 0
    worst = report.worst()
    return 1 if worst is not None and worst >= Severity.parse(ns.fail_on) else 0


def _snapshot_from_file(path: Path) -> Snapshot:
    d = json.loads(path.read_text())
    d = d.get("snapshot", d)
    return Snapshot(
        server=d.get("server") or {},
        instructions=d.get("instructions"),
        tools=d.get("tools") or [],
        prompts=d.get("prompts") or [],
        resources=d.get("resources") or [],
        templates=d.get("resourceTemplates") or [],
    )


def _run_snapshot(target: Target) -> Snapshot:
    try:
        return asyncio.run(_just_snapshot(target))
    except (ExceptionGroup, OSError, TimeoutError) as e:
        raise as_connect_error(e) from e


async def _just_snapshot(target: Target) -> Snapshot:
    import tempfile

    from .sandbox import SandboxRun

    with tempfile.TemporaryDirectory(prefix="mcp-audit-") as tmp:
        work = Path(tmp)
        work.chmod(0o777)
        run = SandboxRun(target.sandbox, work) if target.sandbox else None
        try:
            async with connect(target, work, run) as live:
                return await snapshot(live.session)
        finally:
            if run is not None:
                run.finish()


def cmd_snapshot(ns: argparse.Namespace) -> int:
    try:
        snap = _run_snapshot(_target(ns))
    except ConnectError as e:
        print(f"mcp-audit: {e}", file=sys.stderr)
        return 2
    text = json.dumps(snap.as_dict(), indent=2, ensure_ascii=False)
    if ns.output and ns.output != "-":
        Path(ns.output).write_text(text + "\n")
    else:
        print(text)
    return 0


def _current(ns: argparse.Namespace) -> tuple[str, dict[str, Any]]:
    snap = _snapshot_from_file(Path(ns.snapshot)) if ns.snapshot else _run_snapshot(_target(ns))
    name = ns.name or snap.server.get("name") or "server"
    return name, pin.entry(snap)


def cmd_pin(ns: argparse.Namespace) -> int:
    lock = Path(ns.lock)
    try:
        data = pin.load(lock)
        name, current = _current(ns)
    except (ConnectError, ValueError) as e:
        print(f"mcp-audit: {e}", file=sys.stderr)
        return 2
    data["servers"][name] = current
    pin.save(lock, data)
    print(
        f"pinned {_n(len(current['tools']), 'tool')} and {_n(len(current['prompts']), 'prompt')} of {name!r} in {lock}"
    )
    return 0


def cmd_verify(ns: argparse.Namespace) -> int:
    lock = Path(ns.lock)
    try:
        data = pin.load(lock)
        name, current = _current(ns)
    except (ConnectError, ValueError) as e:
        print(f"mcp-audit: {e}", file=sys.stderr)
        return 2
    locked = data["servers"].get(name)
    if locked is None:
        print(f"mcp-audit: {name!r} is not in {lock}; run `mcp-audit pin` first", file=sys.stderr)
        return 2
    diffs = pin.compare(locked, current)
    if not diffs:
        print(f"{name}: {_n(len(current['tools']), 'tool')} and {_n(len(current['prompts']), 'prompt')} match {lock}")
        return 0
    print(f"{name}: {_n(len(diffs), 'change')} since {lock} was written")
    for d in diffs:
        print(f"  {d}")
    print("review the change, then `mcp-audit pin` to accept it")
    return 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="mcp-audit",
        description="Audit an MCP server: what it tells the model, and what its tools actually do.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--version", action="version", version=f"mcp-audit {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("scan", help="list the server's tools, check them, and (in a sandbox) call them")
    p.add_argument("--snapshot", metavar="FILE", help="scan a saved snapshot instead of a live server")
    p.add_argument("--exercise", action=argparse.BooleanOptionalAction, default=None,
                   help="call every tool (default: on with --sandbox, off otherwise)")  # fmt: skip
    p.add_argument("--calls", metavar="FILE", help="JSON: tool name -> arguments (or a list of them) to call it with")
    p.add_argument("--skip", metavar="TOOL", action="append", help="don't call this tool (repeatable)")
    p.add_argument("--timeout", type=float, default=20.0, help="seconds per tool call (default 20)")
    p.add_argument(
        "--startup-timeout", type=float, default=60.0, help="seconds to wait for the server to start (default 60)"
    )
    p.add_argument("--json", metavar="FILE", help="also write the full report as JSON ('-' for stdout only)")
    p.add_argument("--fail-on", choices=["high", "medium", "info", "never"], default="high",
                   help="exit 1 when a finding is at least this severe (default high)")  # fmt: skip
    p.add_argument("--show-info", action="store_true", help="list info findings too")
    p.add_argument("--unsafe-host-calls", action="store_true", help="allow --exercise without a sandbox")
    p.add_argument("--keep-trace", metavar="DIR", help="save the raw strace log and the server's stderr in DIR")
    _target_args(p)
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("snapshot", help="print what the server shows a client, as JSON")
    p.add_argument("-o", "--output", metavar="FILE")
    _target_args(p)
    p.set_defaults(func=cmd_snapshot)

    for name, func, text in (
        ("pin", cmd_pin, "record the server's tool and prompt definitions in a lockfile"),
        ("verify", cmd_verify, "fail when the server's definitions differ from the lockfile"),
    ):
        p = sub.add_parser(name, help=text)
        p.add_argument("--lock", default="mcp-audit.lock.json", help="lockfile (default mcp-audit.lock.json)")
        p.add_argument("--name", help="key in the lockfile (default: the server's own name)")
        p.add_argument("--snapshot", metavar="FILE", help="use a saved snapshot instead of a live server")
        _target_args(p)
        p.set_defaults(func=func)

    ns = ap.parse_args(argv)
    if getattr(ns, "snapshot", None) is None and ns.cmd in ("pin", "verify") and not ns.command and not ns.url:
        ap.error(f"{ns.cmd}: give the server command after --, --url, or --snapshot")
    if ns.cmd == "scan" and not ns.snapshot and not ns.command and not ns.url:
        ap.error("scan: give the server command after --, --url, or --snapshot")
    code: int = ns.func(ns)
    return code
