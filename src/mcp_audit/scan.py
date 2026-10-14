"""Connect to a server as an MCP client, take its snapshot, optionally exercise it, and judge it."""

from __future__ import annotations

import asyncio
import contextlib
import json
import shutil
import tempfile
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.session import IncomingMessage
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client

from . import static
from .dynamic import judge_calls, judge_relisting
from .model import CallRecord, Report, Snapshot
from .sandbox import SandboxRun, parse_trace
from .synth import arguments_for


@dataclass
class Target:
    command: list[str] = field(default_factory=list)  # stdio server
    url: str | None = None  # streamable HTTP server
    sandbox: str | None = None  # Docker image to run the stdio command in

    def label(self) -> str:
        if self.url:
            return self.url
        cmd = " ".join(self.command)
        return f"{cmd}  (in {self.sandbox})" if self.sandbox else cmd


@dataclass
class Options:
    exercise: bool = False  # call every tool; only allowed in the sandbox unless unsafe_host_calls
    calls: dict[str, list[dict[str, Any]]] = field(default_factory=dict)  # tool -> argument sets to use
    skip: set[str] = field(default_factory=set)
    timeout: float = 20.0
    startup_timeout: float = 60.0
    unsafe_host_calls: bool = False
    keep_trace: Path | None = None  # copy the raw strace log and the server's stderr here


class ConnectError(RuntimeError):
    pass


def _leaf(exc: BaseException) -> BaseException:
    """The first real error inside the exception groups anyio wraps transport failures in."""
    while isinstance(exc, BaseExceptionGroup) and exc.exceptions:
        connect = [e for e in exc.exceptions if isinstance(_leaf(e), ConnectError)]
        exc = connect[0] if connect else exc.exceptions[0]
    return exc


def as_connect_error(exc: BaseException) -> ConnectError:
    leaf = _leaf(exc)
    return leaf if isinstance(leaf, ConnectError) else ConnectError(f"{type(leaf).__name__}: {leaf}")


@dataclass
class _Live:
    session: ClientSession
    notifications: list[tuple[float, str]]
    sandbox: SandboxRun | None
    errlog: Path


@contextlib.asynccontextmanager
async def connect(
    target: Target, workdir: Path, run: SandboxRun | None = None, startup_timeout: float = 60.0
) -> AsyncIterator[_Live]:
    notes: list[tuple[float, str]] = []

    async def on_message(message: IncomingMessage) -> None:
        method = getattr(message, "method", None)
        if isinstance(method, str):
            notes.append((time.time(), method))

    errlog = workdir / "server-stderr.log"
    if target.sandbox and run is None:
        run = SandboxRun(target.sandbox, workdir)
    with errlog.open("w") as err:
        if target.url:
            transport = streamable_http_client(target.url)
        elif run is not None:
            transport = stdio_client(
                StdioServerParameters(command="docker", args=run.docker_args(target.command)), errlog=err
            )
        else:
            transport = stdio_client(
                StdioServerParameters(command=target.command[0], args=target.command[1:]), errlog=err
            )
        async with transport as (read, write), ClientSession(read, write, message_handler=on_message) as session:
            try:
                await asyncio.wait_for(session.initialize(), startup_timeout)
            except Exception as e:
                raise ConnectError(f"could not initialize the server: {e!r}\n{_tail(errlog)}") from e
            yield _Live(session, notes, run, errlog)


def _tail(path: Path, n: int = 15) -> str:
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return ""
    return "\n".join(lines[-n:])


def _dump(obj: Any) -> dict[str, Any]:
    d: dict[str, Any] = obj.model_dump(by_alias=True, exclude_none=True, mode="json")
    return d


async def _list_all(session: ClientSession, method: str, attr: str) -> list[dict[str, Any]]:
    from mcp.types import PaginatedRequestParams

    out: list[dict[str, Any]] = []
    cursor = None
    for _ in range(50):
        params = PaginatedRequestParams(cursor=cursor) if cursor else None
        result = await getattr(session, method)(params=params)
        out += [_dump(x) for x in getattr(result, attr)]
        cursor = getattr(result, "next_cursor", None)
        if not cursor:
            break
    return out


async def snapshot(session: ClientSession, tools_only: bool = False) -> Snapshot:
    init = session.initialize_result
    caps = getattr(init, "capabilities", None)
    snap = Snapshot()
    if init is not None:
        snap.server = _dump(init.server_info)
        snap.instructions = init.instructions
    if caps is None or caps.tools is not None:
        snap.tools = await _list_all(session, "list_tools", "tools")
    if tools_only:
        return snap
    if caps is not None and caps.prompts is not None:
        with contextlib.suppress(Exception):
            snap.prompts = await _list_all(session, "list_prompts", "prompts")
    if caps is not None and caps.resources is not None:
        with contextlib.suppress(Exception):
            snap.resources = await _list_all(session, "list_resources", "resources")
        with contextlib.suppress(Exception):
            snap.templates = await _list_all(session, "list_resource_templates", "resource_templates")
    return snap


def _output_text(result: Any) -> tuple[bool, str]:
    parts: list[str] = []
    for c in getattr(result, "content", None) or []:
        kind = getattr(c, "type", "")
        if kind == "text":
            parts.append(c.text)
        elif kind == "resource":
            res = getattr(c, "resource", None)
            parts.append(getattr(res, "text", None) or f"[resource {getattr(res, 'uri', '')}]")
        else:
            parts.append(f"[{kind}]")
    sc = getattr(result, "structured_content", None)
    if sc is not None:
        parts.append(json.dumps(sc, ensure_ascii=False))
    return bool(getattr(result, "is_error", False)), "\n".join(parts)


async def exercise(live: _Live, snap: Snapshot, opts: Options) -> tuple[list[CallRecord], list[str]]:
    calls: list[CallRecord] = []
    notes: list[str] = []
    for tool in snap.tools:
        name = tool.get("name", "")
        if name in opts.skip:
            notes.append(f"skipped {name} (--skip)")
            continue
        argsets = opts.calls.get(name) or [arguments_for(tool.get("inputSchema"))]
        for args in argsets:
            rec = CallRecord(name, args, time.time(), 0.0)
            try:
                result = await live.session.call_tool(name, args, read_timeout_seconds=opts.timeout)
                rec.is_error, rec.output = _output_text(result)
            except Exception as e:  # a hung or crashed tool is a result too
                rec.error = f"{type(e).__name__}: {e}"[:300]
            rec.ended = time.time()
            calls.append(rec)
            if rec.error and ("closed" in rec.error.lower() or "ClosedResource" in rec.error):
                notes.append(f"the connection closed during {name}; later tools were not called")
                return calls, notes
    return calls, notes


async def audit(target: Target, opts: Options) -> Report:
    report = Report(target.label(), Snapshot())
    if opts.exercise and not target.sandbox and not opts.unsafe_host_calls:
        raise ConnectError(
            "calling tools runs them for real; use --sandbox IMAGE, or --unsafe-host-calls if you mean it"
        )
    with tempfile.TemporaryDirectory(prefix="mcp-audit-") as tmp:
        workdir = Path(tmp)
        workdir.chmod(0o777)
        run = SandboxRun(target.sandbox, workdir) if target.sandbox else None
        session = _Session()
        diff: list[tuple[str, str]] = []
        try:
            await _talk(target, workdir, run, opts, report, session)
        except (ExceptionGroup, OSError, ConnectError, TimeoutError) as e:
            raise as_connect_error(e) from e
        finally:
            if run is not None:
                diff = run.finish()
            if opts.keep_trace is not None:
                opts.keep_trace.mkdir(parents=True, exist_ok=True)
                for name in ("trace.log", "server-stderr.log"):
                    if (workdir / name).exists():
                        shutil.copyfile(workdir / name, opts.keep_trace / name)
        events = []
        if report.dynamic and target.sandbox:
            trace = workdir / "trace.log"
            if trace.exists():
                events = parse_trace(trace.read_text(errors="replace"))
            else:
                report.notes.append("no syscall trace was written; file and network checks did not run")
        elif report.dynamic:
            report.notes.append("not in a sandbox: file and network activity was not traced")
    report.findings = static.scan(report.snapshot)
    reported: set[tuple[str, str]] = set()
    for when, snap in session.relisted:
        for f in judge_relisting(report.snapshot, snap, when, session.notifications):
            key = (f.rule, f.where.removesuffix(f" ({when})"))
            if key not in reported:  # the same change seen again on a later listing
                reported.add(key)
                report.findings.append(f)
    if report.dynamic:
        report.findings += judge_calls(report.snapshot, report.calls, events, diff, traced=bool(target.sandbox))
    report.findings = static.dedupe(report.findings)
    report.findings.sort(key=lambda f: -f.severity)
    return report


@dataclass
class _Session:
    relisted: list[tuple[str, Snapshot]] = field(default_factory=list)
    notifications: list[tuple[float, str]] = field(default_factory=list)


async def _talk(
    target: Target, workdir: Path, run: SandboxRun | None, opts: Options, report: Report, session: _Session
) -> None:
    async with connect(target, workdir, run, opts.startup_timeout) as live:
        report.snapshot = await asyncio.wait_for(snapshot(live.session), opts.startup_timeout)
        session.relisted.append(("on an immediate second listing", await snapshot(live.session)))
        if opts.exercise:
            report.dynamic = True
            report.calls, notes = await exercise(live, report.snapshot, opts)
            report.notes += notes
            with contextlib.suppress(Exception):
                again = await asyncio.wait_for(snapshot(live.session), 15)
                session.relisted.append(("after the tools were called", again))
        session.notifications = list(live.notifications)
