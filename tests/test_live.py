"""Real MCP sessions through the official SDK: stdio servers on this machine, and streamable HTTP.

These run the corpus servers on the host, which is safe because they are ours and the calls
here are only listings; tool calls on the host need --unsafe-host-calls and are refused otherwise.
"""

import asyncio
import json
import socket
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from conftest import CORPUS, PY, ROOT

from mcp_audit.cli import main
from mcp_audit.scan import ConnectError, Options, Target, audit


def corpus(name: str) -> list[str]:
    return ["--", PY, str(CORPUS / f"{name}.py")]


def test_poisoned_server_fails_the_scan(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", *corpus("poisoned_add")]) == 1
    out = capsys.readouterr().out
    assert "server   calculator" in out and "injection.exfil-param" in out


def test_clean_server_passes(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", "--fail-on", "medium", *corpus("clean_calc")]) == 0
    assert "0 high, 0 medium" in capsys.readouterr().out


def test_relisting_catches_a_silent_rug_pull_without_calling_anything() -> None:
    report = asyncio.run(audit(Target(command=[PY, str(CORPUS / "flip_on_relist.py")]), Options()))
    assert not report.calls
    assert "rug-pull.changed" in {f.rule for f in report.findings}


def test_calling_tools_on_the_host_needs_explicit_consent() -> None:
    with pytest.raises(ConnectError, match="--sandbox"):
        asyncio.run(audit(Target(command=[PY, str(CORPUS / "clean_calc.py")]), Options(exercise=True)))


def test_unsafe_host_calls_exercise_and_catch_a_rug_pull() -> None:
    target = Target(command=[PY, str(CORPUS / "rug_pull.py")])
    report = asyncio.run(audit(target, Options(exercise=True, unsafe_host_calls=True)))
    assert [c.tool for c in report.calls] == ["get_fact_of_the_day"]
    assert "rug-pull.changed" in {f.rule for f in report.findings}
    assert any("not traced" in n for n in report.notes)


def test_calls_file_overrides_synthesised_arguments(tmp_path: Path) -> None:
    calls = tmp_path / "calls.json"
    calls.write_text(json.dumps({"add": {"a": 40, "b": 2}, "divide": [{"a": 1, "b": 4}, {"a": 1, "b": 0}]}))
    target = Target(command=[PY, str(CORPUS / "clean_calc.py")])
    report = asyncio.run(
        audit(
            target,
            Options(
                exercise=True,
                unsafe_host_calls=True,
                calls={"add": [{"a": 40, "b": 2}], "divide": [{"a": 1, "b": 4}, {"a": 1, "b": 0}]},
            ),
        )
    )
    assert [(c.tool, c.output, c.is_error) for c in report.calls][:2] == [
        ("add", "42", False),
        ("divide", "0.25", False),
    ]
    assert report.calls[2].is_error  # division by zero comes back as a tool error, not a crash


def test_snapshot_command_prints_the_wire_format(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["snapshot", *corpus("schema_poison")]) == 0
    snap = json.loads(capsys.readouterr().out)
    [tool] = snap["tools"]
    assert tool["annotations"] == {"readOnlyHint": True, "openWorldHint": False}
    assert "conversation history" in tool["inputSchema"]["properties"]["context"]["description"]


def test_a_server_that_will_not_start_is_reported(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", "--", PY, "-c", "import sys; print('boom', file=sys.stderr); sys.exit(3)"]) == 2
    assert "could not initialize" in capsys.readouterr().err


@pytest.fixture
def http_server() -> Iterator[str]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    proc = subprocess.Popen([PY, str(ROOT / "tests/servers/http_server.py"), str(port)], stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        proc.terminate()
        proc.wait(10)


def test_streamable_http(http_server: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", "--url", http_server]) == 1
    out = capsys.readouterr().out
    assert "server   http-demo" in out
    assert "injection.exfil-param  tool count_words, description" in out
    assert "annotations.missing" not in out  # info is hidden by default
