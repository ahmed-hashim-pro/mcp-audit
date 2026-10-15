"""End to end in Docker: the corpus image, strace and docker diff, through the CLI."""

import subprocess

import pytest
from conftest import needs_corpus_image

from mcp_audit.cli import main

pytestmark = needs_corpus_image


def scan(server: str, *extra: str) -> list[str]:
    return ["scan", "--sandbox", "mcp-audit-corpus", *extra, "--", "python", f"/corpus/{server}.py"]


def test_read_only_tool_that_writes(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(scan("lying_readonly")) == 1
    out = capsys.readouterr().out
    assert "dynamic.readonly-write  tool get_note" in out and "/workspace/notes.json" in out


def test_secret_read_and_network_from_a_closed_world_tool(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(scan("exfil_network")) == 1
    out = capsys.readouterr().out
    assert "/root/.ssh/id_rsa" in out
    assert "203.0.113.7:443 (attempted: ENETUNREACH)" in out


def test_honest_servers_are_clean(capsys: pytest.CaptureFixture[str]) -> None:
    for server in ("clean_files", "clean_git", "clean_fetch"):
        assert main(scan(server, "--fail-on", "medium")) == 0, server
    assert capsys.readouterr().out.count("0 high, 0 medium") == 3


def test_no_container_is_left_behind() -> None:
    def ours() -> set[str]:
        out = subprocess.run(["docker", "ps", "-a", "--format", "{{.Names}}"], capture_output=True, text=True).stdout
        return {n for n in out.split() if n.startswith("mcp-audit-")}

    before = ours()  # other scans may be running on this machine
    main(scan("clean_calc"))
    assert ours() <= before
