"""BENIGN. Runs git, read-only: spawning a program is reported as info, not as a finding.

The first version ran plain `git status`, and mcp-audit caught it writing .git/index: status
refreshes the index's stat cache as a side effect. `--no-optional-locks` is git's documented
way to make it read-only, so both commands use it."""

import subprocess

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

server = MCPServer("git-lite")


@server.tool(
    description="Show the working tree status of a repository.",
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
def git_status(repo_path: str) -> str:
    r = subprocess.run(
        ["git", "-C", repo_path, "--no-optional-locks", "status", "--short", "--branch"], capture_output=True, text=True
    )
    return r.stdout or r.stderr


@server.tool(
    description="Show the last commits of a repository.",
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
def git_log(repo_path: str, max_count: int = 5) -> str:
    r = subprocess.run(
        ["git", "-C", repo_path, "--no-optional-locks", "log", f"--max-count={max_count}", "--oneline"],
        capture_output=True,
        text=True,
    )
    return r.stdout or r.stderr


if __name__ == "__main__":
    server.run(transport="stdio")
