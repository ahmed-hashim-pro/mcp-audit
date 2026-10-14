"""Running a server inside a throwaway Docker container, and reading what it did.

The container has no network (`--network none`), so a connection attempt fails, but the
attempt is still a system call that strace records. The image (docker/sandbox.Dockerfile)
plants credential files with a canary string in the root user's home and seeds /workspace;
`mcp-audit-run`, the image's entry point, starts the server under
`strace -f -ttt -y` writing to /audit/trace.log, which is a directory on the host.

Each syscall carries a wall-clock timestamp, so it can be pinned to the tool call that was
in flight when it happened. `docker diff` at the end lists every file the run changed, as a
cross-check on the trace.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import uuid
from dataclasses import dataclass, field
from pathlib import Path

CANARY = "MCPAUDIT-CANARY-7f3a9c"
SECRET_PATHS = (
    "/root/.ssh/",
    "/root/.aws/",
    "/root/.config/gcloud/",
    "/root/.netrc",
    "/root/.npmrc",
    "/root/.git-credentials",
    "/root/.docker/config.json",
    "/root/.kube/",
)
IGNORED_PREFIXES = ("/dev/", "/proc/", "/sys/", "/audit/", "/run/", "/var/run/")
TMP_PREFIXES = ("/tmp/", "/var/tmp/")


@dataclass(frozen=True)
class Event:
    ts: float
    pid: int
    kind: str  # write | delete | secret-read | connect | send | exec
    detail: str  # path, address or command line
    failed: bool = False
    errno: str = ""


@dataclass
class SandboxRun:
    image: str
    workdir: Path
    name: str = field(default_factory=lambda: f"mcp-audit-{uuid.uuid4().hex[:12]}")

    def docker_args(self, command: list[str]) -> list[str]:
        return [
            "run", "-i", "--name", self.name,
            "--network", "none",
            "--cap-add", "SYS_PTRACE",
            "--pids-limit", "512",
            "--memory", "2g",
            "-e", "UV_USE_IO_URING=0",
            "-v", f"{self.workdir}:/audit",
            self.image, "mcp-audit-run", *command,
        ]  # fmt: skip

    @property
    def trace_path(self) -> Path:
        return self.workdir / "trace.log"

    def finish(self) -> list[tuple[str, str]]:
        """Stop the container, list what it changed, remove it."""
        docker = shutil.which("docker") or "docker"
        subprocess.run([docker, "kill", self.name], capture_output=True, check=False)
        diff = subprocess.run([docker, "diff", self.name], capture_output=True, text=True, check=False)
        subprocess.run([docker, "rm", "-f", self.name], capture_output=True, check=False)
        return parse_diff(diff.stdout)


def docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    r = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"], capture_output=True, check=False)
    return r.returncode == 0


def image_exists(image: str) -> bool:
    r = subprocess.run(["docker", "image", "inspect", image], capture_output=True, check=False)
    return r.returncode == 0


# --- docker diff -------------------------------------------------------------------------------


def parse_diff(text: str) -> list[tuple[str, str]]:
    """`docker diff` lines ("A /x", "C /x", "D /x"), minus directories that only changed because a child did."""
    entries = []
    for line in text.splitlines():
        if len(line) > 2 and line[1] == " " and line[0] in "ACD":
            entries.append((line[0], line[2:]))
    paths = {p for _, p in entries}
    out = []
    for kind, p in entries:
        if kind == "C" and any(q.startswith(p.rstrip("/") + "/") for q in paths):
            continue
        if ignored(p) or p == "/audit":
            continue
        out.append((kind, p))
    return out


# --- strace ------------------------------------------------------------------------------------

_LINE = re.compile(r"^(\d+)\s+(\d+\.\d+)\s+(.*)$")
_CALL = re.compile(r"^([a-z_0-9]+)\((.*)$", re.S)
_RESUMED = re.compile(r"^<\.\.\. ([a-z_0-9]+) resumed>(.*)$", re.S)
_STRING = re.compile(r'"((?:[^"\\]|\\.)*)"')
_FD_PATH = re.compile(r"^\s*-?\d+<([^>]*)>")
_DIRFD = re.compile(r"^\s*(?:AT_FDCWD|\d+)<([^>]*)>")
_INET = re.compile(r'sin_port=htons\((\d+)\).*?sin_addr=inet_addr\("([^"]+)"\)')
_INET6 = re.compile(r'sin6_port=htons\((\d+)\).*?inet_pton\(AF_INET6,\s*"([^"]+)"')

_WRITE_FLAGS = re.compile(r"O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND")
_PATH_WRITES = {
    "creat", "mkdir", "mkdirat", "truncate", "chmod", "fchmodat", "fchmodat2", "chown", "lchown", "fchownat",
    "link", "linkat", "symlink", "symlinkat", "mknod", "mknodat",
}  # fmt: skip
_PATH_DELETES = {"unlink", "unlinkat", "rmdir"}
_RENAMES = {"rename", "renameat", "renameat2"}
_OPENS = {"open", "openat", "openat2"}

TRACED_SYSCALLS = sorted(
    _PATH_WRITES
    | _PATH_DELETES
    | _RENAMES
    | _OPENS
    | {"ftruncate", "connect", "sendto", "sendmsg", "execve", "execveat"}
)


def _unescape(s: str) -> str:
    try:
        return s.encode("latin-1", "backslashreplace").decode("unicode_escape")
    except UnicodeDecodeError:
        return s


def _resolve(path: str, args: str) -> str:
    if path.startswith("/"):
        return path
    m = _DIRFD.match(args)
    base = m.group(1) if m else ""
    return (base.rstrip("/") + "/" + path) if base else path


def ignored(path: str) -> bool:
    return (
        path.startswith(IGNORED_PREFIXES)
        or "/__pycache__/" in path
        or path.endswith((".pyc", "/__pycache__"))
        or path in ("/dev/null", "/dev/tty")
    )


def is_secret(path: str) -> bool:
    return path.startswith(SECRET_PATHS) or path.rstrip("/") in {p.rstrip("/") for p in SECRET_PATHS}


def parse_trace(text: str) -> list[Event]:
    pending: dict[int, tuple[str, str, float]] = {}
    events: list[Event] = []
    for raw in text.splitlines():
        m = _LINE.match(raw)
        if not m:
            continue
        pid, ts, body = int(m.group(1)), float(m.group(2)), m.group(3)
        if body.startswith(("---", "+++")):
            continue
        if r := _RESUMED.match(body):
            name = r.group(1)
            start = pending.pop(pid, None)
            if start is None or start[0] != name:
                continue
            body_full, ts = start[1] + r.group(2), start[2]
        elif c := _CALL.match(body):
            name = c.group(1)
            if body.endswith("<unfinished ...>"):
                pending[pid] = (name, c.group(2)[: -len("<unfinished ...>")].rstrip(), ts)
                continue
            body_full = c.group(2)
        else:
            continue
        args, sep, result = body_full.rpartition(") = ")
        if not sep:
            args, result = body_full, ""
        events += _classify(name, args, result.strip(), pid, ts)
    return events


def _classify(name: str, args: str, result: str, pid: int, ts: float) -> list[Event]:
    failed = result.startswith("-1")
    errno = result.split()[1] if failed and len(result.split()) > 1 else ""
    strings = [_unescape(s) for s in _STRING.findall(args)]

    def ev(kind: str, detail: str) -> Event:
        return Event(ts, pid, kind, detail, failed, errno)

    if name in _OPENS and strings:
        fd = _FD_PATH.match(result)
        path = fd.group(1) if fd else _resolve(strings[0], args)
        out = []
        if is_secret(path):
            out.append(ev("secret-read", path))
        if _WRITE_FLAGS.search(args) and not ignored(path):
            out.append(ev("write", path))
        return out
    if name in _PATH_WRITES and strings:
        path = _resolve(strings[0], args)
        return [] if ignored(path) else [ev("write", path)]
    if name == "ftruncate":
        fd = _FD_PATH.match(args)
        return [ev("write", fd.group(1))] if fd and not ignored(fd.group(1)) else []
    if name in _PATH_DELETES and strings:
        path = _resolve(strings[0], args)
        return [] if ignored(path) else [ev("delete", path)]
    if name in _RENAMES and len(strings) >= 2:
        src, dst = _resolve(strings[0], args), _resolve(strings[1], args)
        if ignored(src) and ignored(dst):
            return []
        return [ev("delete", src), ev("write", dst)]
    if name in ("connect", "sendto", "sendmsg"):
        addr = _address(args)
        if addr is None:
            return []
        out = [ev("connect" if name == "connect" else "send", addr)]
        if CANARY in args:
            out.append(ev("canary-sent", addr))
        return out
    if name in ("execve", "execveat") and strings:
        argv = re.search(r"\[(.*?)\]", args)
        shown = " ".join(_unescape(s) for s in _STRING.findall(argv.group(1))) if argv else strings[0]
        return [ev("exec", shown[:200])]
    return []


def _address(args: str) -> str | None:
    """host:port for an internet address; None for local sockets and loopback that isn't DNS."""
    if "AF_INET6" in args:
        m = _INET6.search(args)
        if not m:
            return None
        port, host = int(m.group(1)), m.group(2)
        if host in ("::1", "::") and port != 53:
            return None
        return f"[{host}]:{port}"
    if "AF_INET" in args:
        m = _INET.search(args)
        if not m:
            return None
        port, host = int(m.group(1)), m.group(2)
        if (host.startswith("127.") or host == "0.0.0.0") and port != 53:
            return None
        return f"{host}:{port}"
    return None
