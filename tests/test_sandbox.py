"""Reading strace output and docker diff, on lines in the exact shape strace -f -ttt -y writes."""

import re
from pathlib import Path

from mcp_audit.sandbox import CANARY, TRACED_SYSCALLS, SandboxRun, parse_diff, parse_trace

ROOT = Path(__file__).resolve().parent.parent

TRACE = r"""
7     1792019290.100000 openat(AT_FDCWD</workspace>, "notes.json", O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0666) = 3</workspace/notes.json>
7     1792019290.100100 openat(AT_FDCWD</workspace>, "/workspace/docs/readme.md", O_RDONLY|O_CLOEXEC) = 4</workspace/docs/readme.md>
7     1792019290.100200 openat(AT_FDCWD</>, "/root/.ssh/id_rsa", O_RDONLY|O_CLOEXEC) = 5</root/.ssh/id_rsa>
7     1792019290.100300 openat(AT_FDCWD</>, "/usr/lib/python3.11/__pycache__/x.cpython-311.pyc", O_WRONLY|O_CREAT, 0644) = 6</usr/lib/python3.11/__pycache__/x.cpython-311.pyc>
8     1792019290.100400 connect(9<socket:[1]>, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("203.0.113.7")}, 16 <unfinished ...>
7     1792019290.100450 unlink("/workspace/old.txt") = 0
8     1792019290.100500 <... connect resumed>) = -1 ENETUNREACH (Network is unreachable)
8     1792019290.100600 connect(9<socket:[2]>, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("127.0.0.1")}, 16) = 0
8     1792019290.100700 connect(9<socket:[3]>, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110) = -1 ENOENT (No such file or directory)
8     1792019290.100800 connect(9<socket:[4]>, {sa_family=AF_INET6, sin6_port=htons(53), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2001:db8::1", &sin6_addr), sin6_scope_id=0}, 28) = -1 ENETUNREACH (Network is unreachable)
8     1792019290.100900 sendto(9<socket:[5]>, "key=MCPAUDIT-CANARY-7f3a9c-ssh", 30, 0, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("192.0.2.1")}, 16) = -1 ENETUNREACH (Network is unreachable)
9     1792019290.101000 execve("/usr/bin/git", ["git", "status", "--short"], 0x7ffd /* 9 vars */) = 0
9     1792019290.101100 rename("/workspace/repo/.git/index.lock", "/workspace/repo/.git/index") = 0
9     1792019290.101200 mkdir("/workspace/new", 0777) = -1 EEXIST (File exists)
9     1792019290.101300 ftruncate(3</workspace/notes.json>, 0) = 0
9     1792019290.101400 openat(AT_FDCWD</>, "/dev/null", O_RDWR) = 3</dev/null>
9     1792019290.101500 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED} ---
9     1792019290.101600 +++ exited with 0 +++
"""


def test_parse_trace_classifies_every_kind() -> None:
    got = [(e.kind, e.detail, e.failed) for e in parse_trace(TRACE)]
    assert got == [
        ("write", "/workspace/notes.json", False),
        ("secret-read", "/root/.ssh/id_rsa", False),
        ("delete", "/workspace/old.txt", False),
        ("connect", "203.0.113.7:443", True),  # resumed line supplies the result
        ("connect", "[2001:db8::1]:53", True),
        ("send", "192.0.2.1:53", True),
        ("canary-sent", "192.0.2.1:53", True),
        ("exec", "git status --short", False),
        ("delete", "/workspace/repo/.git/index.lock", False),
        ("write", "/workspace/repo/.git/index", False),
        ("write", "/workspace/new", True),
        ("write", "/workspace/notes.json", False),
    ]
    assert CANARY in TRACE


def test_relative_paths_resolve_against_the_dirfd() -> None:
    line = '5 1.000000 openat(AT_FDCWD</workspace/repo>, ".git/config.lock", O_WRONLY|O_CREAT|O_EXCL, 0666) = -1 EEXIST (File exists)'
    [e] = parse_trace(line)
    assert (e.kind, e.detail, e.failed, e.errno) == ("write", "/workspace/repo/.git/config.lock", True, "EEXIST")


def test_unfinished_calls_from_two_pids_interleave() -> None:
    text = "\n".join(
        [
            '1 1.0 openat(AT_FDCWD</>, "/workspace/a", O_WRONLY|O_CREAT, 0666 <unfinished ...>',
            '2 1.1 openat(AT_FDCWD</>, "/workspace/b", O_WRONLY|O_CREAT, 0666 <unfinished ...>',
            "1 1.2 <... openat resumed>) = 3</workspace/a>",
            "2 1.3 <... openat resumed>) = -1 EACCES (Permission denied)",
        ]
    )
    got = [(e.detail, e.failed, e.ts) for e in parse_trace(text)]
    assert got == [("/workspace/a", False, 1.0), ("/workspace/b", True, 1.1)]


def test_garbage_lines_are_ignored() -> None:
    assert parse_trace("not strace\n\n12 abc nonsense\n3 1.5 <... read resumed>) = 1") == []


def test_parse_diff_drops_parents_and_noise() -> None:
    diff = "C /workspace\nA /workspace/notes.json\nC /root\nC /root/.cache\nA /root/.cache/x\nC /audit\nD /tmp/old\nC /proc/x"
    assert parse_diff(diff) == [("A", "/workspace/notes.json"), ("A", "/root/.cache/x"), ("D", "/tmp/old")]


def test_launcher_traces_exactly_the_syscalls_the_parser_reads() -> None:
    script = (ROOT / "docker/mcp-audit-run").read_text()
    listed = re.search(r"-e trace=(\S+)", script)
    assert listed is not None
    assert sorted(s.lstrip("?") for s in listed.group(1).split(",")) == TRACED_SYSCALLS


def test_container_has_no_network_and_mounts_only_the_audit_dir(tmp_path: Path) -> None:
    args = SandboxRun("img", tmp_path, name="n").docker_args(["srv", "--flag"])
    assert args[args.index("--network") + 1] == "none"
    assert [a for a in args if a.startswith(str(tmp_path))] == [f"{tmp_path}:/audit"]
    assert args[-4:] == ["img", "mcp-audit-run", "srv", "--flag"]
    assert "--privileged" not in args
