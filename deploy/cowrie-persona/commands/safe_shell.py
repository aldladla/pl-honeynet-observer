# SPDX-License-Identifier: MIT

"""Narrow, no-execution emulation for a common shell capability probe.

Some automated campaigns test whether a newly created shell script can be
written, marked executable, run, and removed before deciding whether to send a
payload.  Cowrie can parse that sequence, but nested ``bash -c`` invocations
are needlessly expensive and their result is otherwise hard to distinguish
from ordinary command input.

This module recognizes only the observed, harmless ``filter`` self-test and
returns its marker directly.  It never creates a file or executes a script.
Every other shell invocation is delegated to Cowrie's original implementation.
"""

from __future__ import annotations

from datetime import UTC, datetime

from cowrie.commands.bash import Command_sh as CowrieCommandSh
from cowrie.commands.persona_v2 import emulate, persona_state, synthetic_proc_uptime
from cowrie.shell.honeypot import HoneyPotShell

commands = {}

MAX_PROBE_LENGTH = 2048
MAX_FULL_PROBE_LENGTH = 32_768
PROBE_MARKER = "xxxxxx"
_FORBIDDEN_FRAGMENTS = (
    "$(",
    "`",
    "curl ",
    "wget ",
    "scp ",
    "sftp ",
    "tftp ",
    "ftpget ",
    "nc ",
    "ncat ",
    "ssh ",
    "/dev/tcp",
    "/dev/udp",
)

_FULL_PROBE_FORBIDDEN_FRAGMENTS = tuple(
    fragment for fragment in _FORBIDDEN_FRAGMENTS if fragment != "$("
)

_FULL_PROBE_ANCHORS = (
    "uname=$(",
    "arch=$(",
    "uptime=$(",
    "cpus=$(",
    "cpu_model=$(",
    "gpu_info=$(",
    "last_output=$(",
    "filter_output=$(",
    "===shell_behavior===",
    "execute_err=",
    "echo uname:$uname",
    "echo arch:$arch",
    "echo uptime:$uptime",
    "echo cpus:$cpus",
    "echo cpu_model:$cpu_model",
    "echo gpu:$gpu_info",
    "echo last:$last_output",
    "echo filter:$filter_output",
)


def extract_c_script(args: list[str]) -> str | None:
    """Return the script passed through ``sh -c``, matching Cowrie quoting."""
    if not args or args[0].strip() != "-c" or len(args) < 2:
        return None

    script = " ".join(args[1:]).strip()
    if len(script) >= 2 and script[0] == script[-1] and script[0] in {"'", '"'}:
        script = script[1:-1]
    return script


def is_safe_filter_probe(script: str) -> bool:
    """Recognize only the observed write/chmod/run/remove capability test."""
    if not script or len(script) > MAX_PROBE_LENGTH:
        return False

    normalized = " ".join(script.split()).lower()
    if any(fragment in normalized for fragment in _FORBIDDEN_FRAGMENTS):
        return False
    if not normalized.startswith("printf "):
        return False
    if PROBE_MARKER not in normalized:
        return False

    steps = (
        "> filter",
        "chmod +x filter",
        "./filter",
        "rm -rf filter",
    )
    position = 0
    for step in steps:
        next_position = normalized.find(step, position)
        if next_position < 0:
            return False
        position = next_position + len(step)

    # A full match at the tail prevents an unrelated command from being hidden
    # behind the recognized probe.  Whitespace and a final semicolon are benign.
    tail = normalized[position:].strip()
    return tail in {"", ";"}


def is_full_host_capability_probe(line: str) -> bool:
    """Match only the complete inventory probe observed in the live campaign."""
    if not line or len(line) > MAX_FULL_PROBE_LENGTH:
        return False

    normalized = line.strip().lower()
    # Windows OpenSSH removes the presentation-only double quotes surrounding
    # ``echo NAME:$variable`` when it constructs the remote exec request.  The
    # campaign form seen by Cowrie may therefore be quoted or bare, while its
    # shell semantics remain identical.
    canonical = normalized.replace('"', "")
    if any(fragment in normalized for fragment in _FULL_PROBE_FORBIDDEN_FRAGMENTS):
        return False
    if not all(anchor in canonical for anchor in _FULL_PROBE_ANCHORS):
        return False
    if "chmod +x filter" not in normalized or "rm -rf filter" not in normalized:
        return False

    # The inventory report must be the final action. Appended input is not
    # swallowed by this fast path and continues through Cowrie's normal parser.
    final_action = canonical.rstrip(";").rstrip()
    return final_action.endswith("echo filter:$filter_output")


def full_probe_response(*, state: object | None = None, now: datetime | None = None) -> str:
    """Return the complete, mutually consistent report expected by the probe."""
    effective_now = now or datetime.now(UTC)
    uname = emulate(
        "uname", ["-s", "-v", "-n", "-m"], state=state, now=effective_now
    ).stdout.strip()
    arch = emulate("uname", ["-m"], state=state, now=effective_now).stdout.strip()
    cpus = emulate("nproc", [], state=state, now=effective_now).stdout.strip()
    cpu_model = "Intel(R) Xeon(R) Gold 6140 CPU @ 2.30GHz"
    gpu = (
        "00:02.0 VGA compatible controller: Red Hat, Inc. Virtio GPU (rev 01)\n"
        "00:04.0 3D controller: NVIDIA Corporation TU104GL [Tesla T4] (rev a1)"
    )
    last = emulate("last", [], state=state, now=effective_now).stdout.rstrip("\n")
    proc_uptime = synthetic_proc_uptime(state=state, now=effective_now)
    filter_output = (
        "===SHELL_BEHAVIOR===\n"
        "path_err=-bash: ./xxxxxx: No such file or directory\n"
        "cmd_err=-bash: xxxxxx: command not found\n"
        "execute_err=xxxxxx\n"
        "===DONE==="
    )
    return (
        f"UNAME:{uname}\n"
        f"ARCH:{arch}\n"
        f"UPTIME:{proc_uptime}\n"
        f"CPUS:{cpus}\n"
        f"CPU_MODEL:{cpu_model}\n"
        f"GPU:{gpu}\n"
        f"LAST:{last}\n"
        f"FILTER:{filter_output}\n"
    )


_original_line_received = HoneyPotShell.lineReceived


def _persona_line_received(self: HoneyPotShell, line: str) -> None:
    """Fast-path the exact inventory probe and delegate every other line."""
    if not is_full_host_capability_probe(line):
        _original_line_received(self, line)
        return

    now = datetime.now(UTC)
    state = persona_state(self.protocol)
    stdout = full_probe_response(state=state, now=now)
    self.protocol.events.dispatch("cowrie.command.input", "CMD: %(input)s", input=line)
    self.protocol.events.dispatch(
        "cowrie.command.output.emulated",
        "Emulated complete host capability probe with exit code 0",
        tool="host-capability-probe",
        input="host-capability-probe",
        stdout=stdout,
        stderr="",
        exit_code=0,
        emulated=True,
        probe="complete_host_capability_inventory",
    )
    self.protocol.terminal.write(stdout.encode("utf-8"))
    self.last_exit_code = 0
    self._finish()


_persona_line_received._plhn_persona_v22 = True  # type: ignore[attr-defined]
if not getattr(HoneyPotShell.lineReceived, "_plhn_persona_v22", False):
    HoneyPotShell.lineReceived = _persona_line_received


class Command_safe_sh(CowrieCommandSh):
    """Fast-path the safe probe and delegate every other command to Cowrie."""

    def start(self) -> None:
        script = extract_c_script(self.args)
        if script is None or not is_safe_filter_probe(script):
            super().start()
            return

        stdout = f"{PROBE_MARKER}\n"
        self.protocol.events.dispatch(
            "cowrie.command.output.emulated",
            "Emulated shell capability probe completed with exit code 0",
            tool="shell-self-test",
            input=f"sh -c {script}"[:MAX_PROBE_LENGTH],
            stdout=stdout,
            stderr="",
            exit_code=0,
            emulated=True,
            probe="write_chmod_execute_cleanup",
        )
        self.write(stdout)
        self.exit_code = 0
        self.exit()


for name in ("bash", "/bin/bash", "/usr/bin/bash", "sh", "/bin/sh", "/usr/bin/sh"):
    commands[name] = Command_safe_sh
