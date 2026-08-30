# SPDX-License-Identifier: MIT

"""Host-consistent, no-network command emulation for the build-worker persona.

Every response is synthetic.  The module neither imports networking clients nor
invokes host commands.  Beside writing the response to the emulated terminal it
emits a bounded telemetry event describing exactly what the remote side saw.

The identity and host metrics are stable across reconnects, while time, uptime,
load and memory pressure advance in small deterministic steps. Every session
observes the same synthetic host at a given instant and no host metrics are ever
read.
"""

from __future__ import annotations

import hashlib
import math
import shlex
from dataclasses import dataclass
from datetime import UTC, datetime

from cowrie.shell.command import HoneyPotCommand

commands = {}

HOSTNAME = "app-prod-01"
KERNEL_RELEASE = "6.1.0-21-amd64"
KERNEL_VERSION = "#1 SMP PREEMPT_DYNAMIC Debian 6.1.90-1 (2024-05-03)"
MACHINE = "x86_64"
MAX_TELEMETRY_TEXT = 8192
BOOT_TIME = datetime(2026, 7, 18, 11, 23, 41, tzinfo=UTC)
HOST_METRIC_SEED = int.from_bytes(
    hashlib.sha256(f"{HOSTNAME}|debian-build-worker".encode()).digest()[:4], "big"
)
HOST_METRIC_PHASE = (HOST_METRIC_SEED % 360) * math.pi / 180.0
CPU_COUNT = 8
LOAD_ONE_BASE = 0.23
LOAD_ONE_AMPLITUDE = 0.09
LOAD_ONE_PERIOD_SECONDS = 360.0


@dataclass(frozen=True)
class PersonaState:
    """Stable, non-sensitive seed used to vary one emulated SSH session."""

    seed: int = 0


@dataclass(frozen=True)
class EmulatedResult:
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0


DEFAULT_STATE = PersonaState()


def persona_state(protocol: object) -> PersonaState:
    """Return one stable synthetic state for the lifetime of a protocol."""
    existing = getattr(protocol, "_plhn_persona_state", None)
    if isinstance(existing, PersonaState):
        return existing

    identity = next(
        (
            str(value)
            for name in ("sessionno", "session_id", "uuid")
            if (value := getattr(protocol, name, None)) is not None
        ),
        f"protocol-{id(protocol)}",
    )
    digest = hashlib.sha256(identity.encode("utf-8", errors="replace")).digest()
    state = PersonaState(seed=int.from_bytes(digest[:4], "big"))
    protocol._plhn_persona_state = state  # type: ignore[attr-defined]
    return state


def _utc_now(now: datetime | None) -> datetime:
    if now is None:
        return datetime.now(UTC)
    if now.tzinfo is None:
        return now.replace(tzinfo=UTC)
    return now.astimezone(UTC)


def _uptime_seconds(now: datetime) -> int:
    return max(0, int((now - BOOT_TIME).total_seconds()))


def _load_values(_state: PersonaState, now: datetime) -> tuple[float, float, float]:
    """Generate one host-wide, smooth and reproducible load history."""
    elapsed = float(_uptime_seconds(now))
    phase = HOST_METRIC_PHASE
    one = LOAD_ONE_BASE + LOAD_ONE_AMPLITUDE * math.sin(
        elapsed / LOAD_ONE_PERIOD_SECONDS + phase
    )
    five = 0.20 + 0.06 * math.sin(elapsed / 900.0 + phase / 2.0)
    fifteen = 0.18 + 0.04 * math.sin(elapsed / 1_920.0 + phase / 3.0)
    return tuple(max(0.05, value) for value in (one, five, fifteen))


def _memory_mib(
    _state: PersonaState, now: datetime
) -> tuple[int, int, int, int, int, int]:
    """Return host-wide memory values with exact accounting."""
    total = 15_996
    minute = _uptime_seconds(now) / 60.0
    phase = HOST_METRIC_PHASE
    used = 3_620 + round(240 * math.sin(minute / 19.0 + phase))
    cache = 4_120 + round(150 * math.sin(minute / 37.0 + phase / 2.0))
    shared = 146 + round(18 * math.sin(minute / 11.0 + phase / 4.0))
    free = total - used - cache
    available = free + round(cache * 0.9)
    return total, used, free, shared, cache, available


def synthetic_proc_uptime(
    state: PersonaState | None = None, now: datetime | None = None
) -> str:
    """Return synthetic /proc/uptime content without reading the host."""
    effective_now = _utc_now(now)
    uptime = float(_uptime_seconds(effective_now))
    # /proc/uptime's second field is cumulative idle time over all CPUs.  It
    # must never decrease.  Integrating the synthetic one-minute load gives a
    # smooth cumulative busy time without leaking or sampling host metrics.
    busy = (
        LOAD_ONE_BASE * uptime
        + LOAD_ONE_AMPLITUDE
        * LOAD_ONE_PERIOD_SECONDS
        * (
            math.cos(HOST_METRIC_PHASE)
            - math.cos(uptime / LOAD_ONE_PERIOD_SECONDS + HOST_METRIC_PHASE)
        )
    )
    idle = max(0.0, CPU_COUNT * uptime - busy)
    return f"{uptime:.2f} {idle:.2f}"


def _uname(args: list[str]) -> EmulatedResult:
    if not args:
        return EmulatedResult("Linux\n")
    if "--help" in args:
        return EmulatedResult("Usage: uname [OPTION]...\nPrint system information.\n")
    if "--version" in args:
        return EmulatedResult("uname (GNU coreutils) 9.1\n")

    flags = "".join(arg[1:] for arg in args if arg.startswith("-") and not arg.startswith("--"))
    if "a" in flags:
        flags = "snrvmpio"
    if not flags or any(flag not in "snrvmpio" for flag in flags):
        bad = next((arg for arg in args if not arg.startswith("-")), args[-1])
        return EmulatedResult(stderr=f"uname: extra operand '{bad}'\n", exit_code=1)

    # GNU uname prints fields in this fixed order, independent of option order.
    values = {
        "s": "Linux",
        "n": HOSTNAME,
        "r": KERNEL_RELEASE,
        "v": KERNEL_VERSION,
        "m": MACHINE,
        "p": MACHINE,
        "i": MACHINE,
        "o": "GNU/Linux",
    }
    ordered = [values[flag] for flag in "snrvmpio" if flag in flags]
    return EmulatedResult(" ".join(ordered) + "\n")


def _nproc(args: list[str]) -> EmulatedResult:
    if "--version" in args:
        return EmulatedResult("nproc (GNU coreutils) 9.1\n")
    return EmulatedResult("8\n")


def _lscpu(_args: list[str]) -> EmulatedResult:
    return EmulatedResult(
        "Architecture:                         x86_64\n"
        "CPU op-mode(s):                       32-bit, 64-bit\n"
        "Address sizes:                        46 bits physical, 48 bits virtual\n"
        "Byte Order:                           Little Endian\n"
        "CPU(s):                               8\n"
        "On-line CPU(s) list:                  0-7\n"
        "Vendor ID:                            GenuineIntel\n"
        "Model name:                           Intel(R) Xeon(R) Gold 6140 CPU @ 2.30GHz\n"
        "Thread(s) per core:                   2\n"
        "Core(s) per socket:                   4\n"
        "Socket(s):                            1\n"
        "Virtualization:                       VT-x\n"
        "Hypervisor vendor:                    KVM\n"
        "Virtualization type:                  full\n"
    )


def _free(args: list[str], state: PersonaState, now: datetime) -> EmulatedResult:
    total, used, free, shared, cache, available = _memory_mib(state, now)
    if "-m" in args:
        return EmulatedResult(
            "               total        used        free      shared  buff/cache   available\n"
            f"Mem:           {total:5d}        {used:4d}        {free:4d}         "
            f"{shared:3d}        {cache:4d}       {available:5d}\n"
            "Swap:           2047           0        2047\n"
        )
    if "-h" in args:
        return EmulatedResult(
            "               total        used        free      shared  buff/cache   available\n"
            f"Mem:          {total / 1024:5.1f}Gi     {used / 1024:5.1f}Gi     "
            f"{free / 1024:5.1f}Gi       {shared:3d}Mi     {cache / 1024:5.1f}Gi     "
            f"{available / 1024:5.1f}Gi\n"
            "Swap:          2.0Gi          0B       2.0Gi\n"
        )
    values = (value * 1024 for value in (total, used, free, shared, cache, available))
    total_kib, used_kib, free_kib, shared_kib, cache_kib, available_kib = values
    return EmulatedResult(
        "               total        used        free      shared  buff/cache   available\n"
        f"Mem:        {total_kib:8d}     {used_kib:7d}     {free_kib:7d}      "
        f"{shared_kib:6d}     {cache_kib:7d}    {available_kib:8d}\n"
        "Swap:        2097148           0     2097148\n"
    )


def _df(args: list[str]) -> EmulatedResult:
    human = "-h" in args or "-H" in args
    if human:
        return EmulatedResult(
            "Filesystem      Size  Used Avail Use% Mounted on\n"
            "/dev/vda1        78G   26G   49G  35% /\n"
            "tmpfs           7.9G     0  7.9G   0% /dev/shm\n"
            "tmpfs           3.2G  1.3M  3.2G   1% /run\n"
            "overlay          78G   26G   49G  35% /var/lib/docker/overlay2\n"
        )
    return EmulatedResult(
        "Filesystem     1K-blocks     Used Available Use% Mounted on\n"
        "/dev/vda1       81788928 27262976  51118080  35% /\n"
        "tmpfs            8189952        0   8189952   0% /dev/shm\n"
    )


def _uptime(args: list[str], state: PersonaState, now: datetime) -> EmulatedResult:
    elapsed = _uptime_seconds(now)
    days, remainder = divmod(elapsed, 86_400)
    hours, remainder = divmod(remainder, 3_600)
    minutes = remainder // 60
    if "-p" in args or "--pretty" in args:
        return EmulatedResult(f"up {days} days, {hours} hours, {minutes} minutes\n")
    if "-s" in args or "--since" in args:
        return EmulatedResult(f"{BOOT_TIME:%Y-%m-%d %H:%M:%S}\n")
    load_one, load_five, load_fifteen = _load_values(state, now)
    return EmulatedResult(
        f" {now:%H:%M:%S} up {days} days, {hours:2d}:{minutes:02d},  1 user,  "
        f"load average: {load_one:.2f}, {load_five:.2f}, {load_fifteen:.2f}\n"
    )


def _date(args: list[str], _state: PersonaState, now: datetime) -> EmulatedResult:
    effective_args = [arg for arg in args if arg not in {"-u", "--utc"}]
    if not effective_args:
        return EmulatedResult(f"{now:%a %b %d %H:%M:%S UTC %Y}\n")
    if len(effective_args) == 1:
        formats = {
            "+%s": str(int(now.timestamp())),
            "+%F": now.strftime("%Y-%m-%d"),
            "+%T": now.strftime("%H:%M:%S"),
            "+%F %T": now.strftime("%Y-%m-%d %H:%M:%S"),
            "+%FT%TZ": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        if effective_args[0] in formats:
            return EmulatedResult(formats[effective_args[0]] + "\n")
    return EmulatedResult(
        stderr=f"date: invalid date option '{' '.join(effective_args)}'\n", exit_code=1
    )


def _lspci(_args: list[str]) -> EmulatedResult:
    return EmulatedResult(
        "00:00.0 Host bridge: Intel Corporation 440FX - 82441FX PMC [Natoma]\n"
        "00:01.0 ISA bridge: Intel Corporation 82371SB PIIX3 ISA [Natoma/Triton II]\n"
        "00:02.0 VGA compatible controller: Red Hat, Inc. Virtio GPU (rev 01)\n"
        "00:03.0 Ethernet controller: Red Hat, Inc. Virtio network device\n"
        "00:04.0 3D controller: NVIDIA Corporation TU104GL [Tesla T4] (rev a1)\n"
    )


def _last(_args: list[str]) -> EmulatedResult:
    return EmulatedResult(
        "deploy   pts/0        192.0.2.44      Fri Aug 28 08:17 - 08:42  (00:25)\n"
        "deploy   pts/0        192.0.2.44      Thu Aug 27 16:03 - 16:19  (00:16)\n"
        "reboot   system boot  6.1.0-21-amd64 Fri Jul 18 11:23   still running\n"
        "\nwtmp begins Fri Jul 18 11:23:41 2026\n"
    )


def _ps(args: list[str]) -> EmulatedResult:
    wide = any("a" in arg or "f" in arg for arg in args if arg.startswith("-")) or "aux" in args
    if wide:
        return EmulatedResult(
            "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
            "root           1  0.0  0.1 169436 12384 ?        Ss   Jul18   0:19 /sbin/init\n"
            "root         612  0.0  0.2  15420  8960 ?        Ss   Jul18   1:47 /usr/sbin/sshd -D\n"
            "root         744  0.2  1.4 1849204 229120 ?      Ssl  Jul18 126:08 dockerd -H fd://\n"
            "deploy      1186  0.3  2.1 1248300 352768 ?      Ssl  Jul18 181:33 node /opt/app/server.js\n"
            "postgres    1224  0.1  0.8  219880 133120 ?      Ss   Jul18  54:02 postgres\n"
        )
    return EmulatedResult(
        "    PID TTY          TIME CMD\n"
        "   4021 pts/0    00:00:00 bash\n"
        "   4058 pts/0    00:00:00 ps\n"
    )


def _docker(args: list[str], _state: PersonaState, now: datetime) -> EmulatedResult:
    if not args or args[0] in {"--version", "-v"}:
        return EmulatedResult("Docker version 27.5.1, build 9f9e405\n")
    if args[0] == "version":
        return EmulatedResult(
            "Client: Docker Engine - Community\n Version:           27.5.1\n"
            "Server: Docker Engine - Community\n Engine:\n  Version:          27.5.1\n"
        )
    if args[0] in {"ps", "container"}:
        days = _uptime_seconds(now) // 86_400
        return EmulatedResult(
            "CONTAINER ID   IMAGE                 COMMAND                  STATUS         NAMES\n"
            f"81c5a77031c2   app-worker:2026.08    \"node server.js\"       Up {days} days     app-worker-1\n"
            f"24ab0923f173   postgres:16-alpine    \"docker-entrypoint.s\"   Up {days} days     app-db-1\n"
        )
    if args[0] == "images":
        return EmulatedResult(
            "REPOSITORY    TAG         IMAGE ID       CREATED        SIZE\n"
            "app-worker   2026.08     77d4cc8c74e1   3 weeks ago    1.18GB\n"
            "postgres     16-alpine   8b2f9f1f623e   4 weeks ago    243MB\n"
        )
    if args[0] == "info":
        return EmulatedResult(
            "Containers: 2\n Running: 2\n Images: 5\n Server Version: 27.5.1\n"
            "Storage Driver: overlay2\n Cgroup Driver: systemd\n"
        )
    return EmulatedResult(stderr=f"docker: '{args[0]}' is not a docker command.\n", exit_code=1)


def _systemctl(args: list[str], _state: PersonaState, now: datetime) -> EmulatedResult:
    if not args:
        return EmulatedResult(stderr="Too few arguments.\n", exit_code=1)
    if args[0] == "is-system-running":
        return EmulatedResult("running\n")
    if args[0] in {"list-units", "--type=service"}:
        return EmulatedResult(
            "  UNIT                       LOAD   ACTIVE SUB     DESCRIPTION\n"
            "  app-worker.service         loaded active running Application build worker\n"
            "  docker.service             loaded active running Docker Application Container Engine\n"
            "  postgresql.service         loaded active running PostgreSQL RDBMS\n"
            "  ssh.service                loaded active running OpenBSD Secure Shell server\n"
        )
    if args[0] in {"status", "show", "is-active"}:
        unit = args[1] if len(args) > 1 else "app-worker.service"
        if args[0] == "is-active":
            return EmulatedResult("active\n")
        days = _uptime_seconds(now) // 86_400
        return EmulatedResult(
            f"● {unit} - Application build worker\n"
            "     Loaded: loaded (/etc/systemd/system/app-worker.service; enabled)\n"
            f"     Active: active (running) since Fri 2026-07-18 11:23:49 UTC; {days} days ago\n"
            "   Main PID: 1186 (node)\n"
        )
    return EmulatedResult(stderr="System has not been booted with requested operation.\n", exit_code=1)


def _nvidia_smi(_args: list[str]) -> EmulatedResult:
    return EmulatedResult(
        "NVIDIA-SMI 550.54.15    Driver Version: 550.54.15    CUDA Version: 12.4\n"
        "GPU  Name        Persistence-M | Bus-Id        Disp.A | Volatile Uncorr. ECC\n"
        "  0  Tesla T4               Off | 00000000:00:04.0 Off |                    0\n"
    )


EMULATORS = {
    "uname": _uname,
    "nproc": _nproc,
    "lscpu": _lscpu,
    "free": _free,
    "df": _df,
    "uptime": _uptime,
    "date": _date,
    "lspci": _lspci,
    "last": _last,
    "ps": _ps,
    "docker": _docker,
    "systemctl": _systemctl,
    "nvidia-smi": _nvidia_smi,
}


_DYNAMIC_EMULATORS = {"free", "uptime", "date", "docker", "systemctl"}


def emulate(
    tool: str,
    args: list[str],
    *,
    state: PersonaState | None = None,
    now: datetime | None = None,
) -> EmulatedResult:
    emulator = EMULATORS.get(tool)
    if emulator is None:
        return EmulatedResult(stderr=f"{tool}: command not found\n", exit_code=127)
    if tool in _DYNAMIC_EMULATORS:
        return emulator(args, state or DEFAULT_STATE, _utc_now(now))
    return emulator(args)


class _PersonaCommand(HoneyPotCommand):
    tool = "command"

    def call(self) -> None:
        result = emulate(self.tool, self.args, state=persona_state(self.protocol))
        command = shlex.join([self.tool, *self.args])
        self.protocol.events.dispatch(
            "cowrie.command.output.emulated",
            "Emulated %(tool)s completed with exit code %(exit_code)d",
            tool=self.tool,
            input=command,
            stdout=result.stdout[:MAX_TELEMETRY_TEXT],
            stderr=result.stderr[:MAX_TELEMETRY_TEXT],
            exit_code=result.exit_code,
            emulated=True,
        )
        if result.stdout:
            self.write(result.stdout)
        if result.stderr:
            self.errorWrite(result.stderr)
        self.exit_code = result.exit_code


class Command_uname(_PersonaCommand):
    tool = "uname"


class Command_nproc(_PersonaCommand):
    tool = "nproc"


class Command_lscpu(_PersonaCommand):
    tool = "lscpu"


class Command_free(_PersonaCommand):
    tool = "free"


class Command_df(_PersonaCommand):
    tool = "df"


class Command_uptime(_PersonaCommand):
    tool = "uptime"


class Command_date(_PersonaCommand):
    tool = "date"


class Command_lspci(_PersonaCommand):
    tool = "lspci"


class Command_last(_PersonaCommand):
    tool = "last"


class Command_ps(_PersonaCommand):
    tool = "ps"


class Command_docker(_PersonaCommand):
    tool = "docker"


class Command_systemctl(_PersonaCommand):
    tool = "systemctl"


class Command_nvidia_smi(_PersonaCommand):
    tool = "nvidia-smi"


def _register(names: tuple[str, ...], command_class: type[_PersonaCommand]) -> None:
    for name in names:
        commands[name] = command_class


_register(("uname", "/bin/uname", "/usr/bin/uname", "/bin/./uname"), Command_uname)
_register(("nproc", "/usr/bin/nproc"), Command_nproc)
_register(("lscpu", "/usr/bin/lscpu"), Command_lscpu)
_register(("free", "/usr/bin/free"), Command_free)
_register(("df", "/bin/df", "/usr/bin/df"), Command_df)
_register(("uptime", "/usr/bin/uptime"), Command_uptime)
_register(("date", "/bin/date", "/usr/bin/date"), Command_date)
_register(("lspci", "/usr/bin/lspci"), Command_lspci)
_register(("last", "/usr/bin/last"), Command_last)
_register(("ps", "/bin/ps", "/usr/bin/ps"), Command_ps)
_register(("docker", "/usr/bin/docker"), Command_docker)
_register(("systemctl", "/bin/systemctl", "/usr/bin/systemctl"), Command_systemctl)
_register(("nvidia-smi", "/usr/bin/nvidia-smi"), Command_nvidia_smi)
