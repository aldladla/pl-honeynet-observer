# SPDX-License-Identifier: MIT

"""Dynamic synthetic ``/proc/uptime`` with normal Cowrie ``cat`` fallback."""

from __future__ import annotations

from datetime import UTC, datetime

from cowrie.commands.cat import Command_cat as CowrieCommandCat
from cowrie.commands.persona_v2 import persona_state, synthetic_proc_uptime

commands = {}


class Command_safe_cat(CowrieCommandCat):
    """Intercept only ``cat /proc/uptime`` and delegate every other path."""

    def start(self) -> None:
        if self.args != ["/proc/uptime"]:
            super().start()
            return

        now = datetime.now(UTC)
        stdout = f"{synthetic_proc_uptime(state=persona_state(self.protocol), now=now)}\n"
        self.protocol.events.dispatch(
            "cowrie.command.output.emulated",
            "Emulated /proc/uptime read completed with exit code 0",
            tool="cat-proc-uptime",
            input="cat /proc/uptime",
            stdout=stdout,
            stderr="",
            exit_code=0,
            emulated=True,
        )
        self.write(stdout)
        self.exit_code = 0
        self.exit()


for name in ("cat", "/bin/cat", "/usr/bin/cat"):
    commands[name] = Command_safe_cat
