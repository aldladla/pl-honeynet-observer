# SPDX-FileCopyrightText: 2009-2011 Upi Tamminen <desaster@gmail.com>
# SPDX-FileCopyrightText: 2014-2026 Michel Oosterhof <michel@oosterhof.net>
# SPDX-License-Identifier: BSD-3-Clause

"""Cowrie 3.0.12 registry plus local no-network persona overrides."""

from __future__ import annotations

command_modules = [
    "adduser", "apt", "awk", "base", "base64", "bash", "busybox",
    "cat", "chmod", "chpasswd", "crontab", "curl", "cut", "dd",
    "dig", "du", "env", "ethtool", "find", "finger", "free", "fs",
    "ftpget", "gcc", "git", "groups", "ifconfig", "iptables", "last",
    "locate", "ls", "lspci", "nc", "netstat", "nohup", "perl", "ping",
    "python", "scp", "service", "sleep", "ssh", "su", "sudo", "tar",
    "tee", "tftp", "ulimit", "uname", "uniq", "unzip", "uptime", "wc",
    "wget", "which", "yum",
    # Loaded after the standard modules so wget/curl become no-network simulations.
    "safe_transfer",
    # Session-consistent build-worker responses and bounded output telemetry.
    "persona_v2",
    # Dynamic synthetic /proc/uptime; every other cat path delegates to Cowrie.
    "safe_cat",
    # Narrow fast-path for the observed write/chmod/run/remove shell self-test.
    "safe_shell",
]
