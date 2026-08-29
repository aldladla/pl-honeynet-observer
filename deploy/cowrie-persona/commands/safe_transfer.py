# SPDX-License-Identifier: BSD-3-Clause

"""No-network wget/curl emulation for the PL Honeynet Cowrie persona.

The command records attacker intent and creates a harmless file in Cowrie's
per-session virtual filesystem. It deliberately contains no networking imports
and never retrieves the referenced resource.
"""

from __future__ import annotations

import hashlib
import posixpath
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlsplit

from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.fs import PermissionDenied

commands = {}

PLACEHOLDER_PATH = Path("/cowrie/cowrie-git/persona/safe-placeholder.sh")
PLACEHOLDER_BYTES = b"#!/bin/sh\nexit 0\n"
ALLOWED_SCHEMES = {"http", "https", "ftp"}
MAX_URL_LENGTH = 8192


@dataclass(frozen=True)
class TransferIntent:
    url: str
    output: str | None
    quiet: bool


def _valid_url(value: str) -> bool:
    if not value or len(value) > MAX_URL_LENGTH:
        return False
    try:
        parsed = urlsplit(value)
        return parsed.scheme.lower() in ALLOWED_SCHEMES and bool(parsed.hostname)
    except ValueError:
        return False


def _remote_name(url: str) -> str:
    candidate = unquote(posixpath.basename(urlsplit(url).path)).replace("\x00", "")
    return (candidate or "index.html")[:255]


def parse_wget(args: list[str]) -> TransferIntent | None:
    output: str | None = None
    prefix: str | None = None
    quiet = False
    url: str | None = None
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in {"-q", "--quiet"} or (arg.startswith("-") and "q" in arg[1:]):
            quiet = True
        if arg in {"-O", "--output-document"} and index + 1 < len(args):
            output = args[index + 1]
            index += 2
            continue
        if arg.startswith("--output-document="):
            output = arg.split("=", 1)[1]
        elif arg.startswith("-O") and len(arg) > 2:
            output = arg[2:]
        elif arg in {"-P", "--directory-prefix"} and index + 1 < len(args):
            prefix = args[index + 1]
            index += 2
            continue
        elif arg.startswith("--directory-prefix="):
            prefix = arg.split("=", 1)[1]
        elif _valid_url(arg) and url is None:
            url = arg
        index += 1

    if url is None:
        return None
    if output is None:
        output = _remote_name(url)
        if prefix:
            output = posixpath.join(prefix, output)
    return TransferIntent(url=url, output=output, quiet=quiet)


def parse_curl(args: list[str]) -> TransferIntent | None:
    output: str | None = None
    remote_name = False
    quiet = False
    url: str | None = None
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in {"-s", "--silent"} or (
            arg.startswith("-") and not arg.startswith("--") and "s" in arg[1:]
        ):
            quiet = True
        if arg in {"-o", "--output"} and index + 1 < len(args):
            output = args[index + 1]
            index += 2
            continue
        if arg.startswith("--output="):
            output = arg.split("=", 1)[1]
        elif arg.startswith("-o") and len(arg) > 2:
            output = arg[2:]
        elif arg in {"-O", "--remote-name"}:
            remote_name = True
        elif _valid_url(arg) and url is None:
            url = arg
        index += 1

    if url is None:
        return None
    if remote_name and output is None:
        output = _remote_name(url)
    return TransferIntent(url=url, output=output, quiet=quiet)


class _SafeTransfer(HoneyPotCommand):
    tool = "transfer"
    version_text = ""

    def parse(self) -> TransferIntent | None:
        raise NotImplementedError

    def _record(self, intent: TransferIntent, destination: str) -> None:
        self.protocol.events.dispatch(
            "cowrie.session.file_download.simulated",
            "Simulated %(tool)s request for %(url)s to %(outfile)s without network retrieval",
            tool=self.tool,
            url=intent.url,
            outfile=destination,
            size=len(PLACEHOLDER_BYTES),
            placeholder_sha256=hashlib.sha256(PLACEHOLDER_BYTES).hexdigest(),
            simulated=True,
        )

    def _create_virtual_file(self, target: str) -> str | None:
        resolved = self.fs.resolve_path(target, self.cwd)
        parent = posixpath.dirname(resolved)
        if not parent or not self.fs.exists(parent) or not self.fs.isdir(parent):
            self.errorWrite(f"{self.tool}: {target}: No such file or directory\n")
            self.exit_code = 1
            return None
        if resolved == "/dev/null":
            return resolved
        if self.fs.exists(resolved) and self.fs.isdir(resolved):
            self.errorWrite(f"{self.tool}: {target}: Is a directory\n")
            self.exit_code = 1
            return None
        try:
            if self.fs.exists(resolved):
                self.fs.remove(resolved)
            self.fs.mkfile(
                resolved,
                self.user["uid"],
                self.user["gid"],
                len(PLACEHOLDER_BYTES),
                0o100644,
            )
            self.fs.update_realfile(self.fs.getfile(resolved), str(PLACEHOLDER_PATH))
        except (IndexError, OSError, PermissionDenied, RuntimeError, TypeError, ValueError):
            self.errorWrite(f"{self.tool}: {target}: cannot create output file\n")
            self.exit_code = 1
            return None
        return resolved

    def call(self) -> None:
        if any(arg in {"-V", "--version"} for arg in self.args):
            self.write(self.version_text)
            return
        if any(arg in {"-h", "--help"} for arg in self.args):
            self.write(f"Usage: {self.tool} [options] URL\n")
            return
        intent = self.parse()
        if intent is None:
            self.errorWrite(f"{self.tool}: missing or invalid URL\n")
            self.exit_code = 1
            return

        if intent.output in {None, "-"}:
            self.writeBytes(PLACEHOLDER_BYTES)
            self._record(intent, "stdout")
            return

        destination = self._create_virtual_file(intent.output)
        if destination is None:
            return
        self._record(intent, destination)
        if not intent.quiet:
            if self.tool == "wget":
                self.errorWrite(f"Saving to: '{destination}'\n")
                self.errorWrite(
                    f"'{destination}' saved [{len(PLACEHOLDER_BYTES)}/{len(PLACEHOLDER_BYTES)}]\n"
                )
            else:
                self.errorWrite(
                    f"100 {len(PLACEHOLDER_BYTES):5d}  100 {len(PLACEHOLDER_BYTES):5d} "
                    "   0     0   1700      0 --:--:-- --:--:-- --:--:--  1700\n"
                )


class Command_safe_wget(_SafeTransfer):
    tool = "wget"
    version_text = "GNU Wget 1.21.3 built on linux-gnu.\n"

    def parse(self) -> TransferIntent | None:
        return parse_wget(self.args)


class Command_safe_curl(_SafeTransfer):
    tool = "curl"
    version_text = (
        "curl 7.88.1 (x86_64-pc-linux-gnu) libcurl/7.88.1 OpenSSL/3.0.11 "
        "zlib/1.2.13\n"
    )

    def parse(self) -> TransferIntent | None:
        return parse_curl(self.args)


commands["/usr/bin/wget"] = Command_safe_wget
commands["wget"] = Command_safe_wget
commands["/usr/bin/dget"] = Command_safe_wget
commands["dget"] = Command_safe_wget
commands["/usr/bin/curl"] = Command_safe_curl
commands["curl"] = Command_safe_curl
