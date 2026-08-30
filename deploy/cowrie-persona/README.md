# Cowrie persona: app-prod-01

This directory makes the emulated shell internally consistent and adds local,
no-network simulations for transfers, discovery and one shell capability test.

The simulation records the requested URL, creates a harmless per-session shell
placeholder (`exit 0`) and reports a successful-looking transfer to the remote
session. It never opens a socket, retrieves external content or executes an
attacker-controlled payload. Direct SFTP/SCP uploads remain handled by Cowrie's
existing quarantine and are never executed by the host.

The registry file mirrors Cowrie `3.0.12`; update and re-test it whenever the
pinned Cowrie image changes.

## Persona v2: build worker

The v2 command module gives deterministic, mutually consistent responses for
common system and workload discovery commands (`uname`, `nproc`, `lscpu`,
`free`, `df`, `uptime`, `date`, `lspci`, `last`, `ps`, `docker`, `systemctl`, and
`nvidia-smi`). It models an eight-vCPU Debian application worker with 16 GiB of
memory and a long uptime.

Each v2 response is generated in memory and is also recorded as a bounded
`cowrie.command.output.emulated` event. No command calls the host, opens a
socket, reads host state, or executes attacker-controlled content. Addresses in
the synthetic login history use the RFC 5737 documentation range.

## Persona v2.1: shell capability probe

The final `safe_shell` override recognizes only the observed `bash/sh -c`
write, `chmod`, execute and cleanup test for a temporary file named `filter`.
It returns the expected synthetic marker and records a bounded
`write_chmod_execute_cleanup` telemetry event without creating or executing any
file. All other shell input is delegated unchanged to Cowrie's original
`Command_sh` implementation, including its normal direct-upload handling.

## Persona v2.2: complete inventory response

The same module also recognizes the complete, repeated host-capability probe
seen in the live campaign. A match requires every expected assignment and
report field, the known shell self-test, no network-transfer primitive, and the
final `FILTER` report line as the end of input. The sensor then emits one
consistent synthetic inventory response immediately and records it as
`host-capability-probe`. Any missing anchor, appended command or network token
causes the input to be delegated to Cowrie's standard parser.

## Persona v3: session-consistent runtime

The host identity and synthetic boot timestamp remain stable, while the UTC
clock, uptime, load average, memory pressure and container age advance in small
deterministic steps. Values are derived only from time plus a per-session seed;
they never expose VPS metrics. Repeating a command at the same instant within a
session gives the same response, and related fields use one shared timestamp.

The `safe_cat` override applies the same model to `cat /proc/uptime` and
delegates every other file to Cowrie's original `cat` implementation. The full
host-capability probe also uses this dynamic value, so the direct command,
procfs read and aggregate response cannot drift apart.
