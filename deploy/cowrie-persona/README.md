# Cowrie persona: app-prod-01

This directory makes the emulated shell internally consistent and replaces
Cowrie's network-capable `wget`/`curl` commands with a no-network simulation.

The simulation records the requested URL, creates a harmless per-session shell
placeholder (`exit 0`) and reports a successful-looking transfer to the remote
session. It never opens a socket, retrieves external content or executes an
attacker-controlled payload. Direct SFTP/SCP uploads remain handled by Cowrie's
existing quarantine and are never executed by the host.

The registry file mirrors Cowrie `3.0.12`; update and re-test it whenever the
pinned Cowrie image changes.
