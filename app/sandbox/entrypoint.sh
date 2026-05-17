#!/bin/bash
# Idle entrypoint — keeps the container alive for exec-based command injection.
# Commands are injected via `docker exec` by the sandbox manager.
# Dies after TTL seconds (default 30 min).

TTL=${SANDBOX_TTL:-1800}
echo "[sandbox] ready, TTL=${TTL}s, tools: nmap sqlmap nuclei ffuf amass subfinder httpx jwt"

# Die after TTL
(sleep "$TTL" && echo "[sandbox] TTL expired, shutting down" && exit 0) &

# Idle forever — receives commands via docker exec
tail -f /dev/null
