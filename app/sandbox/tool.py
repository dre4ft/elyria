# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""Single bash tool backed by a disposable sandbox container.

The LLM agent gets ONE tool: `bash`.
Supports batch execution — pass an array of commands to run in sequence.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field

from sandbox.manager import Sandbox, SandboxManager


@dataclass
class BashTool:
    """Single tool for sandbox command execution — supports single + batch."""

    sandbox: Sandbox | None = None
    manager: SandboxManager | None = None
    target: str = ""
    max_output: int = 50_000

    def get_definition(self) -> dict:
        return {
            "type": "function",
            "function": {
                "name": "bash",
                "description": (
                    "Execute commands in the pentest sandbox (Alpine container with pentest tools). "
                    "AVAILABLE BINARIES: nmap, sqlmap, nuclei (5000+ templates), ffuf (fuzzer), subfinder (subdomain enum), curl, jq, python3. "
                    "Use 'command' for a single command, or 'commands' array to batch up to 10 commands. "
                    "CONCRETE EXAMPLES (copy-paste ready):\n"
                    "- nmap -sV -p 1-10000 TARGET\n"
                    "- sqlmap -u http://TARGET/api/users/1 --batch --level=1\n"
                    "- curl -s -I http://TARGET && curl -s http://TARGET/.env\n"
                    "- python3 -c \"import base64,sys; print(base64.b64decode(sys.stdin.read()).decode())\" <<< 'JWT_TOKEN'\n"
                    "- curl -s http://TARGET/api/users | jq '.[0].id'\n"
                    "Batch: ['nmap -sV TARGET', 'curl -s http://TARGET/api/users', 'sqlmap -u http://TARGET/api/users/1 --batch']"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "command": {
                            "type": "string",
                            "description": "Single shell command to execute",
                        },
                        "commands": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Array of commands to run sequentially in the same shell. Use for multi-step recon or when chaining tool output.",
                            "minItems": 1,
                            "maxItems": 10,
                        },
                        "timeout_ms": {
                            "type": "integer",
                            "description": "Max execution time per command in ms (default: 30000)",
                        },
                    },
                },
            },
        }

    def handle(self, params: dict) -> str:
        if not self.sandbox:
            result = self.spawn(self.target)
            if result.get("status") != "ok":
                return json.dumps({"error": "Sandbox not available", "detail": result.get("detail", "")})

        timeout_ms = int(params.get("timeout_ms", 30_000))
        resolved = (
            self.target.replace("127.0.0.1", "host.docker.internal")
            .replace("localhost", "host.docker.internal")
        )

        # Batch mode — array of commands
        commands = params.get("commands", [])
        if commands:
            return self._exec_batch(commands, resolved, timeout_ms)

        # Single command
        command = params.get("command", "")
        if not command:
            return json.dumps({"error": "No command or commands provided"})

        command = command.replace("TARGET", resolved).replace(self.target, resolved)
        result = self.sandbox.exec(command, timeout_ms=timeout_ms)
        return json.dumps(result, ensure_ascii=False)

    def _exec_batch(self, commands: list[str], target: str, timeout_ms: int) -> str:
        """Run multiple commands sequentially, returning per-command results."""
        results = []
        total_start = time.monotonic()

        for cmd in commands:
            cmd = cmd.replace("TARGET", target).replace(self.target, target)
            r = self.sandbox.exec(cmd, timeout_ms=timeout_ms)
            results.append({
                "command": cmd[:200],
                "exit_code": r["exit_code"],
                "stdout": r["stdout"][:5000],
                "stderr": r["stderr"][:2000],
                "elapsed_ms": r["elapsed_ms"],
            })

        total_elapsed = int((time.monotonic() - total_start) * 1000)
        return json.dumps({
            "batch": True,
            "count": len(results),
            "total_elapsed_ms": total_elapsed,
            "results": results,
        }, ensure_ascii=False)

    def spawn(self, target: str) -> dict:
        """Spawn a new sandbox for the given target."""
        self.target = target
        if not self.manager:
            self.manager = SandboxManager()
        if self.sandbox:
            return {"status": "ok", "container_id": self.sandbox.container_id, "target": target}
        try:
            self.sandbox = self.manager.spawn(target=target)
            return {"status": "ok", "container_id": self.sandbox.container_id, "target": target}
        except Exception as e:
            return {"status": "error", "detail": str(e)}

    def destroy(self):
        if self.sandbox:
            self.sandbox.destroy()
            self.sandbox = None
