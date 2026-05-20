# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""Sandbox Manager — spawn, execute, purge disposable pentest containers.

Usage:
    mgr = SandboxManager()
    sandbox = mgr.spawn(target="10.0.0.5")
    result = sandbox.exec("nmap -sV 10.0.0.5")
    sandbox.destroy()
"""

from __future__ import annotations

import subprocess
import time
import uuid
from dataclasses import dataclass, field


DEFAULT_IMAGE = "strike-sandbox"
DEFAULT_TTL = 1800  # 30 minutes
DEFAULT_CPU = "1"
DEFAULT_MEM = "512m"


@dataclass
class Sandbox:
    container_id: str
    target: str
    spawned_at: float = field(default_factory=time.monotonic)

    def exec(self, command: str, timeout_ms: int = 60_000) -> dict:
        """Execute a command in the sandbox. Returns {exit_code, stdout, stderr, elapsed_ms}.

        Uses a temp script file to avoid shell quoting issues (no escaping needed).
        """
        if not self.container_id:
            return {"exit_code": -1, "stdout": "", "stderr": "Sandbox destroyed", "elapsed_ms": 0}

        timeout_s = max(1, timeout_ms // 1000)
        start = time.monotonic()

        import base64
        encoded = base64.b64encode(command.encode()).decode()

        try:
            proc = subprocess.run(
                ["docker", "exec", self.container_id, "bash", "-c",
                 f'echo {encoded} | python3 -c "import base64,sys; sys.stdout.write(base64.b64decode(sys.stdin.read()).decode())" | bash'],
                capture_output=True, text=True, timeout=timeout_s,
            )
            elapsed = int((time.monotonic() - start) * 1000)
            stdout = (proc.stdout or "")
            stderr = (proc.stderr or "")
            if proc.returncode != 0 and not stdout.strip() and not stderr.strip():
                stderr = f"exit code {proc.returncode} (no output — check target reachability from container)"
            return {
                "exit_code": proc.returncode,
                "stdout": stdout[:50_000],
                "stderr": stderr[:10_000],
                "elapsed_ms": elapsed,
            }
        except subprocess.TimeoutExpired:
            elapsed = int((time.monotonic() - start) * 1000)
            return {"exit_code": -1, "stdout": "", "stderr": f"Command timed out after {timeout_ms}ms", "elapsed_ms": elapsed}
        except Exception as e:
            elapsed = int((time.monotonic() - start) * 1000)
            return {"exit_code": -1, "stdout": "", "stderr": str(e)[:500], "elapsed_ms": elapsed}

    def destroy(self):
        """Kill and remove the container + volumes."""
        if self.container_id:
            subprocess.run(
                ["docker", "rm", "-f", "--volumes", self.container_id],
                capture_output=True,
            )
            self.container_id = ""

    @property
    def age_seconds(self) -> float:
        return time.monotonic() - self.spawned_at


class SandboxManager:
    """Pool of sandbox containers. Spawns, tracks, auto-purges."""

    def __init__(self, image: str = DEFAULT_IMAGE):
        self.image = image
        self._sandboxes: dict[str, Sandbox] = {}

    def spawn(
        self,
        target: str,
        ttl: int = DEFAULT_TTL,
        cpu: str = DEFAULT_CPU,
        mem: str = DEFAULT_MEM,
    ) -> Sandbox:
        """Spawn a new sandbox container for the given target."""
        cid = f"strike-{uuid.uuid4().hex[:10]}"

        # Resolve localhost to host.docker.internal so container can reach host
        resolved_target = target
        if "127.0.0.1" in target or "localhost" in target:
            resolved_target = target.replace("127.0.0.1", "host.docker.internal").replace("localhost", "host.docker.internal")

        subprocess.run(
            [
                "docker", "run", "-d", "--rm",
                "--name", cid,
                "--cpus", cpu,
                "--memory", mem,
                "--add-host", "host.docker.internal:host-gateway",
                "--dns", "8.8.8.8",
                "-e", f"SANDBOX_TTL={ttl}",
                "-e", f"SANDBOX_TARGET={resolved_target}",
                self.image,
            ],
            capture_output=True, check=True,
        )

        sandbox = Sandbox(container_id=cid, target=target)
        self._sandboxes[cid] = sandbox

        # Wait for container to be ready
        time.sleep(1.5)

        return sandbox

    def get(self, container_id: str) -> Sandbox | None:
        return self._sandboxes.get(container_id)

    def purge_expired(self, max_age_s: int = DEFAULT_TTL + 300):
        """Destroy sandboxes older than max_age_s."""
        now = time.monotonic()
        for cid, sb in list(self._sandboxes.items()):
            if now - sb.spawned_at > max_age_s:
                sb.destroy()
                del self._sandboxes[cid]

    def purge_all(self):
        """Destroy all sandboxes."""
        for sb in list(self._sandboxes.values()):
            sb.destroy()
        self._sandboxes.clear()
