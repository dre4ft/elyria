import sys, os, json, subprocess
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastmcp import FastMCP

app = FastMCP(name="mcp")


def _get_or_spawn():
    cid = subprocess.run(
        ["docker", "ps", "-q", "--filter", "name=strike-", "--latest"],
        capture_output=True, text=True, timeout=5,
    ).stdout.strip()
    if not cid:
        try:
            cid = subprocess.run(
                ["docker", "run", "-d", "--rm", "--name", "strike-repl",
                 "elyria-sandbox:latest", "sleep", "3600"],
                capture_output=True, text=True, timeout=15,
            ).stdout.strip()
        except Exception:
            return None
    return cid


@app.tool
def run_sandbox_command(**kwargs) -> str:
    """Execute a shell command in the pentest sandbox."""
    # Handle all possible argument formats
    cmd = ""
    if "command" in kwargs:
        cmd = kwargs["command"]
    elif len(kwargs) == 1:
        val = list(kwargs.values())[0]
        cmd = val.get("command", "") if isinstance(val, dict) else str(val)
    if not cmd:
        return json.dumps({"error": "no command", "debug": str(kwargs)[:200]})
    cid = _get_or_spawn()
    if not cid:
        return json.dumps({"error": "Cannot spawn sandbox"})
    try:
        r = subprocess.run(
            ["docker", "exec", cid, "bash", "-c", cmd],
            capture_output=True, text=True, timeout=30,
        )
        return json.dumps({"stdout": r.stdout[:3000], "stderr": r.stderr[:1000], "exit_code": r.returncode})
    except subprocess.TimeoutExpired:
        return json.dumps({"error": "timeout"})
    except Exception as e:
        return json.dumps({"error": str(e)[:200]})


@app.tool
def sandbox_file_read(path: str) -> str:
    """Read a file from the sandbox."""
    p = path if isinstance(path, str) else path.get("path", "")
    cid = _get_or_spawn()
    if not cid: return json.dumps({"error": "No sandbox"})
    try:
        r = subprocess.run(
            ["docker", "exec", cid, "cat", p],
            capture_output=True, text=True, timeout=10,
        )
        return r.stdout[:5000] if r.returncode == 0 else f"Error: {r.stderr[:500]}"
    except Exception as e:
        return str(e)[:500]


@app.tool
def sandbox_file_write(path: str, content: str) -> str:
    """Write content to a file in the sandbox."""
    import base64
    p = path if isinstance(path, str) else path.get("path", "")
    c = content if isinstance(content, str) else content.get("content", "")
    cid = _get_or_spawn()
    if not cid: return json.dumps({"error": "No sandbox"})
    try:
        encoded = base64.b64encode(c.encode()).decode()
        r = subprocess.run(
            ["docker", "exec", cid, "bash", "-c",
             f"echo {encoded} | base64 -d > {p}"],
            capture_output=True, text=True, timeout=10,
        )
        return "ok" if r.returncode == 0 else f"Error: {r.stderr[:500]}"
    except Exception as e:
        return str(e)[:500]


if __name__ == "__main__":
    app.run()
