from fastmcp import FastMCP
from sandbox.tool import BashTool
from sandbox.manager import Sandbox, SandboxManager
from core.logging import get_logger

_log = get_logger("sandbox.mcp_tool")

user_sandboxes = {}
app = FastMCP(name="mcp")

def get_bash_tool(user_id: str,container_id: str = None) -> BashTool | None:
    if user_id in user_sandboxes:
        return user_sandboxes[user_id]
    if container_id:
        sandbox = Sandbox(container_id=container_id, target="")
        bash_tool = BashTool(sandbox=sandbox, manager=None)
        user_sandboxes[user_id] = bash_tool
        return bash_tool
    try:
        mgr = SandboxManager()
        sandbox = mgr.spawn()
        sandbox_id = sandbox.container_id
        bash_tool = BashTool(sandbox=sandbox, manager=mgr)
        _log.info(f"[MCP SANDBOX] Sandbox spawned: container={sandbox_id}")
        user_sandboxes[user_id] = bash_tool
        return bash_tool
    except Exception as e:
        _log.exception(f"Failed to spawn sandbox: {e}")
        return None



@app.tool()
def run_sandbox_command(command: str) -> str:
    """Run a shell command inside a sandbox and return its output."""
    bash_tool = get_bash_tool(user_id="mcp_tool")
    if not bash_tool:
        return "Failed to create or retrieve sandbox."
    try:
        params = command if isinstance(command, dict) else {"command": str(command)}
        output = bash_tool.handle(params)
        return output
    except Exception as e:
        return f"Error running command in sandbox: {e}"

@app.tool()
def list_sandbox_tools() -> dict:
    return {"Paquets disponibles": """bash
                                        curl
                                        wget
                                        ca-certificates
                                        bind-tools
                                        netcat-openbsd
                                        socat
                                        nmap
                                        nmap-scripts
                                        git
                                        openssh-client
                                        python3
                                        py3-pip
                                        jq
                                        yq
                                        unzip
                                        tar
                                        massdns
                                        amass
                                        wfuzz
                                        chromium
                                        chromium-chromedriver""",
                "python": """sqlmap
                            requests
                            httpx
                            aiohttp
                            pyjwt
                            beautifulsoup4""",
                "Outils GO": """nuclei v3.4.2
                                subfinder v2.7.0
                                httpx v1.7.2
                                katana v1.1.0
                                ffuf v2.1.0"""}

@app.tool()
def destroy_bash_tool():
    if "mcp_tool" in user_sandboxes:
        try:
            user_sandboxes["mcp_tool"].destroy()
            _log.info(f"[MCP SANDBOX] Sandbox destroyed for user mcp_tool")
        except Exception as e:
            _log.exception(f"Failed to destroy sandbox for user mcp_tool: {e}")
        del user_sandboxes["mcp_tool"]

if __name__ == "__main__":
    app.run(transport="stdio")