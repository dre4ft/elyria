from sandbox.tool import BashTool
from sandbox.manager import SandboxManager, Sandbox

from core.logging import get_logger


_log = get_logger("ely.sandbox_spawn")



user_sandboxes = {}



def get_sandbox_toollist(user_id: str) -> list[str]:
    if user_id in user_sandboxes:
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
    return []


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
        _log.info(f"[ELY SANDBOX] Sandbox spawned: container={sandbox_id}")
        user_sandboxes[user_id] = bash_tool
        return bash_tool
    except Exception as e:
        _log.exception(f"Failed to spawn sandbox: {e}")
        return None


def destroy_bash_tool(user_id: str):
    if user_id in user_sandboxes:
        try:
            user_sandboxes[user_id].destroy()
            _log.info(f"[ELY SANDBOX] Sandbox destroyed for user {user_id}")
        except Exception as e:
            _log.exception(f"Failed to destroy sandbox for user {user_id}: {e}")
        del user_sandboxes[user_id]
