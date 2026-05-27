from sandbox.tool import BashTool
from sandbox.manager import SandboxManager

from core.logging import get_logger


_log = get_logger("ely.sandbox_spawn")



user_sandboxes = {}


def get_bash_tool(user_id: str) -> BashTool | None:
    if user_id in user_sandboxes:
        return user_sandboxes[user_id]

    try:
        mgr = SandboxManager()
        sandbox = mgr.spawn()
        bash_tool = BashTool(sandbox=sandbox, manager=mgr)
        _log.info(f"[ELY SANDBOX] Sandbox spawned: container={sandbox.container_id}")
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
