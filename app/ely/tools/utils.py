
import json
import threading
from core.logging import get_logger

_log = get_logger("ely.tools.utils")

ACTIONS = {}


def _action(name, description, parameters):
    def decorator(handler):
        ACTIONS[name] = {
            "definition": {
                "type": "function",
                "function": {
                    "name": name,
                    "description": description,
                    "parameters": {
                        "type": "object",
                        "properties": parameters,
                        "required": list(parameters.keys()),
                    },
                },
            },
            "handler": handler,
        }
        return handler
    return decorator