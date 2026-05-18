# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

import json
import re
import sys
import random
import string
from pathlib import Path
from typing import Optional

# Ensure app/ is importable regardless of CWD
_APP = Path(__file__).resolve().parent.parent.parent
if str(_APP) not in sys.path:
    sys.path.insert(0, str(_APP))



def _open_file(path: str):
    ext = path.rsplit(".", 1)[-1] if "." in path else ""
    if ext == "json":
        with open(path) as f:
            content = json.load(f)
    elif ext in ("yml", "yaml"):
        import yaml
        with open(path) as f:
            content = yaml.safe_load(f)
    else:
        raise Exception("File type must be json, yml or yaml")
    validate(content)
    return content

def validate_wrapper(content : dict):
    try: 
        validate(content=content)
        return True 
    except Exception:
        return False 

def validate(content: dict):
    if not content.get("arazzo"):
        raise ValueError("Missing 'arazzo' field — not an Arazzo spec")
    if not content.get("info"):
        raise ValueError("Missing 'info' field")
    if not content.get("sourceDescriptions"):
        raise ValueError("Missing 'sourceDescriptions' field")
    if not content.get("workflows"):
        raise ValueError("Missing 'workflows' field")
    return content["arazzo"]



def _resolve_json_pointer(pointer: str, spec: dict):

    if pointer.startswith("#"):
        pointer = pointer[1:]
    current = spec
    for seg in pointer.split("/"):
        if not seg:
            continue
        seg = seg.replace("~1", "/").replace("~0", "~")
        current = current[seg]
    return current


def _find_operation_by_id(operation_id: str, spec: dict):
    """Search all paths for an operation with the given operationId."""
    for path, path_item in spec.get("paths", {}).items():
        for method in ["get", "post", "put", "patch", "delete", "options", "head"]:
            op = path_item.get(method)
            if op and op.get("operationId") == operation_id:
                return path, method, op
    return None, None, None




def _resolve_param_value(value):

    if not isinstance(value, str):
        return value

    if value.startswith("$inputs."):
        # $inputs.username → {{ctx.inputs.username}}
        return "{{ctx.inputs." + value[len("$inputs."):] + "}}"

    if value.startswith("$steps."):
        # $steps.loginUser.outputs.sessionToken → {{ctx.loginUser.sessionToken}}
        rest = value[len("$steps."):]
        if ".outputs." in rest:
            step_name, var = rest.split(".outputs.", 1)
            return "{{ctx." + step_name + "." + var + "}}"
        return value

    if value.startswith("$response."):
        # $response.body → {{ctx.<step>.body}} — will be resolved by the step's saveTo
        # $response.header.X → {{ctx.<step>.headers["X"]}}
        if value.startswith("$response.header."):
            header_name = value[len("$response.header."):]
            return '{{ctx.response.headers["' + header_name + '"]}}'
        if value == "$response.body":
            return "{{ctx.response.body}}"
        if value.startswith("$response.body#/"):
            pointer = value[len("$response.body#/"):]
            return "{{JSON.parse(ctx.response.body)." + pointer.replace("/", ".") + "}}"

    return value



def _merge_params(openapi_params: list, arazzo_params: list):
    
    arazzo_by_key = {}
    for p in arazzo_params:
        arazzo_by_key[(p["name"], p.get("in", "query"))] = p

    merged = {}
    for p in openapi_params:
        key = (p["name"], p.get("in"))
        if key in arazzo_by_key:
            merged[key] = _resolve_param_value(arazzo_by_key[key].get("value", ""))
        else:
            schema = p.get("schema", {})
            val = schema.get("example", schema.get("default"))
            if val is None:
                t = schema.get("type", "string")
                if t == "integer":
                    val = 0
                elif t == "boolean":
                    val = False
                else:
                    val = "string"
            merged[key] = val

    # Arazzo-only params (not defined in OpenAPI)
    for p in arazzo_params:
        key = (p["name"], p.get("in", "query"))
        if key not in merged:
            merged[key] = _resolve_param_value(p.get("value", ""))

    path_p, query_p, header_p = {}, {}, {}
    for (name, loc), value in merged.items():
        if loc == "path":
            path_p[name] = value
        elif loc == "query":
            query_p[name] = value
        elif loc == "header":
            header_p[name] = value

    return path_p, query_p, header_p




def _extract_captures(step: dict) -> Optional[dict]:
    outputs = step.get("outputs", {})
    if not outputs:
        return None
    captures = {}
    for var_name, expr in outputs.items():
        if not isinstance(expr, str):
            captures[var_name] = expr
        elif expr.startswith("$response.body"):
            captures[var_name] = "$.body"
        elif expr.startswith("$response.header."):
            header_name = expr[len("$response.header."):]
            captures[var_name] = f"$.header.{header_name}"
        else:
            captures[var_name] = expr
    return captures if captures else None


def _extract_condition(step: dict) -> Optional[str]:
    criteria = step.get("successCriteria", [])
    if criteria:
        return criteria[0].get("condition")
    return None




# ── Smart sample value generation ──

_SMART_DEFAULTS = {
    "username": "alice",    "name": "Alice",       "firstname": "Alice",
    "lastname": "Dupont",   "fullname": "Alice Dupont",
    "email": "alice@mail.com", "mail": "alice@mail.com",
    "password": "Test123!", "pass": "Test123!",
    "token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.demo",
    "apikey": "sk-demo-1234567890", "api_key": "sk-demo-1234567890",
    "secret": "********",   "auth": "Bearer eyJhbGciOiJIUzI1NiJ9.demo",
    "id": 1,                "userid": 42,          "user_id": 42,
    "uid": "a1b2c3d4",      "uuid": "550e8400-e29b-41d4-a716-446655440000",
    "url": "https://example.com", "endpoint": "https://api.example.com/v1",
    "host": "api.example.com", "port": 443,
    "date": "2025-06-15",   "startdate": "2025-06-01", "enddate": "2025-12-31",
    "page": 1,              "limit": 10,           "offset": 0,
    "size": 20,             "count": 100,
    "role": "user",         "status": "active",    "type": "standard",
    "q": "search",          "query": "test",       "search": "demo",
    "lang": "fr",           "locale": "fr-FR",     "currency": "EUR",
    "phone": "+33612345678",
    "description": "Lorem ipsum dolor sit amet.",
    "title": "Test",        "message": "Hello World",
}


def _generate_input_value(name: str, prop: dict):
    """Generate a smart sample value for a single input property."""
    if "example" in prop and prop["example"] is not None:
        return prop["example"]
    if "default" in prop and prop["default"] is not None:
        return prop["default"]

    ptype = (prop.get("type") or "string").lower()
    enum = prop.get("enum")
    if enum and isinstance(enum, list):
        return enum[0]

    if ptype == "boolean":
        return False
    if ptype in ("integer", "number"):
        mn = prop.get("minimum") or prop.get("min")
        mx = prop.get("maximum") or prop.get("max")
        if mn is not None:
            return int(mn) if ptype == "integer" else mn
        if mx is not None:
            return int(min(mx, 42)) if ptype == "integer" else min(mx, 42)
        name_key = name.lower().replace("_", "").replace("-", "")
        if name_key in _SMART_DEFAULTS and isinstance(_SMART_DEFAULTS[name_key], (int, float)):
            return _SMART_DEFAULTS[name_key]
        return 42

    if ptype == "array":
        return ["item1", "item2"]
    if ptype == "object":
        return {}

    # string
    name_key = name.lower().replace("_", "").replace("-", "")
    if name_key in _SMART_DEFAULTS and isinstance(_SMART_DEFAULTS[name_key], str):
        return _SMART_DEFAULTS[name_key]

    fmt = (prop.get("format") or "").lower()
    if fmt == "email":
        return "alice@mail.com"
    if fmt in ("uri", "url"):
        return "https://example.com"
    if fmt == "uuid":
        return "550e8400-e29b-41d4-a716-446655440000"
    if fmt == "date":
        return "2025-06-15"
    if fmt == "date-time":
        return "2025-06-15T10:30:00Z"
    if fmt == "ipv4":
        return "192.168.1.1"
    if fmt == "ipv6":
        return "::1"
    if fmt == "hostname":
        return "api.example.com"
    if fmt == "byte":
        return "ZGVtbw=="

    # generate random string respecting constraints
    min_len = prop.get("minLength", 0)
    max_len = prop.get("maxLength", 32)
    target_len = max(min_len, min(max_len, 8))
    chars = string.ascii_lowercase + string.digits
    return "".join(random.choice(chars) for _ in range(target_len))


def _extract_workflow_inputs(wf: dict) -> dict:
    """Extract inputs definition from an Arazzo workflow, generating sample values."""
    inputs_def = wf.get("inputs", {})
    if not inputs_def or not isinstance(inputs_def, dict):
        return None
    props = inputs_def.get("properties", {})
    if not props:
        return None
    result = {}
    for key, prop in props.items():
        if not isinstance(prop, dict):
            continue
        result[key] = _generate_input_value(key, prop)
    return result if result else None


def parse_arazzo(arazzo_content: dict,
                 openapi_specs: Optional[dict[str, dict]] = None,
                 target_server: str = "") -> list[dict]:

    validate(arazzo_content)

    if openapi_specs is None:
        openapi_specs = {}

    # Build case-insensitive lookup for source description names
    _specs_ci = {k.lower(): v for k, v in openapi_specs.items()}

    # Resolve target server: explicit param > first sourceDescription url > empty
    if not target_server:
        for sd in arazzo_content.get("sourceDescriptions", []):
            if sd.get("url"):
                target_server = sd["url"].rstrip("/")
                break

    workflows = []

    for wf in arazzo_content.get("workflows", []):
        wf_name = wf.get("workflowId", "Unnamed Workflow")
        wf_desc = wf.get("description", wf.get("summary", ""))

        steps = []
        for step in wf.get("steps", []):
            step_name = step.get("stepId", "Unnamed Step")

            op_path = None
            op_method = None
            op_operation = None
            openapi_spec = None

            # Try operationId first
            if "operationId" in step:
                for spec in openapi_specs.values():
                    p, m, op = _find_operation_by_id(step["operationId"], spec)
                    if op:
                        op_path = p
                        op_method = m
                        op_operation = op
                        openapi_spec = spec
                        break

            # Fall back to operationPath
            if op_operation is None and "operationPath" in step:
                op_path_str = step["operationPath"]
                m = re.match(r'\{[$]sourceDescriptions\.(\w+)\.url\}(.*)', op_path_str)
                if m:
                    sd_name = m.group(1)
                    pointer = m.group(2)
                    spec = _specs_ci.get(sd_name.lower())
                    if spec is not None:
                        try:
                            op_operation = _resolve_json_pointer(pointer, spec)
                            openapi_spec = spec
                            op_method = pointer.rsplit("/", 1)[-1]
                            # Reconstruct path from pointer: /paths/~1pet~1findByStatus → /pet/findByStatus
                            segments = pointer.split("/")
                            path_segs = segments[2:-1]  # skip empty, "paths", and method
                            op_path = "/" + "/".join(
                                s.replace("~1", "/").replace("~0", "~")
                                for s in path_segs
                            )
                        except (ValueError, KeyError, IndexError):
                            pass
                    # Even without the spec, extract path and method from the pointer
                    if op_operation is None:
                        try:
                            segments = pointer.split("/")
                            # pointer: /paths/~1pet~1findByStatus/get
                            # segments: ['', 'paths', '~1pet~1findByStatus', 'get']
                            op_method = segments[-1].lower()
                            path_segs = segments[2:-1]  # skip empty, "paths", method
                            op_path = "/" + "/".join(
                                s.replace("~1", "/").replace("~0", "~")
                                for s in path_segs
                            )
                        except (IndexError, ValueError):
                            pass

            if op_operation is None and op_path is None:
                # Unresolvable operation (e.g. operationId without OpenAPI spec)
                # Still extract params so headers/auth placeholders are preserved
                path_p, query_p, header_p = {}, {}, {}
                for p in step.get("parameters", []):
                    name = p.get("name", "")
                    loc = p.get("in", "query")
                    val = _resolve_param_value(p.get("value", ""))
                    if loc == "path":
                        path_p[name] = val
                    elif loc == "header":
                        header_p[name] = val
                    else:
                        query_p[name] = val
                url = target_server if target_server else ""
                if query_p:
                    qs = "&".join(f"{k}={v}" for k, v in query_p.items())
                    url = f"{url}?{qs}" if url else f"?{qs}"
                steps.append({
                    "name": step_name,
                    "method": "GET",
                    "url": url,
                    "headers": dict(header_p) if header_p else None,
                    "body": None,
                    "captures": _extract_captures(step),
                    "condition": _extract_condition(step),
                })
                continue

            # Merge parameters (only if we have the OpenAPI operation)
            if op_operation:
                openapi_params = op_operation.get("parameters", [])
                arazzo_params = step.get("parameters", [])
                path_p, query_p, header_p = _merge_params(openapi_params, arazzo_params)
            else:
                # No OpenAPI spec — extract params from Arazzo step alone
                path_p, query_p, header_p = {}, {}, {}
                for p in step.get("parameters", []):
                    name = p.get("name", "")
                    loc = p.get("in", "query")
                    val = _resolve_param_value(p.get("value", ""))
                    if loc == "path":
                        path_p[name] = val
                    elif loc == "query":
                        query_p[name] = val
                    elif loc == "header":
                        header_p[name] = val

            # Build URL
            if openapi_spec and openapi_spec.get("servers"):
                base_url = openapi_spec["servers"][0]["url"]
            else:
                base_url = target_server
            url = base_url.rstrip("/") + "/" + op_path.lstrip("/") if op_path else base_url
            for name, value in path_p.items():
                url = url.replace(f"{{{name}}}", str(value))
            if query_p:
                qs = "&".join(f"{k}={v}" for k, v in query_p.items())
                url = f"{url}?{qs}"

            # Headers
            headers = dict(header_p) if header_p else {}

            # Body (only resolvable with OpenAPI spec)
            body = None
            if op_operation and openapi_spec:
                request_body = op_operation.get("requestBody")
                if request_body:
                    body_content = request_body.get("content", {})
                    if "application/json" in body_content:
                        from doc_mgmt.openapi.parser import _schema_to_example
                        schema = body_content["application/json"].get("schema", {})
                        example = _schema_to_example(schema, openapi_spec)
                        body = json.dumps(example, indent=2)
                        headers["Content-Type"] = "application/json"

            steps.append({
                "name": step_name,
                "method": op_method.upper() if op_method else "GET",
                "url": url,
                "headers": headers if headers else None,
                "body": body,
                "captures": _extract_captures(step),
                "condition": _extract_condition(step),
            })

        # Extract inputs with auto-generated sample values
        wf_inputs = _extract_workflow_inputs(wf)

        workflows.append({
            "name": wf_name,
            "description": wf_desc,
            "steps": steps,
            "inputs": wf_inputs,
        })

    return workflows



def _arazzo_steps_to_graph(steps: list[dict], inputs_values: dict = None) -> dict:
    """Convert Arazzo workflow steps into an Elyria workflow graph (nodes + connections).

    Each Arazzo step becomes an HTTP Request node. Steps are chained sequentially.
    Captures are mapped to the saveTo field. Conditions become Assert nodes.
    If inputs_values is provided, a Set Data node is inserted after Start to initialize ctx.inputs.
    """
    import json as _json

    nodes = []
    connections = []

    # Start node
    nodes.append({"id": "start", "type": "start", "x": 50, "y": 50, "data": {}})

    prev_id = "start"

    # Insert Set Data node for inputs if provided
    if inputs_values:
        inputs_id = "set_inputs"
        nodes.append({
            "id": inputs_id,
            "type": "set_data",
            "x": 330,
            "y": 50,
            "data": {
                "saveTo": "inputs",
                "variables": _json.dumps(inputs_values, indent=2),
            },
        })
        connections.append({
            "from": prev_id, "fromPort": "out",
            "to": inputs_id, "toPort": "in",
        })
        prev_id = inputs_id

    for i, step in enumerate(steps):
        step_id = f"step_{i}"

        # Build HTTP Request node
        headers = step.get("headers")
        headers_str = _json.dumps(headers) if headers else ""
        save_to = step.get("name", f"response_{i}")

        nodes.append({
            "id": step_id,
            "type": "http_request",
            "x": 50 + (i + 1) * 280,
            "y": 50,
            "data": {
                "method": step.get("method", "GET"),
                "url": step.get("url", ""),
                "headers": headers_str,
                "body": step.get("body") or "",
                "saveTo": save_to,
            },
        })

        connections.append({
            "from": prev_id, "fromPort": "out",
            "to": step_id, "toPort": "in",
        })

        prev_id = step_id

        # If step has a condition, insert an Assert node after the request
        condition = step.get("condition")
        if condition:
            assert_id = f"assert_{i}"
            # Translate Arazzo runtime expression to ctx syntax
            cond_expr = _translate_condition(condition, save_to)
            nodes.append({
                "id": assert_id,
                "type": "assert",
                "x": 50 + (i + 1) * 280 + 200,
                "y": 200,
                "data": {
                    "label": f"Assert: {step.get('name', 'step')}",
                    "expression": cond_expr,
                },
            })
            connections.append({
                "from": step_id, "fromPort": "out",
                "to": assert_id, "toPort": "in",
            })
            prev_id = assert_id

    return {"nodes": nodes, "connections": connections}


_FORBIDDEN_EXPR = re.compile(
    r'(?:\b(?:eval|Function|constructor|__proto__|import|require|fetch|XMLHttpRequest'
    r'|document|window|self|top|parent|alert|prompt|confirm|setTimeout|setInterval'
    r'|location|open|close|write|writeln|execScript|execCommand|expression'
    r'|chrome|browser|process|global|globalThis)\b'
    r'|[`$<>]|=>|\\u[0-9a-fA-F]{4})'
)
_EXPR_MAX_LEN = 512


def _validate_expression(expr):
    if not expr or not isinstance(expr, str):
        return
    if len(expr) > _EXPR_MAX_LEN:
        raise ValueError(f"Expression too long (max {_EXPR_MAX_LEN} chars)")
    if _FORBIDDEN_EXPR.search(expr):
        raise ValueError(f"Expression contains forbidden pattern: {expr[:80]}")


def _translate_condition(condition: str, response_key: str) -> str:
    """Translate an Arazzo condition to an Elyria ctx expression.

    Arazzo: $statusCode == 200
    Elyria:  ctx.{response_key}.status_code === 200

    Arazzo: $response.body#/token != undefined
    Elyria:  JSON.parse(ctx.{response_key}.body).token !== undefined
    """
    expr = condition
    # $statusCode → ctx.{key}.status_code
    expr = expr.replace("$statusCode", f"ctx.{response_key}.status_code")
    # $response.header.X → ctx.{key}.headers["X"]
    expr = re.sub(r'\$response\.header\.(\S+)', lambda m: f'ctx.{response_key}.headers["{m.group(1)}"]', expr)
    # $response.body#/path → JSON.parse(ctx.{key}.body).path
    expr = re.sub(r'\$response\.body#/(\S+)', lambda m: f"JSON.parse(ctx.{response_key}.body).{m.group(1).replace('/', '.')}", expr)
    # $response.body → ctx.{key}.body (fallback)
    expr = expr.replace("$response.body", f"ctx.{response_key}.body")
    _validate_expression(expr)
    return expr


def import_to_db(parsed_workflows: list[dict], author_user_id: str, team_id: str = "", inputs_values: dict = None) -> dict:
    """Import Arazzo workflows into the new workflow graph storage.
    If inputs_values is provided (keyed by workflow name), injects a Set Data block
    to initialize ctx.inputs for each matching workflow.
    Returns {"workflow_ids": [...], "collection_name": ...}
    """
    from database.workflow_graph_mgmt import save_workflow

    if inputs_values is None:
        inputs_values = {}

    # If frontend sent inputs_values, treat as overrides
    has_fr_wf_keys = any(k in inputs_values for wf in parsed_workflows for k in [wf.get("name", "")])
    frontend_global = inputs_values.get("__global__") if "__global__" in inputs_values else (inputs_values if not has_fr_wf_keys and inputs_values else None)

    wf_ids = []
    for wf in parsed_workflows:
        wf_name = wf.get("name", "Unnamed Workflow")
        # Priority: frontend per-workflow > frontend global > auto-generated from Arazzo
        auto_inputs = wf.get("inputs")  # already generated by _extract_workflow_inputs
        fr_inputs = inputs_values.get(wf_name) or frontend_global
        wf_inputs = fr_inputs if fr_inputs else auto_inputs
        graph = _arazzo_steps_to_graph(wf.get("steps", []), inputs_values=wf_inputs)
        wf_id = save_workflow(
            name=wf_name,
            graph=graph,
            user_id=author_user_id,
            description=wf.get("description", ""),
            team_id=team_id,
        )
        if wf_id:
            wf_ids.append(wf_id)

    return {
        "workflow_ids": wf_ids,
        "collection_name": f"Arazzo Import ({len(wf_ids)} workflows)",
    }
