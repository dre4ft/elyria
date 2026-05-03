import json
import re
import sys
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
        return "{{" + value[len("$inputs."):] + "}}"

    if value.startswith("$steps."):
        # $steps.loginUser.outputs.sessionToken → {{loginUser.sessionToken}}
        rest = value[len("$steps."):]
        if ".outputs." in rest:
            step_name, var = rest.split(".outputs.", 1)
            return "{{" + step_name + "." + var + "}}"
        return value

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




def parse_arazzo(arazzo_content: dict,
                 openapi_specs: Optional[dict[str, dict]] = None) -> list[dict]:
   
    validate(arazzo_content)

    if openapi_specs is None:
        openapi_specs = {}

    # Build case-insensitive lookup for source description names
    _specs_ci = {k.lower(): v for k, v in openapi_specs.items()}

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

            if op_operation is None:
                # Placeholder — can't resolve without the OpenAPI spec
                steps.append({
                    "name": step_name,
                    "method": "GET",
                    "url": "",
                    "headers": None,
                    "body": None,
                    "captures": _extract_captures(step),
                    "condition": _extract_condition(step),
                })
                continue

            # Merge parameters
            openapi_params = op_operation.get("parameters", [])
            arazzo_params = step.get("parameters", [])
            path_p, query_p, header_p = _merge_params(openapi_params, arazzo_params)

            # Build URL
            base_url = openapi_spec["servers"][0]["url"] if openapi_spec.get("servers") else ""
            url = base_url.rstrip("/") + "/" + op_path.lstrip("/")
            for name, value in path_p.items():
                url = url.replace(f"{{{name}}}", str(value))
            if query_p:
                qs = "&".join(f"{k}={v}" for k, v in query_p.items())
                url = f"{url}?{qs}"

            # Headers
            headers = dict(header_p) if header_p else {}

            # Body
            body = None
            request_body = op_operation.get("requestBody")
            if request_body and openapi_spec:
                body_content = request_body.get("content", {})
                if "application/json" in body_content:
                    from doc_mgmt.openapi.parser import _schema_to_example
                    schema = body_content["application/json"].get("schema", {})
                    example = _schema_to_example(schema, openapi_spec)
                    body = json.dumps(example, indent=2)
                    headers["Content-Type"] = "application/json"

            steps.append({
                "name": step_name,
                "method": op_method.upper(),
                "url": url,
                "headers": headers if headers else None,
                "body": body,
                "captures": _extract_captures(step),
                "condition": _extract_condition(step),
            })

        workflows.append({
            "name": wf_name,
            "description": wf_desc,
            "steps": steps,
        })

    return workflows



def import_to_db(parsed_workflows: list[dict], author_user_id: str) -> list[str]:
    from database import workflow_mgmt

    wf_ids = []
    for wf in parsed_workflows:
        wf_id = workflow_mgmt.create_workflow(
            name=wf["name"],
            author_user_id=author_user_id,
            description=wf.get("description"),
        )
        if wf_id:
            wf_ids.append(wf_id)
            for step in wf["steps"]:
                workflow_mgmt.create_step(
                    workflow_id=wf_id,
                    name=step["name"],
                    method=step.get("method", "GET"),
                    url=step.get("url", ""),
                    headers=step.get("headers"),
                    body=step.get("body"),
                    captures=step.get("captures"),
                    condition=step.get("condition"),
                )
    return wf_ids
