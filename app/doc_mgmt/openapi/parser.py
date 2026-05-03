from pydantic import BaseModel
import json
from typing import Optional


class OpenAPIRequest(BaseModel):
    name: str
    url: str
    method: str
    headers: Optional[dict] = None
    body: Optional[str] = None


def validate(content: dict):
    if content.get("openapi") and content["openapi"].startswith("3."):
        return content["openapi"]
    elif content.get("swagger") and content["swagger"].startswith("2."):
        return content["swagger"]
    else:
        raise ValueError("Unsupported OpenAPI version or missing version field")



def resolve_href(ref: str, content: dict):
    if not ref.startswith("#/"):
        raise ValueError(f"Only local $ref are supported, got: {ref}")
    path = ref[2:].split("/")
    current = content
    for segment in path:
        if segment not in current:
            raise ValueError(f"Cannot resolve $ref '{ref}': segment '{segment}' not found")
        current = current[segment]
    return current



def _schema_to_example(schema: dict, content: dict, depth: int = 0) -> any:
    if depth > 10:
        return None

    if "$ref" in schema:
        resolved = resolve_href(schema["$ref"], content)
        return _schema_to_example(resolved, content, depth + 1)

    if "example" in schema:
        return schema["example"]

    schema_type = schema.get("type", "object")

    if schema_type == "string":
        if "enum" in schema:
            return schema["enum"][0]
        if schema.get("format") == "date-time":
            return "2024-01-01T00:00:00Z"
        if schema.get("format") == "date":
            return "2024-01-01"
        if schema.get("format") == "binary":
            return "(binary)"
        return schema.get("default", "string")

    if schema_type == "integer":
        return schema.get("default", 0)

    if schema_type == "number":
        return schema.get("default", 0.0)

    if schema_type == "boolean":
        return schema.get("default", False)

    if schema_type == "array":
        items_schema = schema.get("items", {"type": "string"})
        return [_schema_to_example(items_schema, content, depth + 1)]

    if schema_type == "object":
        obj = {}
        for prop_name, prop_schema in schema.get("properties", {}).items():
            obj[prop_name] = _schema_to_example(prop_schema, content, depth + 1)
        return obj

    return None


def _extract_params(operation: dict, param_in: str) -> Optional[dict]:
    params = {}
    for param in operation.get("parameters", []):
        if param.get("in") == param_in:
            name = param["name"]
            schema = param.get("schema", {})
            if "example" in schema:
                params[name] = schema["example"]
            elif "default" in schema:
                params[name] = schema["default"]
            elif schema.get("type") == "integer":
                params[name] = 0
            elif schema.get("type") == "boolean":
                params[name] = False
            elif schema.get("type") == "array":
                params[name] = "item1,item2"
            else:
                params[name] = "string"
    return params if params else None


def _build_url(base_url: str, path: str, path_params: list[dict], query_params: Optional[dict]) -> str:
    url = base_url.rstrip("/") + "/" + path.lstrip("/")
    for param in path_params:
        if param.get("in") == "path":
            name = param["name"]
            schema = param.get("schema", {})
            if schema.get("type") == "integer":
                value = str(schema.get("example", schema.get("default", 1)))
            else:
                value = str(schema.get("example", schema.get("default", "string")))
            url = url.replace(f"{{{name}}}", value)
    if query_params:
        qs = "&".join(f"{k}={v}" for k, v in query_params.items())
        url = f"{url}?{qs}"
    return url


def _extract_body(operation: dict, content: dict) -> tuple:
    request_body = operation.get("requestBody")
    if not request_body:
        return {}, None

    body_content = request_body.get("content", {})
    preferred = ["application/json", "application/x-www-form-urlencoded",
                 "application/xml", "application/octet-stream", "*/*"]

    for ct in preferred:
        if ct in body_content:
            schema = body_content[ct].get("schema", {})
            example = _schema_to_example(schema, content)
            headers = {"Content-Type": ct}

            if ct == "application/octet-stream":
                return headers, "(binary data)"

            if isinstance(example, (dict, list)):
                return headers, json.dumps(example, indent=2)
            return headers, str(example) if example is not None else ""

    # Fallback: first available content type
    for ct, ct_spec in body_content.items():
        schema = ct_spec.get("schema", {})
        example = _schema_to_example(schema, content)
        headers = {"Content-Type": ct}
        if isinstance(example, (dict, list)):
            return headers, json.dumps(example, indent=2)
        return headers, str(example) if example is not None else ""

    return {}, None


def parse_openapi(content: dict) -> dict:
    validate(content)

    info = content.get("info", {})
    title = info.get("title", "OpenAPI Collection")
    base_url = content["servers"][0]["url"] if content.get("servers") else "http://INSERT-YOUR-HOST"

    tagged: dict[str, list[OpenAPIRequest]] = {}
    untagged: list[OpenAPIRequest] = []

    methods = ["get", "post", "put", "patch", "delete", "options", "head"]

    for path, path_item in content.get("paths", {}).items():
        for method in methods:
            operation = path_item.get(method)
            if not operation:
                continue

            op_id = operation.get("operationId", f"{method.upper()} {path}")
            tags = operation.get("tags", [])
            tag = tags[0] if tags else None

            query_params = _extract_params(operation, "query")
            url = _build_url(base_url, path, operation.get("parameters", []), query_params)

            header_params = _extract_params(operation, "header")
            body_headers, body_str = _extract_body(operation, content)

            headers = {}
            if header_params:
                headers.update(header_params)
            if body_headers:
                headers.update(body_headers)

            request = OpenAPIRequest(
                name=op_id,
                url=url,
                method=method.upper(),
                headers=headers if headers else None,
                body=body_str,
            )

            if tag:
                tagged.setdefault(tag, []).append(request)
            else:
                untagged.append(request)

    folders = []
    for tag, requests in tagged.items():
        folders.append({
            "name": tag,
            "requests": [r.model_dump() for r in requests],
        })

    if untagged:
        folders.append({
            "name": "default",
            "requests": [r.model_dump() for r in untagged],
        })

    return {
        "title": title,
        "base_url": base_url,
        "folders": folders,
    }




def import_to_db(parsed: dict, author_user_id: str) -> dict:
    
    from database import collection_mgmt

    root_folder_id = collection_mgmt.create_folder(
        name=parsed["title"],
        author_user_id=author_user_id,
        parent_id=None,
    )

    folder_ids = {}
    for folder in parsed["folders"]:
        fid = collection_mgmt.create_folder(
            name=folder["name"],
            author_user_id=author_user_id,
            parent_id=root_folder_id,
        )
        if fid:
            folder_ids[folder["name"]] = fid
            for req in folder["requests"]:
                collection_mgmt.create_saved_request(
                    name=req["name"],
                    author_user_id=author_user_id,
                    folder_id=fid,
                    method=req["method"],
                    url=req["url"],
                    headers=req.get("headers"),
                    body=req.get("body"),
                )

    return {
        "root_folder_id": root_folder_id,
        "folders": folder_ids,
    }


