"""Parse Postman v2.0/v2.1 collection JSON into Elyria saved requests.

Postman format:
{
  "info": {"name": "...", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/"},
  "item": [
    {"name": "Get Users", "request": {"method": "GET", "url": {...}, "header": [...], "body": {...}}},
    {"name": "Folder", "item": [...]}
  ]
}
"""

import json
import uuid


def parse_postman(raw: str) -> dict:
    """Parse a Postman collection JSON string.
    Returns {folders: [...], requests: [...]} for the collection API.
    """
    data = json.loads(raw)
    info = data.get("info", {})
    collection_name = info.get("name", "Postman Import")
    items = data.get("item", [])

    folders = []
    requests = []

    def _walk(items, parent_id=None):
        for item in items:
            name = item.get("name", "Unnamed")
            if "item" in item:
                # It's a folder
                fid = str(uuid.uuid4())
                folders.append({"id": fid, "name": name, "parent_id": parent_id})
                _walk(item["item"], fid)
            elif "request" in item:
                req = item["request"]
                method = req.get("method", "GET").upper()
                url = _build_url(req.get("url", {}))
                headers = _build_headers(req.get("header", []))
                body = _build_body(req.get("body"))
                requests.append({
                    "name": name,
                    "method": method,
                    "url": url,
                    "headers": headers,
                    "body": body,
                    "folder_id": parent_id,
                })

    _walk(items)
    return {
        "collection_name": collection_name,
        "folders": folders,
        "requests": requests,
    }


def _build_url(url_obj) -> str:
    if isinstance(url_obj, str):
        return url_obj
    raw = url_obj.get("raw", "")
    if raw:
        return raw
    # Reconstruct from parts
    protocol = url_obj.get("protocol", "https")
    host = ".".join(url_obj.get("host", []))
    port = url_obj.get("port", "")
    path = "/".join(url_obj.get("path", [])) if url_obj.get("path") else ""
    query = []
    for q in url_obj.get("query", []):
        if q.get("value"):
            query.append(f"{q['key']}={q['value']}")
        else:
            query.append(q["key"])
    url = f"{protocol}://{host}"
    if port:
        url += f":{port}"
    if path:
        url += "/" + path
    if query:
        url += "?" + "&".join(query)
    return url


def _build_headers(header_list: list) -> dict:
    result = {}
    for h in header_list:
        key = h.get("key", "")
        value = h.get("value", "")
        if key:
            result[key] = value
    return result if result else None


def _build_body(body_obj) -> str | None:
    if not body_obj:
        return None
    mode = body_obj.get("mode", "")
    if mode == "raw":
        return body_obj.get("raw", "")
    if mode == "urlencoded":
        pairs = body_obj.get("urlencoded", [])
        return "&".join(f"{p['key']}={p['value']}" for p in pairs if p.get("key"))
    if mode == "formdata":
        return json.dumps(body_obj.get("formdata", []))
    return body_obj.get("raw", "")
