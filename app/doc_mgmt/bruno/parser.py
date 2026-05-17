"""Parse Bruno collection files (.bru format) into Elyria saved requests.

Bruno uses a plain-text format, one .bru file per request:
```
meta {
  name: Get Users
  type: http
  seq: 1
}
get {
  url: https://api.example.com/users
  body: none
  auth: bearer
}
headers {
  Authorization: Bearer {{token}}
}
```

Bruno also supports a folder-structure on disk. We parse a bundle (zip or json export).
For a zip, each .bru file is parsed individually.
For a JSON export, the structure is {name, type, request: {method, url, headers, body}}.
"""

import json
import re


def parse_bruno(raw: str, filename: str = "") -> dict:
    """Parse a Bruno export file.

    Supports:
    - Single .bru file
    - JSON collection export
    - JSON insights export
    Returns {collection_name, folders: [], requests: [...]}
    """
    raw = raw.strip()

    # JSON export
    if raw.startswith("{"):
        return _parse_bruno_json(raw)

    # Plain .bru format
    return _parse_bruno_bru(raw, filename)


def _parse_bruno_json(raw: str) -> dict:
    data = json.loads(raw)
    name = data.get("name", "Bruno Import")
    items = data.get("items", data.get("requests", []))

    requests = []
    for item in items:
        if isinstance(item, str):
            # Just a URL or name
            requests.append({"name": item, "method": "GET", "url": item, "headers": None, "body": None, "folder_id": None})
        elif isinstance(item, dict):
            req = item.get("request", item)
            requests.append({
                "name": item.get("name", req.get("url", "Unnamed")),
                "method": req.get("method", "GET").upper(),
                "url": req.get("url", ""),
                "headers": req.get("headers"),
                "body": req.get("body"),
                "folder_id": None,
            })

    return {"collection_name": name, "folders": [], "requests": requests}


def _parse_bruno_bru(raw: str, filename: str = "") -> dict:
    """Parse a single .bru file content."""
    name = filename.replace(".bru", "") or "Unnamed"
    method = "GET"
    url = ""
    headers = None
    body = None

    # Extract meta block
    meta_match = re.search(r'meta\s*\{([^}]*)\}', raw, re.DOTALL)
    if meta_match:
        meta = meta_match.group(1)
        for line in meta.split("\n"):
            line = line.strip()
            if line.startswith("name:"):
                name = line.split(":", 1)[1].strip()
            elif line.startswith("type:"):
                pass  # http, graphql, etc.

    # Extract method block
    method_match = re.search(r'(get|post|put|patch|delete|head|options)\s*\{([^}]*)\}', raw, re.IGNORECASE | re.DOTALL)
    if method_match:
        method = method_match.group(1).upper()
        block = method_match.group(2)
        for line in block.split("\n"):
            line = line.strip()
            if line.startswith("url:"):
                url = line.split(":", 1)[1].strip()
            elif line.startswith("body:"):
                body_type = line.split(":", 1)[1].strip()
                if body_type == "json":
                    # Body content follows in a body block
                    body_match = re.search(r'body:json\s*\{([^}]*)\}', raw, re.DOTALL)
                    if body_match:
                        body = body_match.group(1).strip()

    # Extract headers
    headers_match = re.search(r'headers\s*\{([^}]*)\}', raw, re.DOTALL)
    if headers_match:
        headers = {}
        for line in headers_match.group(1).split("\n"):
            line = line.strip()
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()

    # Extract body block (json, text, multipart)
    body_block = re.search(r'body\s*\{([^}]*)\}', raw, re.DOTALL)
    if body_block:
        body_content = body_block.group(1).strip()
        # Check if it's json body
        json_match = re.search(r'"([^"]*)"\s*:\s*"([^"]*)"', body_content)
        if json_match:
            body = body_content
        else:
            body = body_content

    if not url:
        # Try to find URL in raw text
        url_match = re.search(r'https?://[^\s]+', raw)
        if url_match:
            url = url_match.group(0)

    return {
        "collection_name": name,
        "folders": [],
        "requests": [{"name": name, "method": method, "url": url, "headers": headers, "body": body, "folder_id": None}],
    }
