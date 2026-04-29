import json


def from_json(data: dict | list | None) -> str | None:
    if data is None:
        return None
    return json.dumps(data)


def to_json(data: str | None)-> dict | list | None:
    if data is None:
        return None
    return json.loads(data)


def serialize_body(body):
    if body is None:
        return None, 0

    if isinstance(body, (dict, list)):
        return json.dumps(body), 1

    return str(body), 0 

def deserialize_body(body, is_json):
    if body is None:
        return None

    if is_json:
        import json
        return json.loads(body)

    return body