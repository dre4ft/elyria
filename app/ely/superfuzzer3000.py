"""
create fuzzing payload for requests API 

"""


from request_manager.request_api import _make_request
from core.logging import get_logger

_log = get_logger("ely.superfuzzer3000")



_FUZZ = "{{FUZZ}}"

def sniperfuzz(request: dict,payloads:list) -> list:
    """Generate a list of fuzzing payloads for the given request."""
    method = request.get("method", "GET")
    url = request.get("url", "")
    headers = request.get("headers", {})
    body = request.get("body", "")


    to_return = []
    for item in payloads:
        payload = item.get("payload", "")
        if not payload:
            continue

        fuzzed_url = url.replace(_FUZZ, payload)
        fuzzed_headers = {k: v.replace(_FUZZ, payload) for k, v in headers.items()}
        fuzzed_body = body.replace(_FUZZ, payload)

        fuzzed_request = {
            "method": method,
            "url": fuzzed_url,
            "headers": fuzzed_headers,
            "body": fuzzed_body,
        }
        _log.debug(f"Generated fuzzed request: {fuzzed_request}")
        to_return.append(fuzzed_request)

    return to_return




def fuzz_and_send(request: dict, payloads:list,fuzzing_type:str="sniper") -> list:
    """Generate fuzzed requests and send them using the request API."""
    if fuzzing_type == "sniper":
        fuzzed_requests = sniperfuzz(request, payloads)
    else:
        _log.warning(f"Fuzzing type {fuzzing_type} not supported. Defaulting to sniper.")
        raise ValueError(f"Fuzzing type {fuzzing_type} not supported. Only 'sniper' is implemented.")
    responses = []
    for fuzzed_request in fuzzed_requests:
        response = _make_request(url=fuzzed_request["url"], method=fuzzed_request["method"], headers=fuzzed_request["headers"], body=fuzzed_request["body"])
        responses.append(response)
        _log.debug(f"Received response: {response}")
    return responses