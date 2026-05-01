from database import collection_mgmt, json_helper, request_mgmt
from request_manager.request_api import handle_raw, handle_request

def get_tools():
    return [
        {
            "type": "function",
            "function": {
                "name": "add_request",
                "description": "Add a new structured HTTP request for the user",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Name of the request"},
                        "folder_id": {"type": "string", "description": "ID of the folder to put the request in (optional)"},
                        "url": {"type": "string", "description": "URL of the request"},
                        "method": {"type": "string", "description": "HTTP method of the request"},
                        "headers": {"type": "string", "description": "Headers of the request (optional) in string format, will be parsed as JSON"},
                        "body": {"type": "string", "description": "Body of the request (optional)"},
                    },
                    "required": ["name", "url", "method"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "create_folder",
                "description": "Create a new folder in the user's collection",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Name of the folder"},
                        "parent_id": {"type": "string", "description": "ID of the parent folder if the folder is embedded (optional)"},
                    },
                    "required": ["name"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "send_request",
                "description": "Send an HTTP request and save it in the history",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "URL of the request"},
                        "method": {"type": "string", "description": "HTTP method of the request"},
                        "headers": {"type": "string", "description": "Headers of the request (optional) in string format, will be parsed as JSON"},
                        "body": {"type": "string", "description": "Body of the request (optional)"},
                    },
                    "required": ["url", "method"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "send_request_by_id",
                "description": "Send a previously saved request by its ID",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "request_id": {"type": "string", "description": "ID of the saved request to send"},
                    },
                    "required": ["request_id"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "send_raw_request",
                "description": "Send a raw HTTP request and save it in the history",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "URL of the request"},
                        "request": {"type": "string", "description": "Raw HTTP request as a string"},
                    },
                    "required": ["url", "request"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "get_sent_request_response",
                "description": "Get the response of a previously sent request by its UUID",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "request_uuid": {"type": "string", "description": "UUID of the sent request"},
                    },
                    "required": ["request_uuid"],
                },
            },
        },
    ]







def handle_tool_call(tool_name, parameters):
    if tool_name == "add_request":
        return create_structured_request(name=parameters["name"], url=parameters["url"], method=parameters["method"], folder_id=parameters.get("folder_id"), headers=parameters.get("headers"), body=parameters.get("body"))
    elif tool_name == "create_folder":
        return create_folder(name=parameters["name"], parent_id=parameters.get("parent_id"))
    elif tool_name == "get_sent_request_response":
        return get_sent_request_response(request_uuid=parameters["request_uuid"])
    elif tool_name == "send_request":
        return send_request(url=parameters["url"], method=parameters["method"], headers=parameters.get("headers"), body=parameters.get("body"))
    elif tool_name == "send_request_by_id":
        return send_request_by_id(request_id=parameters["request_id"])
    elif tool_name == "send_raw_request":
        return send_raw_request(url=parameters["url"], request=parameters["request"])
    else:
        raise ValueError(f"Unknown tool: {tool_name}")

def create_structured_request(name,  url, method,folder_id=None, headers=None, body=None):
    current_user_id = "a8e327d8-2939-4d36-a9c6-bf1b16793c33"  # TODO: get the actual user ID from the context/session
    headers = json_helper.from_json(headers) if headers else None
    request_id = collection_mgmt.create_saved_request(name=name, author_user_id=current_user_id, folder_id=folder_id, method=method, url=url, headers=headers, body=body, is_done_by_ai=True)
    return {"request_id": request_id}


def create_folder(name, parent_id=None):
    current_user_id = "a8e327d8-2939-4d36-a9c6-bf1b16793c33"  # TODO: get the actual user ID from the context/session
    folder_id = collection_mgmt.create_folder(name=name, author_user_id=current_user_id, parent_id=parent_id)
    return {"folder_id": folder_id}

def send_request(url:str, method: str, headers:str=None, body:str=None):
    current_user_id = "a8e327d8-2939-4d36-a9c6-bf1b16793c33"  # TODO: get the actual user ID from the context/session
    headers = json_helper.from_json(headers) if headers else None
    req_uuid, resp = handle_request(user_id=current_user_id, url=url, method=method, headers=headers, body=body, is_done_by_ai=True) 
    return {"response_uuid":req_uuid,"response": resp}

def send_request_by_id(request_id: str):
    current_user_id = "a8e327d8-2939-4d36-a9c6-bf1b16793c33"  # TODO: get the actual user ID from the context/session
    request = collection_mgmt.get_request_by_id(request_id)
    if not request:
        return {"error": f"Request with ID {request_id} not found"}
    if request["author_user_id"] != current_user_id:
        return {"error": "Unauthorized"}
    req_uuid, resp = handle_request(user_id=current_user_id, url=request["url"], method=request["method"], headers=json_helper.to_json(request["headers"]) if request["headers"] else None, body=request["body"], is_done_by_ai=True)
    return {"response_uuid": req_uuid, "response": resp}


def send_raw_request(url:str, request:str):
    current_user_id = "a8e327d8-2939-4d36-a9c6-bf1b16793c33"  # TODO: get the actual user ID from the context/session
    req_uuid, resp = handle_raw(user_token=current_user_id, url=url, request=request,is_done_by_ai=True)
    return {"response_uuid": req_uuid, "response": resp}

def get_sent_request_response(request_uuid: str):
    current_user_id = "a8e327d8-2939-4d36-a9c6-bf1b16793c33"  # TODO: get the actual user ID from the context/session
    response = request_mgmt.get_requests_by_id(request_uuid)
    if not response:
        return {"error": f"Request with UUID {request_uuid} not found"}
    if response["author"] != current_user_id:
        return {"error": "Unauthorized"}
    return {"response": response}

