import uuid_utils

def _generate_request_uuid()->str:
    return str(uuid_utils.uuid4())
