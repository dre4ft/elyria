"""
    {
        "type": "function_call_output",
        "call_id": item.call_id,
        "output": get_weather(json.loads(item.arguments))
    }

"""



tools = []