import json
from typing import Literal

import openai
import rich
from dotenv import load_dotenv
from app.ai_core.providers_api.openai import OpenAI
from pydantic import BaseModel

load_dotenv()

# Define a Pydantic model to use for structured output
class WeatherReport(BaseModel):
    location: str
    temperature: float
    unit: Literal["C", "F"]
    humidity: int | None = None
    wind_speed: int | None = None
    wind_direction: str | None = None
    precipitation: str | None = None


def get_weather(location: str) -> str:
    return f"The weather in {location} is sunny and 20 degrees Celsius. No information about humidity, wind speed, wind direction, or precipitation."


tools = [
    openai.pydantic_function_tool(WeatherReport),
    {
        "type": "function",
        "name": "get_weather",
        "description": "Get the current weather in a given location",
        "parameters": {
            "type": "object",
            "properties": {
                "location": {
                    "type": "string",
                    "description": "The city e.g. Paris",
                },
            },
            "required": ["location"],
        },
    }
]


client = OpenAI()
instructions = "Use the WeatherReport tool when replying to the user"
input_list = [{"role": "user", "content": "Give me the weather report for Paris"}]

response = client.responses.parse(
    model="gpt-4.1-nano",
    instructions=instructions,
    input=input_list,
    tools=tools,
)

# Save function call outputs for subsequent requests
input_list += response.output

# Validate that response is a function call
function_call = response.output[0]
assert function_call.type == "function_call"

# Call the tool
item = response.output[0]
if item.type == "function_call" and item.name == "get_weather":
    input_list.append({
        "type": "function_call_output",
        "call_id": item.call_id,
        "output": get_weather(json.loads(item.arguments))
    })
    # Call the model with the tool call output
    response_2 = client.responses.parse(
        model="gpt-4.1-mini",
        instructions=instructions,
        input=input_list,
        tools=tools,
    )

    # Validate that response is again a function call
    function_call = response_2.output[0]
    assert function_call.type == "function_call"

    # Get the structured output through the function call output
    rich.print(function_call.parsed_arguments)
    # >>> WeatherReport(
        #     location='Paris',
        #     temperature=20.0,
        #     unit='C',
        #     humidity=None,
        #     wind_speed=None,
        #     wind_direction=None,
        #     precipitation=None
        # )