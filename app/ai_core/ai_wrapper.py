import json

from ai_core.providers_api import ollama as ollama_provider
from ai_core.providers_api import openai as openai_provider
from ai_core import tools as tools
import database.ai_mgmt as ai_mgmt




class AIWrapper:
    def __init__(self, provider_type, url=None, api_key=None, model=None, tools_rounds :int =5):
        if provider_type == 'ollama':
            self.provider = ollama_provider.OllamaProvider(model=model, host=url)
        elif provider_type == 'openai':
            self.provider = openai_provider.OpenAIProvider(provider_url=url, api_key=api_key, model=model)
        else:
            raise ValueError(f"Unsupported provider type: {provider_type}")
        self.tools = tools.get_tools()
        self.rounds = tools_rounds

    def chat(self, message: str, user_id: str, conversation_id: str = None):
        conversation_id = ai_mgmt.add_message(self.message_wrapper(message), user_id, conversation_id)
        if not conversation_id:
            raise ValueError("Failed to save message")

        for _ in range(self.rounds):
            messages = ai_mgmt.get_conversation_messages(conversation_id=conversation_id)
            ai_return = self.provider.chat(messages, tools=self.tools)

            assistant_msg = {"role": "assistant", "content": ai_return["content"]}
            if ai_return.get("reasoning_content"):
                assistant_msg["reasoning_content"] = ai_return["reasoning_content"]

            raw_tool_calls = ai_return.get("tool_calls")
            if raw_tool_calls:
                assistant_msg["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    }
                    for tc in raw_tool_calls
                ]

            conversation_id = ai_mgmt.add_message(assistant_msg, user_id, conversation_id)
            if not conversation_id:
                raise ValueError("Failed to save message")

            if raw_tool_calls:
                for tc in raw_tool_calls:
                    tool_params = json.loads(tc.function.arguments)
                    tool_response = tools.handle_tool_call(user_id, tc.function.name, tool_params)
                    tool_msg = {
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": json.dumps(tool_response),
                    }
                    conversation_id = ai_mgmt.add_message(tool_msg, user_id, conversation_id)
                    if not conversation_id:
                        raise ValueError("Failed to save tool response")
            else:
                return {"conversation_id": conversation_id, "response": ai_return}

        messages = ai_mgmt.get_conversation_messages(conversation_id=conversation_id)
        ai_return = self.provider.chat(messages)
        final_msg = {"role": "assistant", "content": ai_return["content"]}
        if ai_return.get("reasoning_content"):
            final_msg["reasoning_content"] = ai_return["reasoning_content"]
        conversation_id = ai_mgmt.add_message(final_msg, user_id, conversation_id)
        return {"conversation_id": conversation_id, "response": ai_return}

    def message_wrapper(self, message: str, role: str = "user"):
        return {"role": role, "content": message}

    def update_model(self, model):
        self.provider.update_model(model)

    def get_models(self):
        return self.provider.get_models()

    def get_config(self):
        return self.provider.get_config()