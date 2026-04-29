from ai_core import ollama as ollama_provider
from ai_core import openai as openai_provider
from ai_core import tools as tools
import database.ai_mgmt as ai_mgmt

class AIWrapper:
    def __init__(self, provider_type, **kwargs):
        if provider_type == 'ollama':
            self.provider = ollama_provider.OllamaProvider(**kwargs)
        elif provider_type == 'openai':
            self.provider = openai_provider.OpenAIProvider(**kwargs)
        else:
            raise ValueError(f"Unsupported provider type: {provider_type}")
        self.tools = tools.tools

    def chat(self, message: str, user_id: str, conversation_id: str = None):
        conv_id = ai_mgmt.add_message(message, user_id, conversation_id)
        if not conv_id:
            raise ValueError("Failed to save message")
        messages = ai_mgmt.get_conversation_messages(conversation_id) if conversation_id else []
        messages.append({"role": "user", "content": message})
        return {"conversation_id": conv_id, "response": self.provider.chat(messages)}
    
    def update_model(self, model):
        self.provider.update_model(model)
    
    @staticmethod
    def list_models(provider_type):
        if provider_type == 'ollama':
            return ollama_provider.OllamaProvider.list_models()
        elif provider_type == 'openai':
            return openai_provider.OpenAIProvider.list_models()
        else:
            raise ValueError(f"Unsupported provider type: {provider_type}")