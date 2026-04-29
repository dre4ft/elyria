from ai_core.providers_api import ollama as ollama_provider
from ai_core.providers_api import openai as openai_provider
from ai_core import tools as tools
import database.ai_mgmt as ai_mgmt

class AIWrapper:
    def __init__(self, provider_type, url=None, api_key=None, model=None):
        if provider_type == 'ollama':
            self.provider = ollama_provider.OllamaProvider(model=model, host=url)
        elif provider_type == 'openai':
            self.provider = openai_provider.OpenAIProvider(provider_url=url, api_key=api_key, model=model)
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
    
    def get_models(self):
        return self.provider.get_models()
    
    def get_config(self):
        return self.provider.get_config()