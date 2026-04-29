import ollama




class OllamaProvider:
    def __init__(self, model=None, host=None):
        self.model = model
        self.host = host if host else "http://localhost:11434"
        if host:
            ollama.set_host(host)

    def chat(self, messages: list, tools: list = None):
        params = {
            "model": self.model,
            "messages": messages,
            "stream": False,
        }
        if tools:
            params["tools"] = tools

        response = ollama.chat(**params)

        message = response['message']
        return {
            "content": message.get('content'),
            "tool_calls": message.get('tool_calls')
        }
    def update_model(self, model):
        self.model = model

    
    def get_models(self):
            return ollama.models()
    
    def get_config(self):
        return {
            "provider": "ollama",
            "model": self.model,
            "host": self.host
        }