import ollama




class OllamaProvider:
    def __init__(self, model=None, host=None):
        self.model = model
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

    @staticmethod
    def list_models():
            return ollama.models()