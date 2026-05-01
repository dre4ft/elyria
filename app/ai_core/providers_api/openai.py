from openai import OpenAI




class OpenAIProvider:
    def __init__(self,provider_url,api_key,model=None):
        self.url = provider_url
        self.key = api_key
        self.model = model 
        self.client =  OpenAI(
                        api_key=self.key,
                        base_url=self.url)
        

    def chat(self, messages: list, tools: list = None):
        params = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "reasoning_effort": "high",
            "extra_body": {"thinking": {"type": "enabled"}}
        }
        if tools:
            params["tools"] = tools

        response = self.client.chat.completions.create(**params)

        message = response.choices[0].message
        return {
            "content": message.content,
            "tool_calls": message.tool_calls if hasattr(message, 'tool_calls') else None,
            "reasoning_content": getattr(message, 'reasoning_content', None),
        }
    
    def update_model(self, model):
        self.model = model
        
    def get_models(self):
        return self.client.models.list()
    
    def get_config(self):
        return {
            "provider": "openai",
            "model": self.model,
            "url": self.url
        }

        