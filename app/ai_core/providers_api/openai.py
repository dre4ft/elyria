# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

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
        }
        # DeepSeek-specific: enable reasoning
        if self.url and "deepseek" in self.url:
            params["reasoning_effort"] = "high"
            params["extra_body"] = {"thinking": {"type": "enabled"}}
        if tools:
            params["tools"] = tools

        response = self.client.chat.completions.create(**params)

        message = response.choices[0].message
        return {
            "content": message.content,
            "tool_calls": message.tool_calls if hasattr(message, 'tool_calls') else None,
            "reasoning_content": getattr(message, 'reasoning_content', None),
            "usage": {
                "prompt_tokens": response.usage.prompt_tokens if response.usage else 0,
                "completion_tokens": response.usage.completion_tokens if response.usage else 0,
                "total_tokens": response.usage.total_tokens if response.usage else 0,
            } if response.usage else None,
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

        