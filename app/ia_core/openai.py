from openai import OpenAI




class OpenAIProvider:
    def __init__(self,provider_url,api_key,model):
        self.url = provider_url
        self.key = api_key
        self.model = model 
        self.client =  OpenAI(
                        api_key=self.key,
                        base_url=self.url)
        

    def chat(self,messages:list):
        response = self.client.chat.completions.create(
        model=self.model,
        messages=messages,
        stream=False,
        )

        return response.choices[0].message.content
        
        