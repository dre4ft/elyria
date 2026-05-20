# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

import app.ai_core.providers_api.lmstudio as lms


class LMStudioProvider:
    def __init__(self, model):
        self.model = model
        self.client = lms.Client()

    def chat(self, messages: list, tools: list = None):
        params = {
            "model": self.model,
            "messages": messages,
            "stream": False,
        }
        if tools:
            params["tools"] = tools

        response = self.client.chat.completions.create(**params)

        message = response.choices[0].message
        return {
            "content": message.content,
            "tool_calls": message.tool_calls if hasattr(message, 'tool_calls') else None
        }


