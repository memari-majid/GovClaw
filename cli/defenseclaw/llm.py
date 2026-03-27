# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""defenseclaw-llm — thin CLI bridge to litellm.

Called by the TypeScript plugin scanner (and anything else) via subprocess.
Uses the same litellm library as the skill scanner so provider routing,
API key handling, and model support are identical.

Usage:
  echo '{"model":"claude-sonnet-4-20250514","messages":[...]}' | python -m defenseclaw.llm
  python -m defenseclaw.llm --model claude-sonnet-4-20250514 --prompt "Analyze this code..."

Input (stdin JSON):
  {
    "model": "claude-sonnet-4-20250514",
    "messages": [{"role": "system", "content": "..."}, {"role": "user", "content": "..."}],
    "max_tokens": 8192,
    "temperature": 0.0,
    "api_key": "...",           // optional, falls back to env
    "api_base": "...",          // optional
    "provider": "anthropic"     // optional, litellm auto-detects from model name
  }

Output (stdout JSON):
  {
    "content": "...",           // assistant response text
    "model": "...",             // actual model used
    "usage": {"prompt_tokens": N, "completion_tokens": N, "total_tokens": N},
    "error": null               // or error message string
  }
"""

from __future__ import annotations

import json
import sys


def call_litellm(request: dict) -> dict:
    try:
        import litellm
    except ImportError:
        return {
            "content": "",
            "model": "",
            "usage": {},
            "error": "litellm not installed. Install with: pip install litellm",
        }

    model = request.get("model", "")
    messages = request.get("messages", [])
    max_tokens = request.get("max_tokens", 8192)
    temperature = request.get("temperature", 0.0)

    # Optional overrides
    api_key = request.get("api_key")
    api_base = request.get("api_base")

    kwargs: dict = {
        "model": model,
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": temperature,
    }
    if api_key:
        kwargs["api_key"] = api_key
    if api_base:
        kwargs["api_base"] = api_base

    try:
        response = litellm.completion(**kwargs)

        content = ""
        if response.choices and len(response.choices) > 0:
            content = response.choices[0].message.content or ""

        usage = {}
        if hasattr(response, "usage") and response.usage:
            usage = {
                "prompt_tokens": getattr(response.usage, "prompt_tokens", 0),
                "completion_tokens": getattr(response.usage, "completion_tokens", 0),
                "total_tokens": getattr(response.usage, "total_tokens", 0),
            }

        return {
            "content": content,
            "model": getattr(response, "model", model),
            "usage": usage,
            "error": None,
        }

    except Exception as exc:
        return {
            "content": "",
            "model": model,
            "usage": {},
            "error": str(exc),
        }


def main() -> None:
    # Read request from stdin
    raw = sys.stdin.read().strip()
    if not raw:
        json.dump({"content": "", "model": "", "usage": {}, "error": "empty input"}, sys.stdout)
        return

    try:
        request = json.loads(raw)
    except json.JSONDecodeError as exc:
        json.dump({"content": "", "model": "", "usage": {}, "error": f"invalid JSON: {exc}"}, sys.stdout)
        return

    result = call_litellm(request)
    json.dump(result, sys.stdout)


if __name__ == "__main__":
    main()
