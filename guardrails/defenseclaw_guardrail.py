"""DefenseClaw LiteLLM Guardrail — LLM traffic inspection for agentic AI.

Intercepts all prompts and completions flowing through the LiteLLM proxy.
Operates in two modes (set via DEFENSECLAW_GUARDRAIL_MODE env var):

  observe  — log findings, never block (default)
  action   — block prompts/responses that match security policies
"""

from __future__ import annotations

import json
import os
import time
import urllib.request
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from litellm.integrations.custom_guardrail import CustomGuardrail

if TYPE_CHECKING:
    from litellm.caching.caching import DualCache
    from litellm.proxy._types import UserAPIKeyAuth

BLUE = "\033[94m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

INJECTION_PATTERNS = [
    "ignore previous", "ignore all instructions", "ignore above",
    "disregard previous", "disregard all", "you are now",
    "act as", "pretend you are", "bypass", "jailbreak",
    "do anything now", "dan mode",
]

SECRET_PATTERNS = [
    "sk-", "sk-ant-", "sk-proj-", "api_key=", "apikey=",
    "-----begin rsa", "-----begin private", "-----begin openssh",
    "aws_access_key", "aws_secret_access", "password=",
    "token:", "bearer ", "ghp_", "gho_", "github_pat_",
]

EXFIL_PATTERNS = [
    "/etc/passwd", "/etc/shadow", "base64 -d", "base64 --decode",
    "exfiltrate", "send to my server", "curl http",
]


class DefenseClawGuardrail(CustomGuardrail):
    """LiteLLM custom guardrail for DefenseClaw."""

    def __init__(self, **kwargs: Any) -> None:
        self.mode: str = os.getenv("DEFENSECLAW_GUARDRAIL_MODE", "observe")
        super().__init__(**kwargs)

    # ------------------------------------------------------------------
    # Inspection
    # ------------------------------------------------------------------

    @staticmethod
    def _scan_patterns(text: str, patterns: list[str]) -> list[str]:
        lower = text.lower()
        return [p for p in patterns if p in lower]

    def _inspect(self, direction: str, content: str) -> dict[str, Any]:
        flags: list[str] = []
        if direction == "prompt":
            flags.extend(self._scan_patterns(content, INJECTION_PATTERNS))
            flags.extend(self._scan_patterns(content, EXFIL_PATTERNS))
        flags.extend(self._scan_patterns(content, SECRET_PATTERNS))

        if not flags:
            return {"action": "allow", "severity": "NONE", "reason": "", "findings": []}

        severity = "HIGH" if any(
            p in flags for p in INJECTION_PATTERNS + EXFIL_PATTERNS
        ) else "MEDIUM"

        return {
            "action": "block" if severity in ("HIGH", "CRITICAL") else "alert",
            "severity": severity,
            "reason": f"matched: {', '.join(flags[:5])}",
            "findings": flags,
        }

    # ------------------------------------------------------------------
    # PRE-CALL: inspect prompt before it reaches the LLM
    # ------------------------------------------------------------------

    async def async_pre_call_hook(
        self,
        user_api_key_dict: UserAPIKeyAuth,
        cache: DualCache,
        data: dict[str, Any],
        call_type: Any | None = None,
    ) -> Exception | str | dict[str, Any] | None:
        messages = data.get("messages", [])
        text = self._messages_to_text(messages)
        if not text:
            return data

        model = data.get("model", "?")
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        t0 = time.monotonic()

        verdict = self._inspect("prompt", text)
        elapsed_ms = (time.monotonic() - t0) * 1000

        severity = verdict.get("severity", "NONE")
        action = verdict.get("action", "allow")
        reason = verdict.get("reason", "")

        self._log_pre_call(ts, model, messages, severity, action, reason, elapsed_ms)
        self._report_to_sidecar("prompt", model, verdict, elapsed_ms)

        if action == "block" and self.mode == "action":
            data["mock_response"] = self._block_message("prompt", reason)
            return data

        return data

    # ------------------------------------------------------------------
    # POST-CALL: inspect completion after LLM responds
    # ------------------------------------------------------------------

    async def async_post_call_success_hook(
        self,
        data: dict[str, Any],
        user_api_key_dict: UserAPIKeyAuth,
        response: Any,
    ) -> None:
        import litellm

        content = ""
        tool_calls: list[dict[str, str]] = []
        if isinstance(response, litellm.ModelResponse):
            for choice in response.choices:
                if hasattr(choice, "message"):
                    if choice.message.content:
                        content += choice.message.content
                    if (
                        hasattr(choice.message, "tool_calls")
                        and choice.message.tool_calls
                    ):
                        for tc in choice.message.tool_calls:
                            tool_calls.append({
                                "name": tc.function.name if tc.function else "?",
                                "args": (tc.function.arguments or "")[:200]
                                if tc.function else "",
                            })

        if not content and not tool_calls:
            return

        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        model = getattr(response, "model", "?")
        usage = getattr(response, "usage", None)
        t0 = time.monotonic()

        verdict = self._inspect("completion", content)
        elapsed_ms = (time.monotonic() - t0) * 1000

        severity = verdict.get("severity", "NONE")
        action = verdict.get("action", "allow")
        reason = verdict.get("reason", "")

        self._log_post_call(
            ts, model, content, tool_calls, severity, action, reason,
            usage, elapsed_ms,
        )

        t_in = getattr(usage, "prompt_tokens", None) if usage else None
        t_out = getattr(usage, "completion_tokens", None) if usage else None
        self._report_to_sidecar(
            "completion", model, verdict, elapsed_ms,
            tokens_in=t_in, tokens_out=t_out,
        )

        if action == "block" and self.mode == "action":
            self._replace_response(response, reason)

    # ------------------------------------------------------------------
    # Sidecar telemetry reporter
    # ------------------------------------------------------------------

    def _report_to_sidecar(
        self,
        direction: str,
        model: str,
        verdict: dict[str, Any],
        elapsed_ms: float,
        *,
        tokens_in: int | None = None,
        tokens_out: int | None = None,
    ) -> None:
        """Fire-and-forget POST to the Go sidecar's guardrail event endpoint."""
        port = os.environ.get("DEFENSECLAW_API_PORT")
        if not port:
            return
        try:
            payload: dict[str, Any] = {
                "direction": direction,
                "model": model,
                "action": verdict.get("action", "allow"),
                "severity": verdict.get("severity", "NONE"),
                "reason": verdict.get("reason", ""),
                "findings": verdict.get("findings", []),
                "elapsed_ms": elapsed_ms,
            }
            if tokens_in is not None:
                payload["tokens_in"] = tokens_in
            if tokens_out is not None:
                payload["tokens_out"] = tokens_out
            data = json.dumps(payload).encode()
            req = urllib.request.Request(
                f"http://127.0.0.1:{int(port)}/v1/guardrail/event",
                data=data,
                headers={
                    "Content-Type": "application/json",
                    "X-DefenseClaw-Client": "litellm-guardrail",
                },
                method="POST",
            )
            urllib.request.urlopen(req, timeout=2)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    def _log_pre_call(
        self, ts: str, model: str, messages: list[dict[str, Any]],
        severity: str, action: str, reason: str, elapsed_ms: float,
    ) -> None:
        sev_color = GREEN if severity == "NONE" else YELLOW if severity == "MEDIUM" else RED
        print(f"\n{BOLD}{BLUE}{'─'*60}{RESET}")
        print(
            f"{BLUE}[{ts}]{RESET} {BOLD}PRE-CALL{RESET}  "
            f"model={model}  messages={len(messages)}  "
            f"{DIM}{elapsed_ms:.0f}ms{RESET}"
        )

        for i, msg in enumerate(messages):
            role = msg.get("role", "?")
            text = self._extract_content(msg)
            preview = text[:120] + ("..." if len(text) > 120 else "")
            rc = YELLOW if role == "user" else GREEN if role == "assistant" else DIM
            print(f"  {DIM}[{i}]{RESET} {rc}{role}{RESET}: {preview}")

        verdict_label = f"{sev_color}{severity}{RESET}"
        if severity == "NONE":
            print(f"  verdict: {verdict_label}")
        else:
            print(f"  verdict: {verdict_label}  action={action}  {reason}")
        print(f"{BLUE}{'─'*60}{RESET}")

    def _log_post_call(
        self, ts: str, model: str, content: str,
        tool_calls: list[dict[str, str]], severity: str, action: str,
        reason: str, usage: Any, elapsed_ms: float,
    ) -> None:
        sev_color = GREEN if severity == "NONE" else YELLOW if severity == "MEDIUM" else RED
        print(f"\n{BOLD}{GREEN}{'─'*60}{RESET}")
        tokens_str = ""
        if usage:
            tokens_str = f"  in={getattr(usage, 'prompt_tokens', '?')} out={getattr(usage, 'completion_tokens', '?')}"
        print(
            f"{GREEN}[{ts}]{RESET} {BOLD}POST-CALL{RESET}  "
            f"model={model}{tokens_str}  "
            f"{DIM}{elapsed_ms:.0f}ms{RESET}"
        )

        if content:
            preview = content[:200] + ("..." if len(content) > 200 else "")
            print(f"  content: {preview}")

        if tool_calls:
            for tc in tool_calls:
                print(f"  tool: {YELLOW}{tc['name']}{RESET}({tc['args'][:80]})")

        verdict_label = f"{sev_color}{severity}{RESET}"
        if severity == "NONE":
            print(f"  verdict: {verdict_label}")
        else:
            print(f"  verdict: {verdict_label}  action={action}  {reason}")
        print(f"{GREEN}{'─'*60}{RESET}")

    # ------------------------------------------------------------------
    # Blocking helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _block_message(direction: str, reason: str) -> str:
        if direction == "prompt":
            return (
                "I'm unable to process this request. DefenseClaw detected a "
                f"potential security concern in the prompt ({reason}). "
                "If you believe this is a false positive, contact your "
                "administrator or adjust the guardrail policy."
            )
        return (
            "The model's response was blocked by DefenseClaw due to a "
            f"potential security concern ({reason}). "
            "If you believe this is a false positive, contact your "
            "administrator or adjust the guardrail policy."
        )

    @staticmethod
    def _replace_response(response: Any, reason: str) -> None:
        """Mutate a ModelResponse in-place to replace content with a block notice."""
        import litellm

        if not isinstance(response, litellm.ModelResponse):
            return
        msg = (
            "The model's response was blocked by DefenseClaw due to a "
            f"potential security concern ({reason}). "
            "If you believe this is a false positive, contact your "
            "administrator or adjust the guardrail policy."
        )
        for choice in response.choices:
            if hasattr(choice, "message"):
                choice.message.content = msg
                choice.message.tool_calls = None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _messages_to_text(messages: list[dict[str, Any]]) -> str:
        parts: list[str] = []
        for msg in messages:
            c = msg.get("content", "")
            if isinstance(c, str):
                parts.append(c)
            elif isinstance(c, list):
                for block in c:
                    if isinstance(block, dict) and block.get("type") == "text":
                        parts.append(block.get("text", ""))
        return "\n".join(parts)

    @staticmethod
    def _extract_content(msg: dict[str, Any]) -> str:
        c = msg.get("content", "")
        if isinstance(c, str):
            return c
        if isinstance(c, list):
            return " ".join(
                b.get("text", "") for b in c
                if isinstance(b, dict) and b.get("type") == "text"
            )
        return str(c)
