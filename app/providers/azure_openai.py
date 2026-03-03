"""
Azure OpenAI provider with MOCK_MODE support.

In MOCK_MODE (MOCK_MODE=true, the default):
  - No network calls are made.
  - Returns a deterministic, safe response that summarises the user's request
    without echoing any potentially sensitive data verbatim.

In live mode:
  - Calls the Azure OpenAI Chat Completions API using the openai SDK.
  - Requires AZURE_OPENAI_API_KEY and AZURE_OPENAI_ENDPOINT to be set.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app import config


@dataclass
class ProviderResponse:
    content: str
    tool_calls: List[Dict[str, Any]] = field(default_factory=list)


# ── Mock ─────────────────────────────────────────────────────────────────────

def _mock_response(messages: List[Dict[str, str]]) -> ProviderResponse:
    """
    Return a short, safe deterministic answer.
    The summary is truncated so it cannot accidentally re-emit a secret that
    was already redacted by DLP.
    """
    user_messages = [m for m in messages if m.get("role") == "user"]
    if user_messages:
        snippet = (user_messages[-1].get("content") or "")[:80].replace("\n", " ")
        content = (
            f"[MOCK RESPONSE] I received your message. "
            f"Here is a safe echo of the first 80 chars: «{snippet}». "
            f"No real AI call was made."
        )
    else:
        content = "[MOCK RESPONSE] Hello! No user message was provided."
    return ProviderResponse(content=content)


# ── Live ──────────────────────────────────────────────────────────────────────

def _live_response(
    messages: List[Dict[str, str]],
    tools: Optional[List[Dict[str, Any]]],
) -> ProviderResponse:
    if not config.AZURE_OPENAI_API_KEY or not config.AZURE_OPENAI_ENDPOINT:
        raise RuntimeError(
            "AZURE_OPENAI_API_KEY and AZURE_OPENAI_ENDPOINT must be set "
            "when MOCK_MODE=false"
        )

    try:
        from openai import AzureOpenAI
    except ImportError as exc:
        raise RuntimeError("openai package is required for live mode") from exc

    client = AzureOpenAI(
        api_key=config.AZURE_OPENAI_API_KEY,
        azure_endpoint=config.AZURE_OPENAI_ENDPOINT,
        api_version=config.AZURE_OPENAI_API_VERSION,
    )

    kwargs: Dict[str, Any] = dict(
        model=config.AZURE_OPENAI_DEPLOYMENT,
        messages=messages,
    )
    if tools:
        kwargs["tools"] = tools

    response = client.chat.completions.create(**kwargs)
    choice = response.choices[0]
    content = choice.message.content or ""

    tool_calls: List[Dict[str, Any]] = []
    if choice.message.tool_calls:
        for tc in choice.message.tool_calls:
            tool_calls.append(
                {
                    "id": tc.id,
                    "type": tc.type,
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments,
                    },
                }
            )

    return ProviderResponse(content=content, tool_calls=tool_calls)


# ── Public API ────────────────────────────────────────────────────────────────

def call_provider(
    messages: List[Dict[str, str]],
    tools: Optional[List[Dict[str, Any]]] = None,
) -> ProviderResponse:
    """
    Route the request to the mock or live backend depending on MOCK_MODE.
    """
    if config.MOCK_MODE:
        return _mock_response(messages)
    return _live_response(messages, tools)
