# tests/test_deep_client.py
from __future__ import annotations

from types import SimpleNamespace

import pytest

from redgrade.deep.client import LlmClient
from redgrade.deep.errors import DeepError


def _response(content: str) -> SimpleNamespace:
    return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=content))])


def test_chat_returns_assistant_content():
    seen: dict[str, object] = {}

    def completion(**kwargs):
        seen.update(kwargs)
        return _response("hello")

    client = LlmClient(model="ollama_chat/llama3.2", api_base="http://127.0.0.1:11434", completion=completion)
    assert client.chat([{"role": "user", "content": "hi"}]) == "hello"
    assert seen["model"] == "ollama_chat/llama3.2"
    assert seen["api_base"] == "http://127.0.0.1:11434"
    assert seen["messages"][0]["content"] == "hi"


def test_chat_json_mode_passes_format():
    seen: dict[str, object] = {}

    def completion(**kwargs):
        seen.update(kwargs)
        return _response('{"prompt":"x","documents":[]}')

    client = LlmClient(model="ollama_chat/llama3.2", completion=completion)
    client.chat([{"role": "user", "content": "hi"}], response_format_json=True)
    assert seen.get("format") == "json"


def test_chat_error_raises_deep_error():
    def completion(**kwargs):
        raise RuntimeError("connection refused")

    client = LlmClient(model="openai/gpt-4o-mini", completion=completion)
    with pytest.raises(DeepError, match="openai/gpt-4o-mini"):
        client.chat([{"role": "user", "content": "hi"}])


def test_chat_missing_ollama_model_hints_pull():
    def completion(**kwargs):
        raise RuntimeError("model 'llama3.2' not found")

    client = LlmClient(model="ollama_chat/llama3.2", completion=completion)
    with pytest.raises(DeepError, match="ollama pull llama3.2"):
        client.chat([{"role": "user", "content": "hi"}])
