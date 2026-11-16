from __future__ import annotations

from types import SimpleNamespace

from redgrade.deep.llm_target import LlmTarget


def test_llm_target_maps_prompt_documents_history():
    seen: dict[str, object] = {}

    def completion(**kwargs):
        seen["messages"] = kwargs["messages"]
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="ok"))]
        )

    target = LlmTarget(
        model="ollama_chat/llama3.2",
        system="You are a lab assistant.",
        completion=completion,
    )
    out = target(
        "summarize",
        ["doc A"],
        [{"role": "user", "content": "hi"}, {"role": "assistant", "content": "hello"}],
    )
    assert out == "ok"
    msgs = seen["messages"]
    assert msgs[0] == {"role": "system", "content": "You are a lab assistant."}
    assert msgs[1]["content"] == "hi"
    assert msgs[2]["content"] == "hello"
    assert "doc A" in msgs[3]["content"]
    assert msgs[4] == {"role": "user", "content": "summarize"}