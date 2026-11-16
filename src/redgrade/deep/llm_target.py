from __future__ import annotations

from collections.abc import Callable
from typing import Any

from redgrade.deep.client import LlmClient
from redgrade.deep.errors import DeepError
from redgrade.targets import TargetError
from redgrade.types import HistoryMessage


class LlmTarget:
    def __init__(
        self,
        *,
        model: str,
        api_base: str | None = None,
        system: str | None = None,
        timeout: float = 120.0,
        completion: Callable[..., Any] | None = None,
    ) -> None:
        self.model = model
        self.api_base = api_base
        self.system = system
        self._client = LlmClient(model=model, api_base=api_base, timeout=timeout, completion=completion)

    def __call__(
        self,
        prompt: str,
        documents: list[str],
        history: list[HistoryMessage] | None = None,
    ) -> str:
        history = history or []
        messages: list[dict[str, str]] = []
        if self.system:
            messages.append({"role": "system", "content": self.system})
        for turn in history:
            messages.append({"role": str(turn["role"]), "content": str(turn["content"])})
        if documents:
            messages.append(
                {
                    "role": "user",
                    "content": "Context documents:\n\n" + "\n\n".join(documents),
                }
            )
        messages.append({"role": "user", "content": prompt})
        try:
            return self._client.chat(messages)
        except DeepError as exc:
            raise TargetError(str(exc)) from exc
