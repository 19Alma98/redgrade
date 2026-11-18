from collections.abc import Callable
from typing import Any

from redgrade.deep.errors import DeepError


class LlmClient:
    def __init__(
        self,
        *,
        model: str,
        api_base: str | None = None,
        timeout: float = 120.0,
        completion: Callable[..., Any] | None = None,
    ) -> None:
        self.model = model
        self.api_base = api_base
        self.timeout = timeout
        if completion is not None:
            self._completion = completion
        else:
            try:
                from litellm import completion as litellm_completion
            except ImportError as exc:
                raise DeepError(
                    "deep mode needs LiteLLM: pip install 'redgrade[deep]' (static CI runs do not need it)"
                ) from exc

            self._completion = litellm_completion

    def chat(self, messages: list[dict[str, str]], *, response_format_json: bool = False) -> str:
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "timeout": self.timeout,
        }
        if self.api_base is not None:
            kwargs["api_base"] = self.api_base
        if response_format_json:
            kwargs["format"] = "json"
        try:
            response = self._completion(**kwargs)
            content = response.choices[0].message.content
            return str(content)
        except DeepError:
            raise
        except Exception as exc:
            text = str(exc)
            hint = ""
            lowered = text.lower()
            if "not found" in lowered or "404" in lowered:
                short = self.model.rsplit("/", 1)[-1]
                hint = f" (try: ollama pull {short})"
            raise DeepError(f"LLM chat failed for model {self.model}: {text}{hint}") from exc
