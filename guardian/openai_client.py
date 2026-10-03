"""Run the engine against OpenAI models.

The engine talks to a google-genai style client: ``client.models.generate_content``,
``client.models.generate_content_stream`` and ``client.chats.create(...).send_message``,
with a ``GenerateContentConfig`` carrying the system instruction and JSON mode.
``OpenAIClient`` exposes that same surface on top of OpenAI Chat Completions, so
``guardian.engine`` needs no provider-specific code.

Gemini's safety_settings have no OpenAI equivalent and are ignored.
Requires the optional ``openai`` package (see requirements-dev.txt).
"""

from types import SimpleNamespace


def _messages(config, history):
    system = getattr(config, "system_instruction", None) if config else None
    return ([{"role": "system", "content": str(system)}] if system else []) + history


def _json_mode(config) -> bool:
    return bool(config) and getattr(config, "response_mime_type", None) == "application/json"


def _response(completion):
    """Shape an OpenAI completion like a google-genai response."""
    choice = completion.choices[0]
    msg = choice.message
    text = msg.content or getattr(msg, "refusal", None) or ""
    usage = completion.usage
    return SimpleNamespace(
        text=text,
        # The engine reports "[BLOCKED]" when there are no candidates.
        candidates=[] if choice.finish_reason == "content_filter" and not text else [choice],
        usage_metadata=SimpleNamespace(
            prompt_token_count=getattr(usage, "prompt_tokens", 0) or 0,
            candidates_token_count=getattr(usage, "completion_tokens", 0) or 0))


class _Models:
    def __init__(self, oa):
        self._oa = oa

    def _create(self, model, history, config, **kw):
        if _json_mode(config):
            kw["response_format"] = {"type": "json_object"}
        return self._oa.chat.completions.create(
            model=model, messages=_messages(config, history), **kw)

    def generate_content(self, model, contents, config=None):
        return _response(self._create(model, [{"role": "user", "content": str(contents)}], config))

    def generate_content_stream(self, model, contents, config=None):
        stream = self._create(model, [{"role": "user", "content": str(contents)}], config,
                              stream=True)
        for chunk in stream:
            delta = chunk.choices[0].delta.content if chunk.choices else None
            if delta:
                yield SimpleNamespace(text=delta)


class _Chat:
    def __init__(self, models, model, config):
        self._models, self._model, self._config = models, model, config
        self._history = []

    def send_message(self, message):
        self._history.append({"role": "user", "content": str(message)})
        r = _response(self._models._create(self._model, self._history, self._config))
        self._history.append({"role": "assistant", "content": r.text})
        return r


class _Chats:
    def __init__(self, models):
        self._models = models

    def create(self, model, config=None):
        return _Chat(self._models, model, config)


class OpenAIClient:
    def __init__(self, api_key=None, client=None):
        if client is None:
            from openai import OpenAI  # optional dependency, only needed for live runs
            client = OpenAI(api_key=api_key)
        self.models = _Models(client)
        self.chats = _Chats(self.models)
