"""Shared by the scripts: build a Gemini or OpenAI client from the environment.

A key in the repository's .env wins over one exported by the shell, so a stale
shell variable cannot silently take precedence.
"""

import os
import pathlib

from dotenv import load_dotenv

ROOT = pathlib.Path(__file__).resolve().parents[1]

DEFAULT_MODELS = {
    # provider: (target, judge)
    "gemini": ("gemini-flash-lite-latest", "gemini-flash-latest"),
    "openai": ("gpt-5.4-nano-2026-03-17", "gpt-5.4-mini-2026-03-17"),
}


def make_client(provider: str):
    load_dotenv(ROOT / ".env", override=True)
    if provider == "openai":
        from guardian.openai_client import OpenAIClient
        return OpenAIClient(api_key=os.environ["OPENAI_API_KEY"])
    from google import genai
    return genai.Client(api_key=os.environ["GEMINI_API_KEY"])
