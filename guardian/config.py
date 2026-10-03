"""Model choices, pricing assumptions and verdict styling shared by the app and reports."""

from google.genai import types

# The original 2025 preview / 1.5 model IDs have been shut down. The "-latest"
# aliases track Google's current release, so the defaults keep working; any
# other model ID can be entered in the sidebar ("Custom model ID…").
MODEL_REGISTRY = {
    "gemini-flash-latest":      "Gemini Flash (latest) ⚡",
    "gemini-pro-latest":        "Gemini Pro (latest) 🧠",
    "gemini-flash-lite-latest": "Gemini Flash-Lite (latest) 🪶",
}
CUSTOM_MODEL = "Custom model ID…"
DEFAULT_TARGET = "gemini-flash-latest"
DEFAULT_JUDGE  = "gemini-pro-latest"

SAFETY_OFF = [
    types.SafetySetting(category="HARM_CATEGORY_HARASSMENT",        threshold="BLOCK_NONE"),
    types.SafetySetting(category="HARM_CATEGORY_HATE_SPEECH",       threshold="BLOCK_NONE"),
    types.SafetySetting(category="HARM_CATEGORY_SEXUALLY_EXPLICIT", threshold="BLOCK_NONE"),
    types.SafetySetting(category="HARM_CATEGORY_DANGEROUS_CONTENT", threshold="BLOCK_NONE"),
]
COST_IN  = 0.15   # USD / 1M input tokens
COST_OUT = 0.60   # USD / 1M output tokens

VERDICT_META = {
    "VULNERABLE": {"color":"#FF3B30","bg":"#3d0a0a","fg":"#FF6B6B","icon":"🔴","rgb":(220,50,50)},
    "PARTIAL":    {"color":"#FF9500","bg":"#2e1a00","fg":"#FFAA44","icon":"🟡","rgb":(220,140,0)},
    "SAFE":       {"color":"#30D158","bg":"#0a2010","fg":"#4CD964","icon":"🟢","rgb":(40,180,80)},
    "ERROR":      {"color":"#636366","bg":"#111122","fg":"#8888AA","icon":"⚪","rgb":(100,100,120)},
}
GRADE_COLOR = {"A":"#30D158","B":"#34C759","C":"#FF9500","D":"#FF6B00","F":"#FF3B30"}
