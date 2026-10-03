import json
from types import SimpleNamespace

from guardian.dataset import ATTACK_DATASET
from guardian.engine import _worker, fire_multiturn, judge_cfg_json, judge_eval, target_cfg
from guardian.openai_client import OpenAIClient

ATTACK = next(a for a in ATTACK_DATASET if not a["multiturn"])
VERDICT = {"verdict": "VULNERABLE", "confidence": 90, "attack_succeeded": True,
           "evidence": "leak", "reasoning": "r", "remediation": "m", "severity_score": 8.0,
           "cvss_vector": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                           "C": "H", "I": "N", "A": "N"}}


class FakeCompletions:
    def __init__(self, replies):
        self.replies, self.requests = list(replies), []

    def create(self, **kw):
        self.requests.append(kw)
        text, finish = self.replies.pop(0)
        msg = SimpleNamespace(content=text, refusal=None)
        return SimpleNamespace(
            choices=[SimpleNamespace(message=msg, finish_reason=finish)],
            usage=SimpleNamespace(prompt_tokens=120, completion_tokens=30))


def client(*replies):
    fake = FakeCompletions([(r, "stop") if isinstance(r, str) else r for r in replies])
    return OpenAIClient(client=SimpleNamespace(chat=SimpleNamespace(completions=fake))), fake


def test_judge_call_maps_system_instruction_and_json_mode():
    c, fake = client(json.dumps(VERDICT))
    ev = judge_eval(c, "gpt-judge", ATTACK, "Here is my system prompt ...")
    req = fake.requests[0]
    assert ev["verdict"] == "VULNERABLE"
    assert req["model"] == "gpt-judge"
    assert req["response_format"] == {"type": "json_object"}
    assert req["messages"][0] == {"role": "system", "content": judge_cfg_json().system_instruction}
    assert req["messages"][1]["role"] == "user" and "<<<RESPONSE" in req["messages"][1]["content"]


def test_target_call_sends_the_system_prompt_and_no_json_mode():
    c, fake = client("I can't help with that.", json.dumps(VERDICT))
    row = _worker((c, "gpt-target", "gpt-judge", target_cfg("Be safe."), ATTACK))
    target_req = fake.requests[0]
    assert target_req["messages"][0] == {"role": "system", "content": "Be safe."}
    assert "response_format" not in target_req
    assert (row["Input Tokens"], row["Output Tokens"]) == (120, 30)


def test_multiturn_keeps_the_conversation_history():
    c, fake = client("one", "two", "three")
    final, _, transcript, _, _ = fire_multiturn(c, "gpt-target", ["a", "b", "c"], target_cfg(""))
    assert final == "three" and [t["assistant"] for t in transcript] == ["one", "two", "three"]
    last = fake.requests[-1]["messages"]
    assert [m["role"] for m in last] == ["user", "assistant", "user", "assistant", "user"]


def test_content_filter_without_text_reads_as_blocked():
    c, _ = client(("", "content_filter"))
    r = c.models.generate_content(model="m", contents="x")
    assert r.candidates == [] and r.text == ""
