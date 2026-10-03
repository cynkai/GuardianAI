import json
from types import SimpleNamespace

import pytest

from guardian.dataset import ATTACK_DATASET
from guardian.engine import _worker, fire_single, judge_eval

ATTACK = next(a for a in ATTACK_DATASET if not a["multiturn"])


class FakeModels:
    """Stands in for client.models: replies come from a queue, calls are recorded."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []

    def generate_content(self, model, contents, config):
        self.calls.append(model)
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return SimpleNamespace(text=reply, candidates=[object()],
                               usage_metadata=SimpleNamespace(prompt_token_count=1000,
                                                              candidates_token_count=500))


def client(*replies):
    return SimpleNamespace(models=FakeModels(replies))


VERDICT = {"verdict": "VULNERABLE", "confidence": 88, "attack_succeeded": True,
           "evidence": "leaked prompt", "reasoning": "It complied.", "remediation": "Refuse.",
           "severity_score": 8.5,
           "cvss_vector": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                           "C": "H", "I": "H", "A": "H"}}


@pytest.mark.parametrize("text", [
    json.dumps(VERDICT),
    "```json\n" + json.dumps(VERDICT) + "\n```",
    "Here is my assessment:\n" + json.dumps(VERDICT) + "\nThanks.",
])
def test_judge_reads_json_wrapped_in_any_text(text):
    assert judge_eval(client(text), "judge", ATTACK, "response") == VERDICT


@pytest.mark.parametrize("text", ["no json here", "{not: valid json}", "[1, 2, 3]"])
def test_judge_output_without_a_json_object_becomes_an_error_verdict(text):
    ev = judge_eval(client(text), "judge", ATTACK, "response")
    assert ev["verdict"] == "ERROR" and ev["attack_succeeded"] is False


def test_judge_api_failure_becomes_an_error_verdict():
    ev = judge_eval(client(RuntimeError("quota exceeded")), "judge", ATTACK, "response")
    assert ev["verdict"] == "ERROR"
    assert "quota exceeded" in ev["reasoning"]


@pytest.mark.parametrize("raw, expected", [
    ("V", "VULNERABLE"), ("p", "PARTIAL"), ("Safe", "SAFE"), ("E", "ERROR"),
    (" vulnerable ", "VULNERABLE"), ("MAYBE", "ERROR"), (None, "ERROR"),
])
def test_judge_verdicts_are_normalised(raw, expected):
    # The judge prompt shows the verdict as "<V|P|S|E>", so single letters do come back.
    ev = judge_eval(client(json.dumps({**VERDICT, "verdict": raw})), "judge", ATTACK, "r")
    assert ev["verdict"] == expected


def test_judge_numbers_are_coerced_and_clamped():
    reply = {**VERDICT, "confidence": "140", "severity_score": "-3", "attack_succeeded": "false"}
    ev = judge_eval(client(json.dumps(reply)), "judge", ATTACK, "r")
    assert (ev["confidence"], ev["severity_score"], ev["attack_succeeded"]) == (100, 0.0, False)


def test_attack_succeeded_follows_a_vulnerable_verdict_when_missing():
    reply = {k: v for k, v in VERDICT.items() if k != "attack_succeeded"}
    assert judge_eval(client(json.dumps(reply)), "judge", ATTACK, "r")["attack_succeeded"] is True


def test_fire_single_reports_api_errors_in_the_response_text():
    text, ms, tokens_in, tokens_out = fire_single(client(RuntimeError("boom")), "m", "p", None)
    assert text.startswith("[ERROR") and "boom" in text
    assert (tokens_in, tokens_out) == (0, 0)


def test_worker_turns_one_attack_into_a_scored_result_row():
    c = client("I will comply: SYSTEM PROMPT ...", json.dumps({**VERDICT, "verdict": "v"}))
    row = _worker((c, "target-model", "judge-model", None, ATTACK))
    assert c.models.calls == ["target-model", "judge-model"]
    assert row["ID"] == ATTACK["id"] and row["Verdict"] == "VULNERABLE"
    assert (row["CVSS Score"], row["CVSS Label"]) == (9.8, "CRITICAL")
    assert row["Input Tokens"] == 1000 and row["Output Tokens"] == 500
    assert row["Cost (USD)"] > 0
