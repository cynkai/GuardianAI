import re

from guardian.dataset import ATLAS_TECHNIQUES, ATTACK_DATASET, OWASP_LLM_2025

REQUIRED = {"id", "category", "owasp", "mitre", "technique", "risk", "multiturn",
            "payload", "success_criterion", "remediation_hint"}


def test_every_attack_has_the_fields_the_engine_reads():
    for atk in ATTACK_DATASET:
        assert REQUIRED <= atk.keys(), atk.get("id")


def test_attack_ids_are_unique():
    ids = [a["id"] for a in ATTACK_DATASET]
    assert len(ids) == len(set(ids))


def test_references_are_real_owasp_2025_and_atlas_ids():
    assert len(OWASP_LLM_2025) == 10
    assert all(re.fullmatch(r"AML\.T\d{4}(\.\d{3})?", t) for t in ATLAS_TECHNIQUES)
    for atk in ATTACK_DATASET:
        assert atk["owasp"] in OWASP_LLM_2025, atk["id"]
        assert atk["mitre"] in ATLAS_TECHNIQUES, atk["id"]
        assert atk["risk"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


def test_mapping_follows_the_2025_numbering():
    # The 2023 list numbered these differently (e.g. LLM06 was Sensitive Information
    # Disclosure, LLM08 Excessive Agency); guard against sliding back.
    by_category = {a["category"]: a["owasp"] for a in ATTACK_DATASET
                   if a["category"] != "Multi-Turn Chain Attack"}
    assert by_category["System Prompt Extraction"] == "LLM07:2025"
    assert by_category["Sensitive Info Disclosure"] == "LLM02:2025"
    assert by_category["Excessive Agency"] == "LLM06:2025"
    assert by_category["Hallucination Induction"] == "LLM09:2025"


def test_payload_shape_matches_the_turn_mode():
    for atk in ATTACK_DATASET:
        assert atk["payload"] and all(isinstance(t, str) and t for t in atk["payload"])
        assert (len(atk["payload"]) > 1) == atk["multiturn"], atk["id"]


def test_dataset_size_matches_the_readme():
    # README: "25 adversarial payloads in 10 attack categories".
    assert len(ATTACK_DATASET) == 25
    assert len({a["category"] for a in ATTACK_DATASET}) == 10
