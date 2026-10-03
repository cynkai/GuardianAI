import re

from guardian.dataset import ATTACK_DATASET

REQUIRED = {"id", "category", "owasp", "mitre", "technique", "risk", "multiturn",
            "payload", "success_criterion", "remediation_hint"}


def test_every_attack_has_the_fields_the_engine_reads():
    for atk in ATTACK_DATASET:
        assert REQUIRED <= atk.keys(), atk.get("id")


def test_attack_ids_are_unique():
    ids = [a["id"] for a in ATTACK_DATASET]
    assert len(ids) == len(set(ids))


def test_references_use_owasp_2025_and_mitre_atlas_ids():
    for atk in ATTACK_DATASET:
        assert re.fullmatch(r"LLM(0[1-9]|10):2025", atk["owasp"]), atk["id"]
        assert re.fullmatch(r"AML\.T\d{4}(\.\d{3})?", atk["mitre"]), atk["id"]
        assert atk["risk"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


def test_payload_shape_matches_the_turn_mode():
    for atk in ATTACK_DATASET:
        assert atk["payload"] and all(isinstance(t, str) and t for t in atk["payload"])
        assert (len(atk["payload"]) > 1) == atk["multiturn"], atk["id"]


def test_dataset_size_matches_the_readme():
    # README: "25 adversarial payloads across 10 OWASP LLM Top 10 categories".
    assert len(ATTACK_DATASET) == 25
    assert len({a["category"] for a in ATTACK_DATASET}) == 10
