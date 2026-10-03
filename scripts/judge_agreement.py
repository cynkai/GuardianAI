"""Compare hand labels with the judge's verdicts on the same responses.

    python scripts/judge_agreement.py reports/raw/labels.json \
        reports/raw/default-prompt.csv reports/raw/weak-prompt.csv --out reports/judge-agreement

labels.json comes from the page built by make_labeling_page.py. Reports exact
agreement and Cohen's kappa on the three verdicts, the same on a binary
"breached (VULNERABLE or PARTIAL) vs SAFE" reading, and the confusion matrix.
Judge ERROR verdicts are left out (there were none in the 2026-10 scans).
"""

import argparse
import json
import pathlib

import pandas as pd

VERDICTS = ["VULNERABLE", "PARTIAL", "SAFE"]


def cohen_kappa(a, b, classes):
    n = len(a)
    if n == 0:
        return float("nan")
    observed = sum(x == y for x, y in zip(a, b)) / n
    expected = sum((a.count(c) / n) * (b.count(c) / n) for c in classes)
    return 1.0 if expected == 1 else (observed - expected) / (1 - expected)


def agreement(human, judge, classes):
    return {"n": len(human),
            "agreement": round(sum(h == j for h, j in zip(human, judge)) / len(human), 3),
            "cohen_kappa": round(cohen_kappa(human, judge, classes), 3)}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("labels")
    ap.add_argument("scans", nargs="+")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    labels = json.loads(pathlib.Path(args.labels).read_text())["labels"]
    rows = []
    for src in args.scans:
        run = pathlib.Path(src).stem
        for r in pd.read_csv(src).to_dict("records"):
            item = f"{run}:{r['ID']}"
            if item in labels and r["Verdict"] in VERDICTS:
                rows.append({"item": item, "id": r["ID"], "category": r["Category"],
                             "human": labels[item], "judge": r["Verdict"]})
    df = pd.DataFrame(rows)
    human, judge = df["human"].tolist(), df["judge"].tolist()
    breach = lambda v: "BREACHED" if v in ("VULNERABLE", "PARTIAL") else "SAFE"  # noqa: E731
    result = {
        "labelled_items": len(labels), "compared": len(df),
        "three_way": agreement(human, judge, VERDICTS),
        "binary": agreement([breach(v) for v in human], [breach(v) for v in judge],
                            ["BREACHED", "SAFE"]),
        "confusion (rows = human, cols = judge)":
            pd.crosstab(df["human"], df["judge"]).reindex(index=VERDICTS, columns=VERDICTS,
                                                          fill_value=0).to_dict("index"),
        "disagreements": df[df["human"] != df["judge"]][["item", "category", "human", "judge"]]
                         .to_dict("records"),
    }
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "agreement.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: result[k] for k in ("compared", "three_way", "binary")}, indent=2))


if __name__ == "__main__":
    main()
