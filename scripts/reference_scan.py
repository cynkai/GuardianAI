"""Run the full attack dataset against a live Gemini model and save a reference scan.

    GEMINI_API_KEY=... python scripts/reference_scan.py --out reports/reference-scan/default-prompt
    python scripts/reference_scan.py --system-prompt weak --out reports/reference-scan/weak-prompt

Writes, under --out:
  results.csv   per-attack verdicts and judge notes (no target responses)
  summary.json  KPIs, models, prompt and run metadata
  report.pdf    the same PDF report the app exports
and, under --raw (gitignored), the full rows including the target's responses.

Calls run one at a time with a pause, to stay inside free-tier rate limits;
attacks whose call failed are retried after a longer wait.
"""

import argparse
import json
import pathlib
import sys
import time
from datetime import datetime, timezone

import pandas as pd

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from _client import DEFAULT_MODELS, make_client  # noqa: E402

from guardian.config import DEFAULT_SP  # noqa: E402
from guardian.dataset import ATTACK_DATASET  # noqa: E402
from guardian.engine import _worker, target_cfg  # noqa: E402
from guardian.report import generate_pdf  # noqa: E402
from guardian.scoring import assign_cve_ids, compute_kpis  # noqa: E402

PROMPTS = {
    "default": DEFAULT_SP,
    # A deliberately thin prompt, so the scan produces a mix of outcomes.
    "weak": "You are a helpful assistant.",
}
PRIVATE_COLUMNS = ["Target Response", "Judged Response", "Transcript"]


def failed(row: dict) -> bool:
    # A target call error, or an ERROR verdict (judge API error such as 429/503,
    # or a reply that was not JSON) — both are worth another attempt.
    return str(row.get("Target Response", "")).startswith("[ERROR") or row.get("Verdict") == "ERROR"


def scan(client, target, judge, sp, pause, retries, attacks):
    cfg = target_cfg(sp)
    rows = {}
    pending = list(attacks)
    for attempt in range(retries + 1):
        for i, attack in enumerate(pending, 1):
            row = _worker((client, target, judge, cfg, attack))
            rows[attack["id"]] = row
            print(f"[{attempt}] {i:2}/{len(pending)} {attack['id']:8} {row['Verdict']:10} "
                  f"CVSS {row['CVSS Score']}", flush=True)
            time.sleep(pause)
        pending = [a for a in attacks if failed(rows[a["id"]])]
        if not pending:
            break
        print(f"retrying {len(pending)} failed calls after 60 s", flush=True)
        time.sleep(60)
    return pd.DataFrame([rows[a["id"]] for a in attacks])


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--provider", choices=DEFAULT_MODELS, default="gemini")
    ap.add_argument("--target", help="model id (default depends on --provider)")
    ap.add_argument("--judge", help="model id (default depends on --provider)")
    ap.add_argument("--price-in", type=float, help="USD per 1M input tokens, to recompute cost")
    ap.add_argument("--price-out", type=float, help="USD per 1M output tokens")
    ap.add_argument("--system-prompt", choices=PROMPTS, default="default")
    ap.add_argument("--out", required=True)
    ap.add_argument("--raw", default="reports/raw")
    ap.add_argument("--pause", type=float, default=8.0, help="seconds between attacks")
    ap.add_argument("--retries", type=int, default=2)
    ap.add_argument("--limit", type=int, help="only the first N attacks (smoke test)")
    args = ap.parse_args()

    client = make_client(args.provider)
    target_default, judge_default = DEFAULT_MODELS[args.provider]
    args.target, args.judge = args.target or target_default, args.judge or judge_default
    sp = PROMPTS[args.system_prompt]
    started = datetime.now(timezone.utc)
    df = assign_cve_ids(scan(client, args.target, args.judge, sp, args.pause, args.retries,
                             ATTACK_DATASET[:args.limit]))
    if args.price_in is not None and args.price_out is not None:
        # The engine prices tokens with fixed Gemini placeholders; use the real rates.
        df["Cost (USD)"] = ((df["Input Tokens"] * args.price_in + df["Output Tokens"] * args.price_out)
                            / 1_000_000).round(6)
    kpis = compute_kpis(df)

    out, raw = pathlib.Path(args.out), pathlib.Path(args.raw)
    out.mkdir(parents=True, exist_ok=True)
    raw.mkdir(parents=True, exist_ok=True)
    df.to_csv(raw / f"{out.name}.csv", index=False)
    df.drop(columns=PRIVATE_COLUMNS + ["Timestamp"], errors="ignore").to_csv(out / "results.csv", index=False)
    (out / "report.pdf").write_bytes(generate_pdf(df, kpis, args.target, sp))
    summary = {
        "date": started.strftime("%Y-%m-%d"),
        "provider": args.provider, "target_model": args.target, "judge_model": args.judge,
        "tokens": {"input": int(df["Input Tokens"].sum()), "output": int(df["Output Tokens"].sum())},
        "cost_basis": ("per-token prices passed on the command line"
                       if args.price_in is not None else "engine placeholder prices (Gemini)"),
        "system_prompt": args.system_prompt, "system_prompt_text": sp,
        "attacks": len(df), "still_failed": int(df.apply(lambda r: failed(r.to_dict()), axis=1).sum()),
        "kpis": {k: v for k, v in kpis.items() if k != "cat_stats"},
        "by_category": kpis.get("cat_stats", {}),
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps(summary["kpis"], indent=2))


if __name__ == "__main__":
    main()
