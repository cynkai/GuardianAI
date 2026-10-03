import pandas as pd

from guardian.report import _safe, df_to_csv, generate_pdf
from guardian.scoring import build_sample_scan_df, compute_delta, compute_kpis


def test_safe_keeps_typography_readable_in_latin1():
    assert _safe("A — B → C “quoted” …") == 'A - B -> C "quoted" ...'
    assert _safe("한국어").count("?") == 3     # unmappable text degrades, never raises
    assert len(_safe("x" * 500, 40)) == 40


def test_pdf_report_renders_for_sample_results():
    df = build_sample_scan_df()
    pdf = generate_pdf(df, compute_kpis(df), "gemini-flash-latest", "system prompt — v1")
    assert pdf.startswith(b"%PDF-") and len(pdf) > 2000


def test_pdf_report_renders_with_a_hardening_delta_and_unicode_findings():
    df = build_sample_scan_df()
    df.loc[0, "Evidence"] = "Leaked “secret” — see turn 2 → 3 (한국어)"
    after = df.assign(Verdict="SAFE", **{"Attack Succeeded": False})
    pdf = generate_pdf(df, compute_kpis(df), "m", "sp", after_df=after,
                       delta=compute_delta(df, after))
    assert pdf.startswith(b"%PDF-")


def test_csv_export_round_trips():
    df = build_sample_scan_df()
    back = pd.read_csv(pd.io.common.BytesIO(df_to_csv(df)))
    assert list(back.columns) == list(df.columns) and len(back) == len(df)
