import csv
import io

import pandas as pd

from guardian import report
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


def test_pdf_preserves_long_finding_details_across_pages(monkeypatch):
    class UncompressedPDF(report.RedTeamPDF):
        def __init__(self):
            super().__init__()
            self.set_compression(False)

    monkeypatch.setattr(report, "RedTeamPDF", UncompressedPDF)
    df = build_sample_scan_df()
    finding = df.index[df["Verdict"].isin(["VULNERABLE", "PARTIAL"])][0]
    df.loc[finding, "Evidence"] = ("A detailed observation. " * 450) + "Evidence ends here"
    df.loc[finding, "Remediation"] = ("Check the documented configuration. " * 20) + "Remediation ends here"

    pdf = generate_pdf(df, compute_kpis(df), "m", "sp")

    assert pdf.count(b"/Type /Page\n") > 4
    assert b"Evidence ends here" in pdf
    assert b"Remediation ends here" in pdf


def test_csv_export_round_trips():
    df = build_sample_scan_df()
    back = pd.read_csv(pd.io.common.BytesIO(df_to_csv(df)))
    assert list(back.columns) == list(df.columns) and len(back) == len(df)


def test_csv_export_treats_generated_text_as_spreadsheet_data():
    evidence = ["=1+1", "  +note", "- leading bullet", "@summary", "\ttext", "\rtext",
                "\ntext", "한국어, \"quoted\"\nsecond line", None]
    df = pd.DataFrame({"=heading": evidence, "Score": range(-4, 5)})

    rows = list(csv.reader(io.StringIO(df_to_csv(df).decode())))

    assert rows[0] == ["'=heading", "Score"]
    assert [row[0] for row in rows[1:]] == [
        *["'" + value for value in evidence[:7]], evidence[7], "",
    ]
    assert [row[1] for row in rows[1:]] == [str(value) for value in range(-4, 5)]
    assert df.iloc[0, 0] == "=1+1"
