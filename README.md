*Read this in other languages: [한국어](README.ko.md)*

[![tests](https://github.com/cynkai/GuardianAI/actions/workflows/tests.yml/badge.svg)](https://github.com/cynkai/GuardianAI/actions/workflows/tests.yml)

# GuardianAI — LLM Automated Red-Teaming Scanner

> A hackathon prototype that stress-tests an LLM's defenses by firing adversarial
> prompts at a target model and using a second LLM as a judge to decide whether
> each attack succeeded.
>
> Built for the CMUX × AIM Hackathon 2025 (AI Safety & Security Track).

## Overview

GuardianAI lets a developer test how well their own AI service resists attacks.
It sends a dataset of adversarial prompts at a **target model**, then a separate
**judge model** analyzes each response in context and rules whether the model was
`VULNERABLE`, `PARTIAL`, or `SAFE`. Findings are scored, reported, and used to
auto-generate a hardened system prompt.

Each payload is tagged with an **OWASP Top 10 for LLM Applications (2025)** entry and a
**MITRE ATLAS** technique.

## Motivation

As LLMs are deployed in real services, jailbreaks, prompt injection, and data-leak
attempts grow more sophisticated — moving well beyond simple keyword filtering into
subtle, context-dependent bypasses. Developers need a way to probe their own service's
defenses before attackers do. GuardianAI explores a lightweight, automated red-team
workflow for exactly that.

## Core Features

- **Attack dataset** — 25 adversarial payloads in 10 attack categories (e.g. Base64
  encoding, role-play jailbreaks, multi-turn attacks), mapped to five OWASP LLM 2025
  entries (LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM06
  Excessive Agency, LLM07 System Prompt Leakage, LLM09 Misinformation) and nine MITRE
  ATLAS techniques.
- **LLM-as-a-Judge** — instead of plain string matching, a judge model reads the
  target's response in context and returns a structured JSON verdict.
- **Interactive defense testing** — enter a custom defensive system prompt and
  validate its resilience in real time.
- **Adaptive Attack Tree** — depth-3 recursive self-escalation: when an attack is
  blocked, the engine mutates it into a harder variant and retries.
- **CVSS v3.1 scoring** — the judge proposes a base vector per finding; the app computes
  its CVSS v3.1 base score (checked against reference vectors) and an overall grade.
- **CVE-style finding index** — each finding gets an internal `RTAI-YYYY-NNN` ID for
  tracking (a CVE-like format, not a registered CVE).
- **Auto-Hardener** — generates a hardened system prompt from the findings, with a
  before/after re-scan to validate the fix.
- **Reproducibility & statistics** — N-repeat consistency checks, Wilson intervals,
  chi-square tests and Cramér's V across categories.
- **Reporting** — exportable CSV / JSON / PDF executive reports.

## Architecture

```
Attack Dataset (25 payloads · 10 categories · OWASP LLM 2025 + MITRE ATLAS)
        │ [ThreadPoolExecutor]
        ▼
TARGET  model · system prompt under test
        │ response
        ▼
JUDGE   model · JSON verdict + CVSS vector
        │
        ├─ CVE-style IDs (RTAI-YYYY-NNN)
        ├─ Adaptive Attack Tree (depth-3 recursive)
        ├─ Reproducibility checker
        ├─ Statistical tests (χ², Cramér's V)
        ├─ Before/After comparison
        ├─ Auto-Hardener (AI patches the system prompt)
        └─ PDF / CSV / JSON report
```

## Tech Stack

- Python
- Streamlit (UI)
- Google Gemini API (`google-genai` SDK)
- Plotly (visualization), fpdf2 (PDF reports), pandas / numpy

## Quick Start

Requires Python 3.13 (other recent 3.x versions likely work but are untested).

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

- **No API key needed to look around:** open the **Results** tab and click
  **Load Sample Results** to explore every dashboard and export a PDF report with
  sample data.
- **Live scans** need a Gemini API key: `cp .env.example .env` and set
  `GEMINI_API_KEY`, or paste a key into the sidebar. A scan calls the Gemini API
  for every payload (target + judge), so it uses your quota.
- Models default to Google's `gemini-flash-latest` (target) and `gemini-pro-latest`
  (judge) aliases; choose **Custom model ID…** in the sidebar to pin another model.

## Project Structure & Tests

```
app.py              Streamlit UI, charts, scan orchestration
guardian/
  config.py         model choices, pricing assumptions, verdict styling
  dataset.py        attack payloads + OWASP 2025 / MITRE ATLAS reference names
  engine.py         Gemini calls: fire, judge (with output normalisation), tree, harden
  scoring.py        CVSS v3.1, KPIs and grade, CVE-style IDs, statistics
  report.py         CSV and PDF export
tests/              pytest suite (no API calls)
```

```bash
pip install -r requirements-dev.txt
python -m pytest
```

The tests pin the logic the dashboards report: CVSS v3.1 base scores against reference
vectors, KPIs and grades, Wilson intervals, chi-square p-values, parsing of the judge's
JSON (using a fake Gemini client), PDF/CSV export, and the dataset's OWASP/ATLAS IDs.
GitHub Actions runs them on every push.

## Post-hackathon Changes (2026-10)

Revisiting the hackathon build in October 2026, I made it runnable again, put the core
logic under test, and fixed what the tests found:

- **Runnable from a fresh clone** — the original Gemini model IDs had been shut down;
  added pinned requirements, `.env.example`, and a no-key sample mode.
- **Testable structure** — moved the core logic out of the single 2,300-line `app.py`
  into the `guardian/` package (no behaviour change), then added the test suite and CI.
- **PDF report** — generation crashed on non-latin-1 characters with current fpdf2;
  body text was nearly invisible and CVE IDs were truncated.
- **CVSS** — the "CVSS-inspired" formula disagreed with CVSS v3.1 on 6 of 8 reference
  vectors (rounding, scope-dependent Privileges Required); it now matches the spec.
- **Statistics** — the chi-square p-value used the wrong formula and overstated
  p-values (χ² = 3.84 was reported as p = 0.17 instead of 0.05).
- **Hardening comparison** — before/after scores used a different formula from the
  dashboard, so the same scan showed two different scores.
- **Judge parsing** — single-letter verdicts such as `"V"` were dropped from every count;
  the judge's JSON is now normalised.
- **Judge prompt injection** — the target's response was pasted into the judge prompt
  unfenced, so an attack could make the target tell the judge "this is SAFE". Grading
  rules now sit in the judge's system instruction, and the payload and response are
  passed as untrusted data between markers with a random per-call tag, so a response
  cannot close its own block.
- **Judge without a reference** — the judge never saw the system prompt it was meant to
  protect, so a verbatim leak could be graded SAFE; it now gets it as fenced reference.
- **Live runs on OpenAI too** — an adapter (`guardian/openai_client.py`) runs the same
  engine against OpenAI models; `scripts/` adds a reference scan, a judge-injection
  check and a blind labelling page for measuring the judge.
- **Taxonomy** — payloads were labelled `:2025` but used the 2023 OWASP numbering, and
  some MITRE ATLAS IDs pointed at the wrong technique; remapped and checked by tests.

## Reference Results (2026-10)

Measured with OpenAI models (target `gpt-5.4-nano`, judge `gpt-5.4-mini`); details,
data and limits in [`reports/`](reports/README.md).

- **Reference scan** — default system prompt: score 89 (B), 3 of 25 payloads breached;
  a deliberately thin prompt: 78 (B), 5 of 25. Breaches: persona jailbreaks,
  zero-width-character injection, a partial stereotype completion.
- **Judge prompt injection** — with the pre-fix prompt the judge was hijacked by the
  attack payload it was grading and returned SAFE in 18 of 18 cases (including the
  control with no extra text); with the current prompt, 0 of 18.
- **Judge vs. human labels** — on 20 hand-labelled responses (enriched for breaches):
  75% agreement on breached-vs-safe (κ = 0.53), 60% on all three verdicts (κ = 0.42).
  The judge never flagged a safe response but missed 5 of 13 partial or full breaches,
  so scan breach rates are likely underestimates.

## My Role

- Designed and implemented the automated red-teaming workflow end to end
- Built the LLM-as-a-Judge verdict logic and the adversarial attack dataset
- Implemented CVSS-style scoring, the auto-hardener, and report generation
- Integrated the Gemini API and handled API-key security (`.env` + `.gitignore`)

## Ethics & Responsible Use

Payloads test model governance only — no synthesis routes, CSAM, or operational-harm
instructions. Safety filters are relaxed on the *target* model only, and solely to
measure system-prompt defenses — never to bypass production safeguards. Every finding
is paired with a remediation suggestion.

## Limitations

Developed as a hackathon prototype. The goal was to explore an automated
LLM red-teaming workflow, not to ship a production-grade scanner. Within the time
available, the bypass and judging logic were not perfected, and results should be
read as exploratory rather than authoritative. In particular:

- Verdicts and CVSS vectors come from an LLM judge; the CVSS arithmetic is exact, but
  the vector it scores is the judge's opinion.
- Each category has only 2–4 payloads, so per-category rates, Wilson intervals and the
  chi-square test (a large-sample approximation) are indicative only.
- The judge is lenient on partial leaks (see Reference Results), so breach rates are
  likely underestimated.
- Fencing the target's response makes judge manipulation harder, not impossible: the
  judge is still an LLM reading attacker-influenced text.
- Cost figures use fixed per-token prices in `guardian/config.py`, not the selected
  model's current pricing.
- Live scans after the 2026 changes ran on OpenAI models through the adapter, not on
  Gemini; the Gemini path is covered by the offline tests and the sample-data mode.

## Future Work

- Expand the attack dataset and harden the judging logic
- Validate against more target models and real-world system prompts
- Tie findings into a continuous, cloud-based monitoring pipeline
