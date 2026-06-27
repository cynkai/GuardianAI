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

The taxonomy follows the **OWASP LLM Top 10 (2025)** and **MITRE ATLAS**.

## Motivation

As LLMs are deployed in real services, jailbreaks, prompt injection, and data-leak
attempts grow more sophisticated — moving well beyond simple keyword filtering into
subtle, context-dependent bypasses. Developers need a way to probe their own service's
defenses before attackers do. GuardianAI explores a lightweight, automated red-team
workflow for exactly that.

## Core Features

- **Attack dataset** — 26 adversarial payloads across 10 OWASP LLM Top 10 categories
  (e.g. Base64 encoding, role-play jailbreaks, multi-turn attacks).
- **LLM-as-a-Judge** — instead of plain string matching, a judge model reads the
  target's response in context and returns a structured JSON verdict.
- **Interactive defense testing** — enter a custom defensive system prompt and
  validate its resilience in real time.
- **Adaptive Attack Tree** — depth-3 recursive self-escalation: when an attack is
  blocked, the engine mutates it into a harder variant and retries.
- **CVSS-inspired scoring** — per-finding severity vectors and an overall security grade.
- **CVE-style finding index** — each finding gets an `RTAI-YYYY-NNN` ID for tracking.
- **Auto-Hardener** — generates a hardened system prompt from the findings, with a
  before/after re-scan to validate the fix.
- **Reproducibility & statistics** — N-repeat consistency checks, chi-square tests,
  and Cramér's V across categories.
- **Reporting** — exportable CSV / JSON / PDF executive reports.

## Architecture

```
Attack Dataset (26 payloads · 10 OWASP categories)
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
read as exploratory rather than authoritative.

## Future Work

- Expand the attack dataset and harden the judging logic
- Validate against more target models and real-world system prompts
- Tie findings into a continuous, cloud-based monitoring pipeline
