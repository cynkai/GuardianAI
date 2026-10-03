*다른 언어로 보기: [English](README.md)*

[![tests](https://github.com/cynkai/GuardianAI/actions/workflows/tests.yml/badge.svg)](https://github.com/cynkai/GuardianAI/actions/workflows/tests.yml)

# GuardianAI — LLM 자동 레드팀 스캐너

> 타겟 모델에 적대적 프롬프트를 쏘고, 별도의 평가자 LLM이 각 공격의 성공 여부를
> 판결하는 방식으로 LLM의 방어력을 점검하는 해커톤 프로토타입.
>
> CMUX × AIM 해커톤 2025 (AI Safety & Security 트랙) 출품작.

## 개요

GuardianAI는 개발자가 자신의 AI 서비스가 공격에 얼마나 잘 버티는지 직접 테스트할 수
있게 해줍니다. **타겟 모델**에 적대적 프롬프트 데이터셋을 입력한 뒤, 별도의 **평가자
모델**이 각 응답을 문맥까지 분석하여 `VULNERABLE`(뚫림) / `PARTIAL`(부분) / `SAFE`(방어)로
판결합니다. 판결된 취약점은 점수화·리포트화되며, 이를 바탕으로 강화된 시스템 프롬프트를
자동 생성합니다.

각 페이로드에는 **OWASP Top 10 for LLM Applications (2025)** 항목과 **MITRE ATLAS** 기법이
표시되어 있습니다.

## 기획 배경

LLM이 실제 서비스에 도입되면서 탈옥(Jailbreak), 프롬프트 인젝션, 개인정보 유출 시도가
점점 정교해지고 있습니다. 단순 키워드 필터링을 넘어선, 문맥에 기반한 교묘한 우회 공격이
등장하는 상황입니다. 개발자는 공격자보다 먼저 자기 서비스의 방어력을 점검할 수단이
필요하며, GuardianAI는 이를 위한 가볍고 자동화된 레드팀 워크플로우를 탐구한
프로젝트입니다.

## 핵심 기능

- **공격 데이터셋** — 10개 공격 카테고리에 걸친 25개 적대적 페이로드(Base64 인코딩,
  롤플레잉 우회, 멀티턴 공격 등). OWASP LLM 2025의 5개 항목(LLM01 Prompt Injection,
  LLM02 Sensitive Information Disclosure, LLM06 Excessive Agency, LLM07 System Prompt
  Leakage, LLM09 Misinformation)과 MITRE ATLAS 기법 9개에 매핑
- **LLM-as-a-Judge** — 단순 문자열 매칭이 아니라, 평가자 모델이 타겟의 응답을 문맥으로
  읽고 구조화된 JSON 판결을 반환
- **인터랙티브 방어벽 테스트** — 사용자가 방어용 시스템 프롬프트를 직접 입력하고
  실시간으로 방어력을 검증
- **적응형 공격 트리(Adaptive Attack Tree)** — depth-3 재귀 자가 강화. 공격이 막히면
  더 강한 변종으로 변이시켜 재시도
- **CVSS v3.1 점수화** — 평가자가 취약점별 기본 벡터를 제안하면, 앱이 CVSS v3.1 기본
  점수(기준 벡터로 검증)와 전체 보안 등급을 계산
- **CVE 스타일 취약점 인덱스** — 각 취약점에 내부용 `RTAI-YYYY-NNN` ID를 부여해 추적
  (CVE와 비슷한 형식일 뿐, 등록된 CVE는 아님)
- **자동 하드너(Auto-Hardener)** — 취약점을 토대로 강화된 시스템 프롬프트를 생성하고,
  Before/After 재스캔으로 개선 효과를 검증
- **재현성·통계 검정** — N회 반복 일관성 체크, Wilson 신뢰구간, 카이제곱 검정, Cramér's V
- **리포트** — CSV / JSON / PDF 형태의 요약 리포트 내보내기

## 아키텍처

```
공격 데이터셋 (25개 페이로드 · 10개 카테고리 · OWASP LLM 2025 + MITRE ATLAS)
        │ [ThreadPoolExecutor]
        ▼
TARGET  테스트 대상 모델 · 시스템 프롬프트
        │ 응답
        ▼
JUDGE   평가자 모델 · JSON 판결 + CVSS 벡터
        │
        ├─ CVE 스타일 ID (RTAI-YYYY-NNN)
        ├─ 적응형 공격 트리 (depth-3 재귀)
        ├─ 재현성 체커
        ├─ 통계 검정 (χ², Cramér's V)
        ├─ Before/After 비교
        ├─ 자동 하드너 (시스템 프롬프트 자동 강화)
        └─ PDF / CSV / JSON 리포트
```

## 기술 스택

- Python
- Streamlit (UI)
- Google Gemini API (`google-genai` SDK)
- Plotly (시각화), fpdf2 (PDF 리포트), pandas / numpy

## 빠른 시작

Python 3.13이 필요합니다(다른 최신 3.x 버전도 동작할 가능성이 높지만 검증하지 않았습니다).

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

- **API 키 없이 둘러보기:** **Results** 탭에서 **Load Sample Results**를 누르면
  샘플 데이터로 모든 대시보드를 보고 PDF 리포트까지 내보낼 수 있습니다.
- **실제 스캔**에는 Gemini API 키가 필요합니다. `cp .env.example .env` 후
  `GEMINI_API_KEY`를 채우거나, 사이드바에 키를 입력하세요. 스캔은 페이로드마다
  Gemini API를 호출(대상 + 심사)하므로 사용량이 소모됩니다.
- 모델 기본값은 Google의 `gemini-flash-latest`(대상)와 `gemini-pro-latest`(심사)
  별칭입니다. 다른 모델을 고정하려면 사이드바에서 **Custom model ID…**를 고르세요.

## 구조와 테스트

```
app.py              Streamlit UI, 차트, 스캔 오케스트레이션
guardian/
  config.py         모델 선택, 가격 가정, 판결 스타일
  dataset.py        공격 페이로드 + OWASP 2025 / MITRE ATLAS 공식 이름
  engine.py         Gemini 호출: 공격, 판결(출력 정규화 포함), 트리, 하드닝
  scoring.py        CVSS v3.1, KPI와 등급, CVE 스타일 ID, 통계
  report.py         CSV / PDF 내보내기
tests/              pytest 테스트 (API 호출 없음)
```

```bash
pip install -r requirements-dev.txt
python -m pytest
```

테스트는 대시보드가 보여주는 계산을 고정합니다. CVSS v3.1 기준 벡터 점수, KPI와 등급,
Wilson 구간, 카이제곱 p-value, 평가자 JSON 해석(가짜 Gemini 클라이언트 사용), PDF/CSV
내보내기, 데이터셋의 OWASP/ATLAS ID를 검사하며, push할 때마다 GitHub Actions에서
실행됩니다.

## 해커톤 이후 변경 사항 (2026-10)

2026년 10월에 해커톤 버전을 다시 살펴보면서, 실행되게 만들고 핵심 로직에 테스트를
붙이고 테스트로 찾은 문제를 고쳤습니다.

- **새로 클론해도 실행** — 원래 쓰던 Gemini 모델 ID가 서비스 종료되어 있었습니다.
  버전을 고정한 의존성, `.env.example`, 키 없이 보는 샘플 모드를 추가했습니다.
- **테스트할 수 있는 구조** — 2,300줄짜리 `app.py`에서 핵심 로직을 `guardian/` 패키지로
  옮기고(동작 변경 없음), 테스트와 CI를 붙였습니다.
- **PDF 리포트** — 최신 fpdf2에서 latin-1 밖의 문자 때문에 생성이 실패했고, 본문 글자가
  거의 보이지 않았으며 CVE ID가 잘렸습니다.
- **CVSS** — "CVSS 기반" 공식이 기준 벡터 8개 중 6개에서 CVSS v3.1과 달랐습니다(반올림
  방식, Scope에 따른 Privileges Required). 이제 명세와 일치합니다.
- **통계** — 카이제곱 p-value 공식이 틀려 p-value를 크게 보고했습니다(χ² = 3.84를 0.05가
  아니라 0.17로 보고).
- **하드닝 비교** — 전후 점수가 대시보드와 다른 공식을 써서, 같은 스캔이 두 가지 점수로
  보였습니다.
- **판결 해석** — `"V"` 같은 한 글자 판결이 모든 집계에서 빠졌습니다. 이제 평가자 JSON을
  정규화합니다.
- **판정 모델 프롬프트 인젝션** — 대상 모델의 응답이 구분 없이 판정 프롬프트에 들어가서,
  공격이 대상 모델을 통해 평가자에게 "이건 SAFE"라고 지시할 수 있었습니다. 판정 규칙은
  평가자의 시스템 지시로 옮기고, 페이로드와 응답은 호출마다 새로 만든 무작위 태그가 붙은
  구분자 사이의 신뢰할 수 없는 데이터로 전달합니다. 응답이 자기 블록을 임의로 닫을 수
  없습니다.
- **분류 체계** — `:2025`라고 표시했지만 실제로는 2023년판 OWASP 번호를 썼고, 일부 MITRE
  ATLAS ID가 다른 기법을 가리켰습니다. 다시 매핑하고 테스트로 확인합니다.

## 담당 역할

- 자동 레드팀 워크플로우를 처음부터 끝까지 설계·구현
- LLM-as-a-Judge 판결 로직과 적대적 공격 데이터셋 구축
- CVSS 기반 점수화, 자동 하드너, 리포트 생성 기능 구현
- Gemini API 연동 및 API 키 보안 관리(`.env` + `.gitignore`)

## 윤리 및 책임 있는 사용

페이로드는 모델의 거버넌스(안전 정책)만을 테스트하며, 합성 경로·CSAM·실제 위해 지침은
포함하지 않습니다. 안전 필터 완화는 **타겟 모델에만**, 그리고 오직 시스템 프롬프트의
방어력을 측정하기 위해서만 적용했으며, 운영 환경의 안전장치를 우회하려는 목적이
아닙니다. 모든 취약점에는 개선 방안을 함께 제시합니다.

## 한계점

해커톤 프로토타입으로 개발되었습니다. 목표는 자동화된 LLM 레드팀 워크플로우를
탐구하는 것이었지, 상용 수준의 스캐너를 만드는 것이 아니었습니다. 주어진 시간 안에서
우회 및 판결 로직을 완벽하게 구현하지는 못했으며, 결과는 확정적 판단이 아니라 탐색적
참고 자료로 보는 것이 적절합니다. 특히 다음 점에 유의하세요.

- 판결과 CVSS 벡터는 LLM 평가자가 정합니다. CVSS 계산 자체는 정확하지만, 계산 대상인
  벡터는 평가자의 판단입니다.
- 카테고리마다 페이로드가 2~4개뿐이라, 카테고리별 비율·Wilson 구간·카이제곱 검정(대표본
  근사)은 참고용입니다.
- 응답을 구분자로 감싸면 평가자 조작이 어려워질 뿐 불가능해지지는 않습니다. 평가자는
  여전히 공격자의 영향을 받은 텍스트를 읽는 LLM입니다.
- 비용 수치는 `guardian/config.py`의 고정 토큰 단가를 쓰며, 선택한 모델의 현재 가격이
  아닙니다.
- 2026년 변경 이후 실제 스캔은 다시 돌리지 않았습니다(API 키와 사용량 필요). 변경 사항은
  오프라인 테스트와 샘플 데이터 모드로 확인했습니다.

## 향후 과제

- 공격 데이터셋 확장 및 판결 로직 고도화
- 더 많은 타겟 모델과 실제 시스템 프롬프트로 검증
- 취약점 결과를 클라우드 기반의 지속적 모니터링 파이프라인으로 연계
