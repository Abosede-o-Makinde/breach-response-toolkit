# breach-response-toolkit

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![GDPR Art. 33/34](https://img.shields.io/badge/GDPR-Art.%2033%2F34-important)](docs/ICO_NOTIFICATION_GUIDE.md)
[![Status](https://img.shields.io/badge/status-in%20development-yellow)](docs/ARCHITECTURE.md)

> Python toolkit for managing data breach incidents under UK GDPR Articles 33 and 34.
> 72-hour ICO countdown · Severity classifier · NIST CSF mapper · Article 33(3) evidence log

**Current status:** Days 9–10 complete — full report pipeline, sample outputs, and security tests are live. Release polish next (days 11–12).

---

## The problem this solves

Under UK GDPR **Article 33**, every data controller must notify the ICO within **72 hours** of becoming aware of a personal data breach. In practice, organisations fail because:

- There is no automatic clock
- There is no objective severity standard
- There is no Article 33(3)-compliant evidence log template
- Commercial tools cost £15,000–£60,000/year

**breach-response-toolkit** handles all of it from the command line. Free. Open source. Local-only.

---

## Sprint schedule (9–22 June 2026)

Two layers from the developer brief and blueprint:

| Layer | What it is |
| ----- | ---------- |
| **Setup** (pre-sprint) | Repo scaffold — structure, models, configs, templates, CI skeleton, stubs. **Done** before module coding started. |
| **12-day sprint** (below) | Actual implementation — modules, tests, pipeline, release. **In progress.** |

### Day plan

| Days | Dates (approx.) | Focus | Status |
| ---- | --------------- | ----- | ------ |
| — | Before 9 Jun | Repo scaffold + architecture | Done |
| 1–2 | 9–10 Jun | `breach_model.py`, `timer.py`, `classifier.py` + tests | Done |
| 3–4 | 11–12 Jun | `nist_mapper.py`, `evidence_log.py` + tests | Done |
| 5–6 | 13–14 Jun | `ico_notification.py`, templates, `main.py` CLI wiring | Done |
| 7–8 | 15–16 Jun | `pdf_report.py` | Done |
| 9–10 | 17–18 Jun | Full pipeline, `sample_outputs/`, security tests | Done |
| 11–12 | 19–22 Jun | CI polish, docs, README screenshots, v1.0.0 tag | Next |

**Deadline:** v1.0.0 by **22 June 2026** · ≥57 tests · ≥85% coverage

### Module phases (maps to days above)

These are the **build order** from [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — not separate from the sprint, just the same work broken down by file:

| Phase | Module | Sprint days | Tests |
| ----- | ------ | ----------- | ----- |
| — | Setup (scaffold) | Pre-sprint | scaffold smoke tests |
| 1 | `timer.py` | 1–2 | 12 ✓ |
| 2 | `classifier.py` | 1–2 | 15 ✓ |
| 3 | `nist_mapper.py` | 3–4 | 10 ✓ |
| 4 | `evidence_log.py` | 3–4 | 8 ✓ |
| 5 | `ico_notification.py` | 5–6 | 8 ✓ |
| 6 | `pdf_report.py` | 7–8 | 8 ✓ |
| 7 | `pipeline.py` + `--mode report` | 9–10 | 8 ✓ |
| 8 | Sample outputs, security tests | 9–10 | 6 ✓ |
| 9 | Release, docs polish | 11–12 | — ← **next** |

---

## Repository structure

```
breach-response-toolkit/
├── main.py                    # CLI entry point (--mode router)
├── src/
│   ├── breach/                # Timer, classifier, NIST mapper, evidence log, ICO draft
│   ├── models/                # Pydantic input/output models
│   ├── reporter/              # PDF report generator
│   └── pipeline.py            # Full report pipeline orchestration
├── config/                    # breach_types.json, nist_mappings.json
├── templates/                 # Jinja2: ICO notification, Markdown evidence log
├── docs/                      # Architecture + practitioner guides
├── sample_data/               # Example breach input JSON
├── sample_outputs/            # Pre-generated examples (see sample_outputs/README.md)
├── tests/                     # 84 passing tests
└── .github/workflows/         # CI/CD: test + release pipelines
```

---

## Installation

```bash
pip install -r requirements.txt
python main.py --help
```

---

## CLI commands

| Command | Status | Description |
| ------- | ------ | ----------- |
| `python main.py --mode timer` | **Working** | 72-hour Article 33 countdown |
| `python main.py --mode classify` | **Working** | Severity classification from breach JSON |
| `python main.py --mode nist` | **Working** | NIST CSF breach mapping |
| `python main.py --mode report` | **Working** | Full breach report pipeline |
| `python main.py --mode notify` | **Working** | ICO notification draft from breach JSON |

### Working now

```bash
# 72-hour countdown with escalating alerts at 48h and 68h
python main.py --mode timer --detection "2024-06-09T14:30:00Z" --breach-id "B-2024-001"

# Severity classification from sample input
python main.py --mode classify --input sample_data/example_breach.json

# NIST CSF mapping for a confidentiality breach at HIGH severity
python main.py --mode nist --breach-type confidentiality --data-type financial --severity HIGH

# ICO notification draft for DPO review
python main.py --mode notify --input sample_data/example_breach.json

# Full report pipeline — all four output files under outputs/{breach_id}/
python main.py --mode report --input sample_data/example_breach.json --output outputs/
```

Pre-generated examples are in [`sample_outputs/B-2024-001/`](sample_outputs/B-2024-001/).

### Sample outputs (no run required)

```bash
# Inspect pre-generated artefacts from the README
ls sample_outputs/B-2024-001/
# evidence_log.json  evidence_log.md  ico_notification.txt  breach_report.pdf
```

---

## GDPR coverage

| Article | Obligation | Module | Status |
| ------- | ---------- | ------ | ------ |
| **Art. 33(1)** | Notify ICO within 72 hours | `timer.py` | Done |
| **Art. 33(3)(a–d)** | Four mandatory notification fields | `evidence_log.py` | Done |
| **Art. 34(1)** | Notify data subjects if high risk | `classifier.py` | Done |
| **Art. 5(1)(f)** | Integrity and confidentiality | `nist_mapper.py` | Done |

---

## Why local-only?

breach-response-toolkit makes **no network calls**. All processing happens on your machine. Breach evidence should not leave your controlled environment until you choose to submit it to the ICO.

---

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — module design, data flow, security controls
- [Breach Response Guide](docs/BREACH_RESPONSE_GUIDE.md) — plain-English 72-hour procedure
- [ICO Notification Guide](docs/ICO_NOTIFICATION_GUIDE.md) — Article 33(3) field-by-field reference

---

## Part of the Data Protection Engineering portfolio

Related repositories:

- [dp-audit-toolkit](https://github.com/[YOUR-USERNAME]/dp-audit-toolkit) — 36-control GDPR audit engine
- [gdpr-security-mapper](https://github.com/[YOUR-USERNAME]/gdpr-security-mapper) — Maps security configs to GDPR articles *(coming soon)*

---

## Licence

MIT — free to use, modify, and distribute. See [LICENSE](LICENSE).
