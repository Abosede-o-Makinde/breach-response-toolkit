# breach-response-toolkit

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![GDPR Art. 33/34](https://img.shields.io/badge/GDPR-Art.%2033%2F34-important)](docs/ICO_NOTIFICATION_GUIDE.md)

> Python toolkit for managing data breach incidents under UK GDPR Articles 33 and 34.
> 72-hour ICO countdown · Severity classifier · NIST CSF mapper · Article 33(3) evidence log

---

## The problem this solves

Under UK GDPR **Article 33**, every data controller must notify the ICO within **72 hours** of becoming aware of a personal data breach. In practice, organisations fail because:

- There is no automatic clock
- There is no objective severity standard
- There is no Article 33(3)-compliant evidence log template
- Commercial tools cost £15,000–£60,000/year

**breach-response-toolkit** handles all of it from the command line. Free. Open source. Local-only.

---

## Features

| Capability | Module | CLI mode |
| ---------- | ------ | -------- |
| 72-hour Article 33 countdown with escalating alerts | `timer.py` | `--mode timer` |
| Four-weight severity scoring and notification flags | `classifier.py` | `--mode classify` |
| NIST CSF v1.1 control failure mapping | `nist_mapper.py` | `--mode nist` |
| Article 33(3) evidence log (JSON + Markdown) | `evidence_log.py` | `--mode report` |
| Pre-filled ICO notification draft | `ico_notification.py` | `--mode notify` |
| Seven-page A4 incident report (PDF) | `pdf_report.py` | `--mode report` |

Run individual modules or the full pipeline end-to-end with `--mode report`.

---

## Installation

```bash
pip install -r requirements.txt
python main.py --help
python main.py --version
```

---

## Commands

All functionality runs through **`python main.py`**. Pick a `--mode` and the flags it needs.

| Mode | Required flags | What you get |
| ---- | -------------- | ------------ |
| `report` | `--input breach.json` | Full pipeline — writes all four files under `--output` (default: `outputs/`) |
| `timer` | `--detection` (ISO 8601 UTC), `--breach-id` | 72-hour countdown in the terminal |
| `classify` | `--input breach.json` | Severity score and notification flags (JSON printed) |
| `nist` | `--breach-type`, `--data-type`, `--severity` | NIST CSF failed controls (printed) |
| `notify` | `--input breach.json` | ICO notification draft (`.txt` file) |

Optional on any mode: `--output outputs/` (where files are written).

### Examples

```bash
# Full breach response — all artefacts under outputs/B-2024-001/
python main.py --mode report --input sample_data/example_breach.json --output outputs/

# 72-hour countdown (use today's detection time for a live window)
python main.py --mode timer --detection "2026-06-15T08:00:00Z" --breach-id "B-2024-001"

# Severity classification
python main.py --mode classify --input sample_data/example_breach.json

# NIST CSF mapping
python main.py --mode nist --breach-type confidentiality --data-type financial --severity HIGH

# ICO notification draft only
python main.py --mode notify --input sample_data/example_breach.json --output outputs/
```

### Output files (`--mode report`)

Each full report run creates:

```
outputs/{breach_id}/
├── evidence_log.json      # Structured Article 33(3) log
├── evidence_log.md        # Human-readable evidence log
├── ico_notification.txt   # Pre-filled ICO draft
└── breach_report.pdf      # Seven-page incident report
```

Pre-generated examples (no local run required): [`sample_outputs/B-2024-001/`](sample_outputs/B-2024-001/)

---

## GDPR coverage

| Article | Obligation | Handled by |
| ------- | ---------- | ---------- |
| **Art. 33(1)** | Notify ICO within 72 hours | Timer + pipeline |
| **Art. 33(3)(a–d)** | Four mandatory notification fields | Evidence log + ICO draft |
| **Art. 34(1)** | Notify data subjects if high risk | Classifier |
| **Art. 5(1)(f)** | Integrity and confidentiality | NIST mapper |

Outputs are **decision-support drafts for DPO review** — not legal advice and not auto-submitted to the ICO.

---

## Why local-only?

breach-response-toolkit makes **no network calls**. All processing happens on your machine. Breach evidence should not leave your controlled environment until you choose to submit it to the ICO.

---

## Repository structure

```
breach-response-toolkit/
├── main.py                    # CLI entry point
├── src/breach/                # Timer, classifier, NIST mapper, evidence log, ICO draft
├── src/reporter/              # PDF report generator
├── src/pipeline.py            # Full report orchestration
├── config/                    # Classification rules, NIST mappings
├── templates/                 # Jinja2 templates
├── sample_data/               # Example breach input JSON
├── sample_outputs/            # Pre-generated example artefacts
└── docs/                      # Architecture and practitioner guides
```

---

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — module design, data flow, security controls
- [Breach Response Guide](docs/BREACH_RESPONSE_GUIDE.md) — plain-English 72-hour procedure
- [ICO Notification Guide](docs/ICO_NOTIFICATION_GUIDE.md) — Article 33(3) field-by-field reference

---

## Licence

MIT — free to use, modify, and distribute. See [LICENSE](LICENSE).
