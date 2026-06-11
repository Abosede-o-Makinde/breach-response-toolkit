# breach-response-toolkit

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![GDPR Art. 33/34](https://img.shields.io/badge/GDPR-Art.%2033%2F34-important)](docs/ICO_NOTIFICATION_GUIDE.md)
[![Status](https://img.shields.io/badge/status-scaffold-orange)](docs/ARCHITECTURE.md)

> Python toolkit for managing data breach incidents under UK GDPR Articles 33 and 34.
> 72-hour ICO countdown · Severity classifier · NIST CSF mapper · Article 33(3) evidence log

**Current status:** Repository structure and architecture scaffold is complete. Module implementation is the next phase.

---

## The problem this solves

Under UK GDPR **Article 33**, every data controller must notify the ICO within **72 hours** of becoming aware of a personal data breach. In practice, organisations fail because:

- There is no automatic clock
- There is no objective severity standard
- There is no Article 33(3)-compliant evidence log template
- Commercial tools cost £15,000–£60,000/year

**breach-response-toolkit** handles all of it from the command line. Free. Open source. Local-only.

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
├── sample_outputs/            # Pre-generated examples (after implementation)
├── tests/                     # 57+ tests (target)
└── .github/workflows/         # CI/CD: test + release pipelines
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full architecture specification.

---

## Installation

```bash
pip install -r requirements.txt
python main.py --help
```

---

## Planned commands

| Command | Description |
|---------|-------------|
| `python main.py --mode report` | Full breach report pipeline |
| `python main.py --mode timer` | 72-hour Article 33 countdown |
| `python main.py --mode classify` | Severity classification only |
| `python main.py --mode nist` | NIST CSF breach mapping only |
| `python main.py --mode notify` | ICO notification draft only |

```bash
# Full report (once implemented)
python main.py --mode report --input sample_data/example_breach.json --output outputs/

# Timer only
python main.py --mode timer --detection "2024-06-09T14:30:00Z" --breach-id "B-2024-001"
```

---

## GDPR coverage

| Article | Obligation | How this tool addresses it |
|---------|------------|----------------------------|
| **Art. 33(1)** | Notify ICO within 72 hours | Timer with WARNING (48hr) and CRITICAL (68hr) alerts |
| **Art. 33(3)(a–d)** | Four mandatory notification fields | Evidence log with completeness scoring |
| **Art. 34(1)** | Notify data subjects if high risk | Subject notification flag in classifier |
| **Art. 5(1)(f)** | Integrity and confidentiality | NIST CSF control failure identification |

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
