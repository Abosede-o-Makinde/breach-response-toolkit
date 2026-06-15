# Architecture — breach-response-toolkit

## Purpose

Local-first Python CLI for UK GDPR breach response under Articles 33 and 34. Unifies five functions that organisations typically handle separately:

1. 72-hour ICO notification countdown
2. GDPR severity classification
3. NIST CSF incident mapping
4. Article 33(3) evidence logging
5. Pre-filled ICO notification drafting + PDF report

## Design principles

| Principle | Implementation |
|-----------|----------------|
| **Local-first** | No network calls; all outputs written to `outputs/{breach_id}/` |
| **Pipeline architecture** | Each module produces structured output feeding the next stage |
| **Modular CLI** | Every module invokable independently via `--mode` |
| **Validate at entry** | All input passes through `BreachInput` (Pydantic v2) before processing |
| **Forensic integrity** | UTC timestamps, append-only audit trail, path traversal prevention |
| **Decision support** | Outputs are drafts for DPO review — not legal advice or auto-submission |

## High-level architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  CLI ENTRY POINT — main.py                                          │
│  Click CLI · Rich terminal · JSON input                             │
└────────┬──────────────────────────────────────────────┬─────────────┘
         │                                              │
┌────────▼──────────────────────────────────┐  ┌────────▼────────────┐
│  BREACH MODULES (src/breach/)             │  │  REPORTER           │
│  ┌──────────┐ ┌───────────┐ ┌──────────┐  │  │  src/reporter/      │
│  │ timer    │ │ classifier│ │ nist_    │  │  │  pdf_report.py      │
│  │          │ │           │ │ mapper   │  │  └──────────┬──────────┘
│  └────┬─────┘ └─────┬─────┘ └────┬─────┘  │             │
│       └─────────────┼────────────┘        │             │
│  ┌──────────────────▼──────────────────┐ │             │
│  │  evidence_log.py                      │ │             │
│  └──────────────────┬──────────────────┘ │             │
│  ┌──────────────────▼──────────────────┐ │             │
│  │  ico_notification.py                │ │             │
│  └─────────────────────────────────────┘ │             │
└──────────────────────────────────────────┘             │
         │                                                 │
┌────────▼─────────────────────────────────────────────────▼──────────┐
│  CONFIG LAYER — config/breach_types.json, config/nist_mappings.json  │
│  TEMPLATES — templates/*.j2                                         │
└─────────────────────────────────────────────────────────────────────┘
         │
┌────────▼────────────────────────────────────────────────────────────┐
│  OUTPUT — outputs/{breach_id}/                                      │
│  ├── evidence_log.json                                              │
│  ├── evidence_log.md                                                │
│  ├── ico_notification.txt                                           │
│  └── breach_report.pdf                                              │
└─────────────────────────────────────────────────────────────────────┘
```

## Data flow (full pipeline)

```
Step 1  User input (CLI flags or --input breach.json)
          └─► BreachInput validated (Pydantic)

Step 2  BreachClassifier.classify()
          └─► ClassificationResult (severity, score, notification flags)

Step 3  BreachTimer.get_status()
          └─► TimerStatus (elapsed, remaining, alert level, deadline)

Step 4  NISTMapper.map_breach()
          └─► NISTMappingResult (failed controls, recommendations)

Step 5  EvidenceLog.create()
          └─► evidence_log.json + evidence_log.md (completeness score)

Step 6  ICONotificationGenerator.generate()
          └─► ico_notification.txt (Jinja2 template)

Step 7  BreachReportGenerator.generate()
          └─► breach_report.pdf (fpdf2)

Step 8  Rich terminal summary with all output paths
```

Orchestration lives in `src/pipeline.py` (`BreachReportPipeline`).

## Module responsibilities

| Module | File | Input | Output |
|--------|------|-------|--------|
| Timer | `src/breach/timer.py` | `detection_datetime`, `breach_id` | `TimerStatus` |
| Classifier | `src/breach/classifier.py` | `BreachInput` | `ClassificationResult` |
| NIST Mapper | `src/breach/nist_mapper.py` | `breach_type`, `severity` | `NISTMappingResult` |
| Evidence Log | `src/breach/evidence_log.py` | `EvidenceLogEntry` | JSON + Markdown files |
| ICO Notification | `src/breach/ico_notification.py` | breach + classification + timer | `DraftResult` (.txt) |
| PDF Reporter | `src/reporter/pdf_report.py` | `BreachReportData` | PDF file |

## Data models

Defined in `src/models/`:

- **`breach_model.py`** — `BreachInput`, enums (`DataType`, `BreachType`, `SeverityLevel`), `ClassificationResult`
- **`report_model.py`** — `BreachReportData` aggregated payload for PDF generation

All external input must pass through `BreachInput` before any module processes it.

## CLI modes

| Mode | Command | Purpose |
|------|---------|---------|
| `report` | `python main.py --mode report --input breach.json` | Full pipeline |
| `timer` | `python main.py --mode timer --detection "..."` | 72-hour countdown only |
| `classify` | `python main.py --mode classify --input breach.json` | Severity scoring only |
| `nist` | `python main.py --mode nist --breach-type ... --severity ...` | NIST mapping only |
| `notify` | `python main.py --mode notify --input breach.json` | ICO notification draft |

## Security controls

| Control | Where enforced |
|---------|----------------|
| No network calls | Verified by `tests/test_security.py` |
| UTC timestamps | `BreachTimer`, `EvidenceLog`, all `*_utc` fields |
| Path traversal prevention | `breach_id` regex + `Path.resolve()` prefix check |
| Append-only evidence log | `audit_trail` array in `EvidenceLog.update()` |
| Input sanitisation | Pydantic v2 strict validation on `BreachInput` |
| No eval/exec | Config parsed with `json.load()` only |

## Storage layout

| Path | Purpose | Git tracked |
|------|---------|-------------|
| `outputs/{breach_id}/` | Generated reports at runtime | No (gitignored) |
| `data/breaches/` | Reserved for persistent breach records (v2.0) | No (gitignored) |
| `sample_outputs/` | Pre-generated examples for README | Yes |
| `sample_data/` | Example input JSON for demos and tests | Yes |
| `config/` | Classification rules and NIST mappings | Yes |
| `templates/` | Jinja2 templates for ICO draft and Markdown log | Yes |

## Configuration

- **`config/breach_types.json`** — Data type weights, scale thresholds, severity bands, notification rules
- **`config/nist_mappings.json`** — NIST CSF v1.1 control mappings per breach type with GDPR cross-references

Both files are editable without changing Python code.

## Testing

The test suite in `tests/` covers each breach module, the full report pipeline, and security controls (input handling, path traversal prevention, local-only operation).

```bash
pytest tests/ -v
```

GitHub Actions runs ruff, black, and coverage checks on every push to `main`.
