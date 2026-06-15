# Sample outputs

Pre-generated artefacts from `sample_data/example_breach.json`, produced by:

```bash
python main.py --mode report --input sample_data/example_breach.json --output sample_outputs/
```

These files let you inspect output format without running the toolkit locally.

| File | Description |
| ---- | ----------- |
| `B-2024-001/evidence_log.json` | Article 33(3) structured evidence log |
| `B-2024-001/evidence_log.md` | Human-readable evidence log |
| `B-2024-001/ico_notification.txt` | Pre-filled ICO notification draft |
| `B-2024-001/breach_report.pdf` | Seven-page A4 incident report |

**Note:** The sample breach uses a June 2024 detection date, so timer fields show an **EXPIRED** 72-hour window when viewed today. That is expected for static demo data.
