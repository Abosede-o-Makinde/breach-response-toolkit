# Breach Evidence Log — B-2024-001

> **Schema version:** 1.0
> **Created (UTC):** 2026-06-14T16:03:22.521327+00:00
> **Last updated (UTC):** 2026-06-14T16:03:22.521327+00:00
> **Article 33(3) completeness:** 100.0%

---

## Article 33(3)(a) — Nature of the Breach

| Field | Value |
|-------|-------|
| Description | Unauthorised access to customer financial records via SQL injection in the payment portal |
| Breach type | CONFIDENTIALITY |
| Data categories | bank account numbers, sort codes, full names, transaction references |
| Approx. data subjects | 1500 |
| Approx. records | 1500 |

## Article 33(3)(b) — Contact Point

| Field | Value |
|-------|-------|
| Name | Jane Smith |
| Role | Data Protection Officer |
| Email | dpo@organisation.com |
| Telephone | 01234 567890 |

## Article 33(3)(c) — Likely Consequences


1. Financial fraud using exposed bank account numbers and sort codes

2. Identity theft risk for 1,500 affected customers

3. Potential regulatory action from the ICO


## Article 33(3)(d) — Measures Taken


1. Payment portal taken offline at 15:00 UTC on 9 June 2024

2. Incident response team engaged; forensic investigation commenced

3. Affected customers notified by email at 18:00 UTC on 9 June 2024

4. SQL injection vulnerability patched; security scan in progress


---

## Internal Tracking

- **Detection (UTC):** 2024-06-09T14:30:00+00:00
- **Notification deadline (UTC):** 2024-06-12T14:30:00+00:00
- **Severity:** HIGH (score: 55.0)
- **ICO notification required:** True
- **Subject notification required:** False
- **Timer alert level:** EXPIRED
- **NIST framework:** NIST CSF v1.1

---

## Audit Trail

| Timestamp (UTC) | Action | Actor |
|-----------------|--------|-------|

| 2026-06-14T16:03:22.521327+00:00 | LOG_CREATED | breach-response-toolkit v1.0.0 |
