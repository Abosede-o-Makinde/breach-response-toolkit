# Breach Response Guide — The First 72 Hours

> **Audience:** DPOs, security teams, and incident responders at UK organisations.

## What this guide covers

A plain-English procedure for what to do in the 72 hours after discovering a personal data breach under UK GDPR Article 33.

## The 72-hour clock

- When the clock starts (moment of awareness, not discovery of root cause)
- Who owns the countdown
- What happens at 48 hours (WARNING) and 68 hours (CRITICAL)
- What to do if the window has expired

## Step-by-step procedure

### Hour 0–4: Contain and assess

1. Contain the breach (isolate systems, revoke access)
2. Record detection datetime in UTC
3. Start the breach-response-toolkit timer
4. Identify affected data categories and approximate numbers

### Hour 4–24: Investigate and classify

1. Run the severity classifier
2. Determine ICO notification requirement (Art. 33)
3. Determine subject notification requirement (Art. 34)
4. Begin the Article 33(3) evidence log

### Hour 24–48: Document and draft

1. Complete all four Article 33(3) fields in the evidence log
2. Generate the ICO notification draft
3. Internal legal/DPO review
4. Map failed controls via NIST CSF

### Hour 48–72: Notify and follow up

1. Submit ICO notification via ico.org.uk/report-a-breach
2. Notify affected individuals if required (Art. 34)
3. Document all measures taken
4. Preserve the evidence log for regulatory inquiry

## Using breach-response-toolkit in each step

| Step | Command |
|------|---------|
| Start timer | `python main.py --mode timer --detection "..."` |
| Classify severity | `python main.py --mode classify --input breach.json` |
| Full report | `python main.py --mode report --input breach.json` |

## Important disclaimer

This guide and the toolkit provide decision support. All breach notifications must be reviewed by a qualified DPO or legal representative before submission to the ICO.
