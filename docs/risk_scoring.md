# Risk Scoring

Risk scores quantify how dangerous each trifecta finding is on a 0-100 scale.

## Components

Each finding's risk score is computed from 6 weighted components:

| Component              | Weight | Description                                              |
|------------------------|--------|----------------------------------------------------------|
| `trifecta_completeness`| 30%    | How many of the 3 trifecta legs are present (0, 1, 2, 3) |
| `cross_server`         | 20%    | Whether the trifecta spans multiple MCP servers          |
| `capability_count`     | 15%    | Total number of dangerous capabilities involved          |
| `data_sensitivity`     | 15%    | Sensitivity of the data the read-leg can access          |
| `exfil_bandwidth`      | 10%    | How much data the exfil-leg can send per call            |
| `exploit_confirmed`    | 10%    | Whether a sandbox exploit successfully confirmed the path |

## Score Bands

| Score Range | Label    | Meaning                                              |
|-------------|----------|------------------------------------------------------|
| 90-100      | Critical | Confirmed exfiltration path, cross-server, broad access |
| 70-89       | High     | Strong trifecta with plausible attack scenario       |
| 50-69       | Medium   | Partial trifecta or single-server only               |
| 30-49       | Low      | Weak keyword match, low confidence classification    |
| 0-29        | Info     | Informational; unlikely to be exploitable            |

## Overall Risk

The overall risk percentage for a scan is computed as a weighted average of
all finding scores, with higher-scored findings given exponentially more weight.
This prevents a single critical finding from being diluted by many low findings.

```
overall = sum(score^2 for score in scores) / sum(score for score in scores)
```

If there are no findings, the overall risk is 0%.

## Interpreting Results

- **Score above 80**: Immediate attention required. Review which tools are
  granting read + ingest + exfil access and disable the riskiest server.
- **Score 50-80**: Review the trifecta path. Consider whether the use case
  genuinely requires all three capabilities simultaneously.
- **Score below 50**: Monitor and re-scan after any server updates.
