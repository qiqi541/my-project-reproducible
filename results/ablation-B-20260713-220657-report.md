# Reproducible experiment report: ablation-B-20260713-220657

> Every value in this report was calculated from the SQLite evidence table. No expected result is hard-coded.

## Overall results

| Metric | Value |
|---|---:|
| Scenario | B_waf_enabled |
| Durable unique events | 500 |
| Successful vulnerability validations | 0 |
| Success rate | 0.000% |
| Average DRS | 0.000 |
| End-to-end average latency | 21.318 ms |
| End-to-end P95 latency | 34.692 ms |
| End-to-end P99 latency | 69.136 ms |

## Results by attack type

| Attack type | Count | Success | Avg DRS | Avg latency (ms) | P95 (ms) |
|---|---:|---:|---:|---:|---:|
| sql_injection | 500 | 0 | 0.000 | 21.318 | 34.692 |

## SQL injection ablation metrics

| Metric | Value |
|---|---:|
| Ground-truth positives | 0 |
| Ground-truth negatives | 500 |
| Static-model false positives | 500 |
| Static-model FPR | 100.0% |
| DRS false positives | 0 |
| DRS FPR | 0.0% |

## Compared ablation run

Comparison run: `ablation-A-20260713-220657` / scenario `A_no_waf`.
Static-model FPR: None%; DRS FPR: None%.

## Interpretation boundary

- A Padding Error response demonstrates distinguishable oracle behavior; it does not by itself demonstrate plaintext recovery.
- Zero loss may be stated only when the stress-test `persisted` count equals the planned count.
- Latency values are environment-specific and must be reported with this run ID and VM configuration.
