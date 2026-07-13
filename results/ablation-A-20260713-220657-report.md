# Reproducible experiment report: ablation-A-20260713-220657

> Every value in this report was calculated from the SQLite evidence table. No expected result is hard-coded.

## Overall results

| Metric | Value |
|---|---:|
| Scenario | A_no_waf |
| Durable unique events | 500 |
| Successful vulnerability validations | 500 |
| Success rate | 100.000% |
| Average DRS | 8.900 |
| End-to-end average latency | 20.927 ms |
| End-to-end P95 latency | 33.903 ms |
| End-to-end P99 latency | 57.362 ms |

## Results by attack type

| Attack type | Count | Success | Avg DRS | Avg latency (ms) | P95 (ms) |
|---|---:|---:|---:|---:|---:|
| sql_injection | 500 | 500 | 8.900 | 20.927 | 33.903 |

## SQL injection ablation metrics

| Metric | Value |
|---|---:|
| Ground-truth positives | 500 |
| Ground-truth negatives | 0 |
| Static-model false positives | 0 |
| Static-model FPR | None% |
| DRS false positives | 0 |
| DRS FPR | None% |

## Compared ablation run

Comparison run: `ablation-B-20260713-220657` / scenario `B_waf_enabled`.
Static-model FPR: 100.0%; DRS FPR: 0.0%.

## Interpretation boundary

- A Padding Error response demonstrates distinguishable oracle behavior; it does not by itself demonstrate plaintext recovery.
- Zero loss may be stated only when the stress-test `persisted` count equals the planned count.
- Latency values are environment-specific and must be reported with this run ID and VM configuration.
