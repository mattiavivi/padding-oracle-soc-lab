# ADR-002: Nanosecond Crypto-Timing Separation & Finite-Sample Bimodality Detection

## Status
Accepted

## Date
2026-08-28

## Context
Timing side-channel detection on AES-CBC Padding Oracle attacks was previously evaluated using end-to-end HTTP request latency. Under varying host CPU loads and container networking jitter, this introduced false positives (benign traffic marked as anomalous) and false negatives (cryptographic leakage masked by network jitter).
Furthermore, standard asymptotic bimodality coefficients exhibited bias and spurious alerts when sample sizes were small ($n < 30$).

## Decision
1. **Nanosecond Crypto Execution Timing (`crypto_processing_time_ns`)**:
   Measure elapsed execution time using `time.perf_counter_ns()` strictly around `verify_and_extract()` and `encrypt_token()`, isolating CPU execution from Flask web framework overhead and network transit.
2. **Finite-Sample Corrected Sarle's Bimodality Coefficient ($BC_{sample}$)**:
   Implement the exact finite-sample formula:
   $$BC = \frac{\gamma^2 + 1}{\kappa + \frac{3(n-1)^2}{(n-2)(n-3)}}$$
   where $\gamma$ is sample skewness and $\kappa$ is sample Pearson kurtosis.
3. **Multi-Variate Timing Inspection**:
   Combine Sarle's $BC > 0.555$ with Interquartile Range ($IQR$) and $P_{95}-P_{50}$ dispersion to identify bimodal response distributions with statistical confidence $> 0.95$.

## Alternatives Considered

### Relying Solely on Standard Deviation ($\sigma$)
- Pros: Simple to compute in $O(n)$.
- Cons: Sensitive to isolated outliers (e.g. single slow DNS or socket delay), triggering false alarms.
- Rejected: Unacceptable false positive rate under noisy network conditions.

### Hartigan's Dip Test via SciPy / C-extension
- Pros: Formal mathematical test for unimodality vs. multimodality.
- Cons: Requires heavy external dependency (`scipy` or `diptest` native compilation).
- Rejected: Violates the constraint of keeping the core lab lightweight and free from heavy binary packages.

## Consequences
- Accurate detection of timing leakage even with timing differences down to microsecond/nanosecond levels.
- Zero false positives on uniform benign client traffic.
- Transparent reporting of both `crypto_time_ns` and `latency_ms` in telemetry events.
