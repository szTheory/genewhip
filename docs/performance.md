# Performance observations

These are descriptive results from one bounded development measurement on macOS arm64. They establish that the measured inputs completed with equivalent outputs under the stated runner; they do not establish broad compatibility, a speed guarantee, or release qualification. The report binds the runtime input identity, build, fixture inputs, host, every run, and cleanup receipts. The runtime source revision is recorded separately from the source identity and is not a public-source SHA.

## Reproduce

Use macOS with CMake 3.27+, Ninja, Python 3, and the project fixtures. The bounded scope is `evidence/v02-execution.json`: serial children, at most 600 seconds per child, 4 GiB process RSS, 2 GiB capture, finite output, and a 12-hour measurement sub-batch.

```sh
cmake -S . -B build/v02/performance -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON \
  -DGENEWHIP_BUILD_TOOLS=ON -DGENEWHIP_TEST_HOOKS=ON
cmake --build build/v02/performance --target gw_core_benchmark --parallel 2
python3 -I tools/evidence/core_benchmark.py \
  --build build/v02/performance --workload all \
  --scope evidence/v02-execution.json \
  --out build/v02/performance/full.json
python3 -I tools/evidence/core_benchmark.py \
  --validate-v02 build/v02/performance/full.json
python3 -I tools/evidence/core_benchmark.py \
  --validate-v02 build/v02/performance/full.json --report-only
```

`--report-only` revalidates the retained report and writes a sanitized descriptive summary to `build/v02/performance/public/performance.json`; it does not launch benchmark children. The raw report and attempt journals stay in the ignored build tree. For the same source and scope, validation fails closed when source, inputs, roster, output equivalence, process identities, resource receipts, or sample counts differ.

## Measured development batch

The completed batch ran 60 timed children: five fresh processes in each combination of diagnostics disabled/enabled and sampled/aggregate observation for each workload. It also ran one untimed correctness reference per workload. All 63 process starts were serial, exited successfully, and had confirmed process-group cleanup. No timed-out, cancelled, or failed child counted toward the roster.

| Workload | Window | Untimed output identity (SHA-256) | Timed samples |
| --- | --- | --- | --- |
| Control | 120 warmup + 600 measured fields | `86c18b198c6c7a8ce828c5a52df949abb3748791e459c05c91413932f6579f57` | 20 |
| Recursion94 | 0 warmup + 3,631 completed fields | `3c6a8677c6497e031925ff3c1e5c584176262f4adfab4332c17189b06495667c` | 20 |
| Tank Battle | 0 warmup + 4,196 completed fields | `e8ee5ff9a29bddefa8010927e081de963aa95e1d78c13c7a5a4524abcfdeceec` | 20 |

Elapsed time is in milliseconds. Each row reports five runs for one workload, diagnostics setting, and observer; no workloads or hosts are pooled. The p95 and maximum are the observed values among those five runs. Per-run samples remain in the raw report.

| Workload | Diagnostics | Observer | Median | p95 | Observed maximum |
| --- | --- | --- | ---: | ---: | ---: |
| Control | Off | Sampled | 385.599 | 399.380 | 399.380 |
| Control | Off | Aggregate | 385.969 | 391.130 | 391.130 |
| Control | On | Sampled | 398.880 | 404.790 | 404.790 |
| Control | On | Aggregate | 388.185 | 399.932 | 399.932 |
| Recursion94 | Off | Sampled | 3,905.528 | 3,965.433 | 3,965.433 |
| Recursion94 | Off | Aggregate | 3,804.602 | 5,370.156 | 5,370.156 |
| Recursion94 | On | Sampled | 4,824.668 | 4,982.032 | 4,982.032 |
| Recursion94 | On | Aggregate | 4,768.494 | 4,829.456 | 4,829.456 |
| Tank Battle | Off | Sampled | 4,409.624 | 4,562.772 | 4,562.772 |
| Tank Battle | Off | Aggregate | 4,066.926 | 4,326.034 | 4,326.034 |
| Tank Battle | On | Sampled | 4,116.086 | 4,158.810 | 4,158.810 |
| Tank Battle | On | Aggregate | 4,253.157 | 5,414.251 | 5,414.251 |

Comparable field latency has more than 1,000 samples per workload and diagnostics setting, so field p99 is reported. Control has 3,000 samples per setting; Recursion94 has 18,155; Tank Battle has 20,980. Five whole-run repetitions are not enough for a run-latency p99, which is omitted. Field latency includes the configured observation path; compare only the same workload, host, and diagnostics setting. Observer and diagnostics cost pairs are retained in the generated summary rather than treated as a performance guarantee.

## Build and host

- Host: Darwin 25.6.0, macOS 26.6.2, arm64. The benchmark process could not identify the host model.
- Compiler: Apple clang 21.0.0 (`clang-2100.1.1.101`); Release `-O3 -DNDEBUG`; Ninja.
- `GENEWHIP_TEST_HOOKS=ON`; desktop target off. Core-owned allocation counters are test-hook observations, not whole-process memory.
- Build configuration SHA-256: `cea97caaf6fda70a97a2552538d4b8bedb8de82f031e0897081dfa37622611d5`.
- Benchmark executable SHA-256: `5c10cd233b132fff7d39788ed3f03c80baf8ea40ac59bfdee43b3930620cc81b`.
- Runtime input source identity SHA-256: `7e8ab096db6da5f8e6ffc87256ce66c5c7db45badfd5cd1e479fa4f6079c1731`.
- Runtime input revision: `2a7a019fea81421c86a15c846865ef41dde7fcf4`; this is local provenance metadata, not a public-source SHA.

Darwin `getrusage(2)` `ru_maxrss` is recorded in bytes and covers the whole benchmark process, including the harness. Maximum observed process RSS was 168.47 MiB for Control, 1,009.23 MiB for Recursion94, and 1,164.52 MiB for Tank Battle. Maximum core-owned peak allocation was 0.91 MiB, 1.89 MiB, and 1.39 MiB respectively. The 4 GiB RSS and 2 GiB capture figures are configured ceilings, not observations or guarantees.

## Retained attempts and limits

The completed report is `build/v02/performance/full.json`; its receipt journal is `build/v02/performance/attempt-03.json`. Two earlier full batches are retained separately as non-qualifying evidence. Attempt 01 launched 63 children, all of which exited successfully, but rejected the final control reference for missing RSS-unit provenance; its runner did not retain the raw outputs or child receipts, so those rows are not reconstructed or accepted. A first control diagnostic had no journal; its start count is unknown. A later bounded control diagnostic is retained separately with one start and a confirmed receipt. Attempt 02 recorded 63 confirmed starts and complete receipts, then rejected its final report because the legacy control rows had no explicit repetition indices and qualification was set after validation. The complete Attempt 03 fixed those report-contract issues and passed validation. Failed attempt exposure is disclosed and is not combined with the accepted 63-child batch.

This measurement is specific to these source inputs, build, runner, and host. It does not measure other host systems, physical display or audio output, public game compatibility, or future source revisions. Any source or fixture change that affects runtime input identity requires a new complete bounded measurement; do not edit a report identity by hand.
