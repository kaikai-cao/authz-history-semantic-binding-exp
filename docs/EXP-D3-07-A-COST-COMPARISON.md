# EXP-D3-07-A — Cost Comparison

## 1. Method

- Test: `tests/d3_07_a_cost.rs`
- Same machine, same release profile (`opt-level = 3`), fixed D3-C GG proof seed `20261124`.
- One D3-06-C keygen/proof is produced, then verification paths are measured.
- Keygen and prove time are not counted as external-anchor overhead; they are unchanged by this stage.
- All numbers are observed values from this run, not theoretical minima and not a performance optimization claim.

## 2. Measurements

| Metric | Observed | Notes |
| --- | --- | --- |
| canonical checkpoint encode | 1.873 µs / call, n=1000 | D1-compatible `encode_checkpoint` |
| checkpoint digest | 1.895 µs / call, n=1000 | SHA-256 over canonical bytes |
| anchor verification path | 0.5500 ms / call, n=100 | includes canonical encoding, digest, QC Ed25519 verification, time policy and local state read |
| local state read | 0.1697 ms / call, n=1000 | JSON file read + parse under mutex |
| local state write | 4.8788 ms / call, n=100 | temp file + `sync_all` + rename; platform-dependent |
| Halo2 proof verify | 838.4089 ms / call, n=20 | D3-06-C GG proof, K=16, 7072 B |
| combined verification | 848.2793 ms / call, n=1 | anchor path + binding + Halo2 verify + state commit |
| envelope JSON size | 1121 B | test serialization size, not canonical signature size |
| QC JSON size | 609 B | three signatures |
| canonical checkpoint size | 560 B | D1 signature payload |
| proof size | 7072 B | unchanged D3-06-C proof |

Memory RSS was not measured: no portable in-process RSS API was available. This is recorded as unmeasured, not as zero.

## 3. Interpretation

The cryptographic anchor path is small relative to Halo2 verification in this run: roughly 0.55 ms versus 838 ms. Local durable state writes are materially more expensive (~4.9 ms) because they include file synchronization on Windows. The combined run was about 9.9 ms above the separately measured Halo2 verify average; this difference includes one state read, one state write, binding checks and run-to-run variance.

These measurements do **not** imply a general performance claim:

- no network query was performed;
- no external Witness service was deployed;
- no cross-process file-lock stress test was run;
- the local state path is a prototype, not a production database;
- Halo2 verification timing varies with machine load and build environment.

## 4. Cost categories

| Category | Measured here? | Value / boundary |
| --- | --- | --- |
| Pure cryptographic anchor verification | partially | included in 0.55 ms anchor path; no standalone split for Ed25519 only |
| Local persistence | yes | read 0.1697 ms; write 4.8788 ms |
| External network latest-checkpoint query | no | not implemented; no number fabricated |
| Halo2 proof verification | yes | 838.4089 ms same-run observed |
| Keygen / proving | no change | frozen D3-06-C behavior; not counted as bridge overhead |

## 5. Conclusion

The host-side trust bridge adds a small cryptographic and binding layer, with the dominant new cost coming from durable local state writes rather than Ed25519 verification. This supports feasibility of the bridge prototype, but it does not reduce or alter D3-06-C proving cost and does not replace an external latestness service.
