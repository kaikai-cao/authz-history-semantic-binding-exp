# EXP-D3-07-A — Summary

## 1. Stage result

`EXP-D3-07-A` is complete within its declared scope.

The stage question was how a D3-06-C proof's trusted pre-state should be anchored externally, and how far freshness can be claimed. The implemented answer is:

> A D1-style checkpoint/QC envelope can authenticate a canonical carrier of `C_prev`; host-side checks can enforce time policy and local non-regression; and the D3-06-C Halo2 proof can then be verified against the same eight public instances. This establishes a trusted-anchor bridge, not global latestness.

The system can prove:

> Given an externally anchored and locally non-regressing S0, two ordered events execute on the single chain S0 → S1 → S2.

It cannot prove:

> S0 is the current latest authorization state.

An R1 revision subsequently closed a configuration gap: the D1 3-of-4 witness profile is now enforced inside `verify_anchor` before any QC field is interpreted, and the `NO_LOG` / `log_size = 0` anchor profile is explicit. No Halo2 circuit, public instance, or frozen implementation was changed by R1.

## 2. Added files

```text
src/anchor/canonical.rs
src/anchor/combined.rs
src/anchor/mod.rs
src/anchor/state.rs
src/anchor/types.rs
src/anchor/verifier.rs
tests/d3_07_a_anchor.rs
tests/d3_07_a_cost.rs
docs/EXP-D3-07-A-BASELINE.md
docs/EXP-D3-07-A-ANCHOR-SPEC.md
docs/EXP-D3-07-A-SECURITY-TESTS.md
docs/EXP-D3-07-A-FRESHNESS-ANALYSIS.md
docs/EXP-D3-07-A-COST-COMPARISON.md
docs/EXP-D3-07-A-SUMMARY.md
```

Modified for integration only:

- `Cargo.toml` / `Cargo.lock`: add `ed25519-dalek = 2.1.1`;
- `src/lib.rs`: one `pub mod anchor;` registration.

No Halo2 circuit, witness builder, frozen test or historical document was modified. R1 touched only `src/anchor/types.rs`, `src/anchor/verifier.rs`, `tests/d3_07_a_anchor.rs`, and the three R1-updated documents (`ANCHOR-SPEC`, `SECURITY-TESTS`, `SUMMARY`).

## 3. D1 reuse decisions

- Reused D1 checkpoint field order and canonical encoding byte-for-byte.
- Reused D1 checkpoint SHA-256 digest and Ed25519 signing model.
- Reused D1 witness-set root encoding and 3-of-4 threshold model.
- Mapped D1 `epoch` to anchor sequence and D1 signed `timestamp` to an explicit issued-time policy.
- Mapped D3 `C_prev` into the signed D1 `state_root` as lowercase canonical field hex.
- Mapped policy/version into the signed D1 `policy_version` string.
- Used `NO_LOG`; no RFC6962 inclusion/consistency is claimed.
- Strengthened duplicate-witness handling: any repeated witness ID is rejected.

The verifier does not check witness persistent locks. D1 E7 remains the authoritative boundary for that assumption.

## 4. Implemented checks

`verify_anchor` performs:

- trusted-config validation before QC parsing: `threshold = 3`, exactly four witnesses, non-empty IDs, no duplicate `witness_id` or public key, and parseable Ed25519 public keys;
- mandatory anchor profile checks: `log_root == "NO_LOG"` and `log_size == 0`;
- canonical field validation;
- checkpoint digest / QC hash / epoch / previous-hash checks;
- chain ID and witness-set ID checks;
- witness-set root check against trusted config;
- duplicate/unknown witness rejection;
- Ed25519 signature verification and threshold counting;
- max-age / max-skew time policy;
- sequence monotonicity, same-sequence equivocation and chain-parent checks;
- local durable state read.

`bind_to_instances` checks:

- `C_prev == instances[0]`;
- checkpoint epoch `== instances[1]`;
- checkpoint policy `== instances[4]`;
- checkpoint transition version `== instances[5]`;
- `event_count == 2` at `instances[7]`.

`verify_anchored_transition` enforces the full order and only commits local state after the Halo2 proof verifies.

## 5. Test evidence

A01–A36 all passed:

- A01–A07: QC security;
- A08–A12: D3 instance binding;
- A13–A17: time policy and anti-rollback verification;
- A18–A21: durable commit, restart and concurrent commit behavior;
- A22–A28: combined verification, including proof-failure no-commit checks;
- A29–A36: trusted-config and anchor-profile fail-closed checks, including a zero-signature QC with `threshold = 0`.

Negative cases enter the actual verifier/binding/combined path. A09–A12 are re-signed so the QC path succeeds and the intended binding check rejects them; A35/A36 use re-signed envelopes but profile checks precede QC verification, so these tests do not claim the QC path was executed; A29/A30 clear the QC signatures but are rejected by config validation first.

Full `cargo test --release` result after R1: **374 passed / 0 failed / 3 ignored**. `cargo fmt --all -- --check` and `git diff --check` both pass.

## 6. Cost summary

Same-run observations:

| Metric | Value |
| --- | --- |
| checkpoint hash | 1.895 µs |
| canonical encode | 1.873 µs |
| anchor verification path | 0.5500 ms |
| local state read | 0.1697 ms |
| local state write | 4.8788 ms |
| Halo2 proof verify | 838.4089 ms |
| combined verification | 848.2793 ms |
| envelope / QC / canonical / proof size | 1121 B / 609 B / 560 B / 7072 B |

No external network query was performed and no portable RSS measurement was available. These are bridge-cost observations, not optimization claims.

## 7. Known limitations

- No external trusted latest-checkpoint service.
- No first-contact historical rollback detection.
- No witness persistent-lock verification from a single envelope.
- No witness-set rotation protocol.
- No RFC6962 inclusion/consistency in this profile.
- No production key management.
- No Halo2 circuit-side anchor proof; the anchor layer is host-side only.
- Quorum re-signing old content cannot be unconditionally detected.
- Time validity is not global freshness.
- `C_next` is not treated as a newly certified checkpoint.
- Trusted config provisioning is external; R1 only enforces its fixed D1 3-of-4 shape and cannot authenticate the config source itself.

## 8. BLOCKED items

None. Phase 0 found D1 field limitations, but the explicit anchor profile in `EXP-D3-07-A-ANCHOR-SPEC.md` binds all D3-relevant values inside D1-signed fields without modifying D1.

## 9. Next stage boundary

This stage stops here. D3-07-B is not started. Any later stage must separately define external latestness queries, witness rotation, transparency-log inclusion if needed, and a concrete trust model for first contact.
