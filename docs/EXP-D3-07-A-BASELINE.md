# EXP-D3-07-A — Baseline and Protocol Audit

## 1. Frozen baseline

- Repository: `kaikai-cao/authz-history-semantic-binding-exp`
- Base branch: `exp-d3-06-c-two-event-ir-transition`
- Base commit: `25b581c36a603cc6af260b85d8e18802d19dc972`
- New branch: `exp-d3-07-a-external-anchor-freshness`
- Verified before branching:
  - current branch = base branch;
  - `HEAD` = base commit;
  - `origin/exp-d3-06-c-two-event-ir-transition` and GitHub remote = base commit;
  - working tree clean;
  - D3-06-C summary, sequential-state model and circuit spec all exist.

The Halo2 circuits, tests and historical documents of D3-06-B/C and earlier stages remain frozen. This stage adds a host-side anchor module and documentation only.

## 2. D1 source audit

Repository audited: `D:\Research\authorization-state-trust-exp`, origin `kaikai-cao/authorization-state-trust-exp`.

### 2.1 Checkpoint and QC structures

`src/models.py:34-57` defines:

```text
Checkpoint(chain_id, epoch, previous_hash, state_root, log_root,
           policy_version, witness_set_root, log_size, timestamp)

QuorumCertificate(checkpoint_hash, epoch, previous_hash,
                  signatures=((witness_id, signature_hex), ...))
```

`state_root` and `log_root` are separate signed strings. `src/models.py:92-114` constructs D1 checkpoints with `state_root = state_root(events[:prefix_len])`, but verification does not recompute the authorization history root from events. In D1, `state_root` is therefore a signed field, not a universally fixed hash format at the verifier boundary.

`log_root = "NO_LOG"` is an explicit D1 marker for schemes without a transparency log (`src/models.py:98-100`).

### 2.2 Canonical encoding

`src/canonical.py:11-40`:

- prefix: `b"EXP-D1-E:"`;
- domain: `enc_str(domain)`;
- each field name: `enc_str(name)`;
- string: 8-byte big-endian length + UTF-8 bytes;
- integer: 8-byte big-endian signed int64;
- bytes: 8-byte big-endian length + raw bytes;
- `repr()` is never used.

`encode_checkpoint` (`src/canonical.py:61-72`) signs the nine D1 fields in the exact order shown above. `checkpoint_hash` (`src/crypto.py:25-26`) is `sha256_hex(encode_checkpoint(cp))`.

`encode_witness_set` (`src/canonical.py:86-90`) sorts public-key hex strings lexicographically and length-prefixes each. `witness_set_root` (`src/crypto.py:33-34`) is SHA-256 of that encoding.

### 2.3 Witness QC

`src/crypto.py:1-11,42-72` uses Ed25519. Keys are deterministically derived as `sha256(seed || b"|" || key_id)` (`src/crypto.py:50-60`), matching the test-vector model.

`src/quorum.py:45-98` implements `QuorumSigner`:

- 4 witnesses, threshold 3 (`config.json:6-7`);
- QC binds `checkpoint_hash`, `epoch`, `previous_hash` and signatures;
- signature payload is `encode_checkpoint(cp)`;
- unknown witness IDs are rejected because only `QuorumSigner._publics` is used;
- duplicate witness IDs with different signatures are rejected; exact duplicate signatures are de-duplicated by the D1 dictionary logic;
- fewer than threshold distinct valid signatures are rejected.

This stage keeps the D1 signature, encoding, threshold and trusted-public-key model. It deliberately **strengthens** duplicate handling: any repeated witness ID in an anchor QC is rejected, not merely de-duplicated, because A04 requires explicit duplicate-witness rejection.

### 2.4 Witness persistent lock

`src/quorum.py:12-39` models a witness lock table `parent_checkpoint_hash -> child_checkpoint_hash`. A witness refuses to sign a second child for the same parent. `export_locks()` / `restored()` simulate persistence and restart.

`tests/test_e7_witness_rollback.py:17-30` shows that losing locks for a quorum can create conflicting QCs. This is a witness-side operational assumption, not something a verifier can infer from one envelope. The D3-07-A verifier does **not** claim to check persistent locks.

### 2.5 RFC6962 transparency log

`src/merkle.py` and `src/transparency.py:21-164` implement RFC6962-style inclusion and consistency proofs, signed Tree Heads and split-view comparison. `tests/test_r1_logroot_binding.py:40-94` verifies that `log_root` is inside the signed checkpoint and that consistency checks can fail even when QC is valid.

D3-07-A does not deploy a transparency log. Anchor checkpoints use `log_root = "NO_LOG"`, `log_size = 0`; therefore this stage claims no inclusion or consistency guarantee.

### 2.6 D1 freshness boundary

`src/gateway.py:21-52`:

- A/C gateway accepts only chain-continuous, strictly epoch-increasing checkpoints with valid QC;
- `freshness_claim(external_attestation)` returns true only when an external attestation is supplied (`src/gateway.py:49-52`);
- B gateway consistency proofs prove append-only consistency, not latestness (`src/gateway.py:85-88`).

`tests/test_e3_replay.py`, `test_e4_cold_start.py` and `test_e7_witness_rollback.py` explicitly show replay, cold-start and witness-lock-loss limits. No internal signature check is treated as global freshness.

## 3. D3-06-C interface audit

`docs/EXP-D3-06-C-SUMMARY.md:49-58` and `src/transition/d3_06_c_types.rs:342-379` establish:

```text
C_prev = poseidon::<6>([D3-STATE-v2, GR0, RR0, IR0, prev_epoch, policy_id])
C_next = poseidon::<6>([D3-STATE-v2, GR2, RR2, IR2, next_epoch, policy_id])
D_E    = poseidon::<5>([D3-BATCH-v1, 2, C0, C1, Cpad])
```

Instance order:

| index | value |
| --- | --- |
| 0 | `C_prev` |
| 1 | `prev_epoch` |
| 2 | `C_next` |
| 3 | `next_epoch` |
| 4 | `policy_id` |
| 5 | `transition_version` |
| 6 | `D_E` |
| 7 | `event_count = 2` |

D3-06-C proves `S0 -> S1 -> S2` for GG/GR/RR. It explicitly does not prove external S0 anchoring or freshness (`EXP-D3-06-C-SUMMARY.md:94-111`).

## 4. Field mapping used by the D3-07-A anchor profile

D1 has no native fields named `checkpoint_sequence`, `issued_at`, `expiry`, `witness_set_id`, `policy_id` field element or `transition_version`. The following mapping is therefore explicit and is **not** claimed as a D1 protocol feature:

| Anchor semantics | Encoding |
| --- | --- |
| checkpoint sequence | D1 `epoch` |
| `C_prev` | lowercase 64-hex `encode_field_i(C_prev)`, stored in signed `state_root` |
| policy + version | `d3-transition-v1|<64-hex policy_id>|<decimal transition_version>`, stored in signed `policy_version` |
| witness set ID | envelope routing label; must equal trusted config ID and signed `witness_set_root` must match that config |
| issued time | D1 signed `timestamp`, additionally checked by an explicit max-age/max-skew policy |
| local chain parent | D1 `previous_hash`; checked for higher sequences during verification and commit |
| transparency log | `NO_LOG`, `log_size = 0`; no inclusion or consistency claim |

These fields remain inside the D1 nine-field signed checkpoint. No unsigned host field is treated as trusted checkpoint content.

## 5. What the baseline cannot provide

- No globally latest checkpoint query.
- No witness persistent-lock verification from a single envelope.
- No RFC6962 inclusion/consistency in this profile.
- No proof that a fresh timestamp implies latest state.
- No protection for first contact before a durable local high-water mark exists.
- No detection of a quorum re-signing an old state unless local anti-rollback, chain continuity or an external latestness service exposes the conflict.
- No new Halo2 public instance and no circuit-side anchor proof.

## 6. Stop-condition decision

D1's signed `state_root` and `policy_version` fields are generic strings; the verifier does not require them to be the D1 history-prefix hash. Thus the D3-07-A profile can safely carry a canonical D3 `C_prev` and policy/version payload inside D1-authenticated fields.

No Phase 0 BLOCKED item is declared. However, the profile limitations in §5 are mandatory boundary statements for all later documents and reports.
