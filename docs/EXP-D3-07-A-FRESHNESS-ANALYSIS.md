# EXP-D3-07-A — Freshness Trust Boundary

## 1. Four guarantees that must not be conflated

| Term | What this implementation actually checks |
| --- | --- |
| `QC valid` | D1-canonical checkpoint digest matches; threshold distinct trusted Ed25519 signatures verify; witness-set root matches trusted config. |
| `timestamp fresh` | Signed `timestamp` satisfies an explicit max-age/max-skew policy. |
| `sequence monotonic` | Offered sequence is not below the local durable high-water mark; same-sequence equivocation is rejected after local observation. |
| `globally latest` | Not implemented. Requires an external trusted latest-checkpoint service or an equivalent Witness/liveness assumption. |

A successful `verify_anchored_transition` means the first three checks passed where applicable and the D3-06-C proof verified. It never means the fourth.

## 2. Answers to the eight required questions

### 2.1 Can a QC-valid but old checkpoint be accepted?

Yes, if it is still inside the configured time window and does not violate local anti-rollback. QC validity authenticates who signed what; it does not establish when the verifier learned it or whether a newer checkpoint exists.

### 2.2 Does a fresh timestamp imply latest state?

No. `timestamp` is a signed field in D1's checkpoint. An adversary with a valid old signature cannot change it, but a signer can issue a checkpoint with a current time over an old state unless external liveness checks constrain that behavior. Time validity is a policy window, not latestness.

### 2.3 Can first-contact local anti-rollback identify historical rollback?

No. Local anti-rollback only knows what it has already persisted. On first contact, any internally valid checkpoint may become the initial high-water mark unless the verifier is bootstrapped from a trusted checkpoint or chain.

### 2.4 What does the Witness persistent lock constrain?

D1 `Witness.signed` maps `parent_checkpoint_hash -> child_checkpoint_hash`; a witness refuses to sign a second child for the same parent. It constrains a witness that correctly persists its lock table. D1 E7 shows that losing locks for a quorum permits conflicting QCs. The D3-07-A verifier cannot observe those locks from a single envelope.

### 2.5 What happens under Witness set rotation?

This stage has no rotation protocol. A checkpoint is accepted only when its signed `witness_set_root` matches the selected trusted config. An old-set checkpoint is rejected under a new config; it remains valid only while the old set is still trusted. Rotation of keys/quorum needs its own protocol.

### 2.6 How does a verifier detect malicious replay of an old valid checkpoint?

If the verifier already persisted a higher sequence or a conflicting digest, replay is rejected by anti-rollback. If this is first contact, or the attacker supplies an older checkpoint before any newer one is observed, the verifier cannot detect it locally. An external latest-checkpoint query or gossip/transparency mechanism is required.

### 2.7 Can the current protocol detect a quorum re-signing an old state?

Only conditionally:

- if the re-signed checkpoint has a lower sequence than the local high-water mark, it is rejected;
- if it has the same sequence but a different digest, it is rejected;
- if it is presented on first contact, it cannot be distinguished;
- if a quorum assigns a higher sequence to old content, this verifier sees a well-formed signed checkpoint and cannot prove semantic progress;
- D1's persistent lock would block conflicting children under the same parent only while witness locks are correctly preserved.

Thus the current protocol does not provide unconditional detection of quorum equivocation.

### 2.8 What can be promised without a trusted latest-checkpoint query?

At most:

1. the checkpoint was signed by a threshold of the configured Witness set under D1 canonical encoding;
2. the selected Witness set matches the signed witness-set root;
3. the signed state root binds to the D3-06-C `C_prev`;
4. epoch/policy/version and event count are bound to the proof instances;
5. the D3-06-C Halo2 proof verifies for the declared two-event transition;
6. the checkpoint satisfies a local time policy and has not regressed relative to locally persisted state.

It cannot promise that this checkpoint is the current latest authorization state.

## 3. Attack trajectories

### 3.1 Replay of an old valid checkpoint

- **Attacker ability:** obtains a previously valid checkpoint and QC.
- **Affected verification state:** checkpoint sequence, timestamp, `C_prev`.
- **Current implementation:** rejects if the local high-water sequence is higher, or if the same sequence has a different digest. It may accept if the checkpoint falls inside the time window and no newer state was observed.
- **External assumption needed:** trusted latest-checkpoint query, chain monitoring, or witness liveness.

### 3.2 First-contact stale checkpoint

- **Attacker ability:** gives a new verifier an old but validly signed checkpoint before any other checkpoint is observed.
- **Affected verification state:** initial local high-water mark.
- **Current implementation:** cannot detect the staleness. It accepts if canonical encoding, QC, time and D3 binding pass.
- **External assumption needed:** trusted genesis/bootstrap checkpoint or external latestness attestation. D1 E4 explicitly records this boundary.

### 3.3 Same-sequence equivocation

- **Attacker ability:** obtains or creates two different checkpoint digests for the same signed sequence, for example by broken witness locks.
- **Affected verification state:** local sequence/digest binding.
- **Current implementation:** once one digest is persisted, a different digest at the same sequence is rejected. Before first observation, neither is distinguishable; after quorum lock loss, external witnesses may still have signed conflicting children.
- **External assumption needed:** persistent witness locks, gossip/evidence exchange, and a policy for detecting conflicting QCs.

## 4. Research conclusion

The implemented system can prove:

> Given an externally anchored, locally non-regressing authorization state S0, a D3-06-C proof shows that two ordered events are executed on the single chain S0 → S1 → S2.

It cannot prove:

> S0 is the current latest trusted authorization state.

The second statement remains conditional on external Witness/liveness/bootstrap assumptions and is not a Halo2 result.
