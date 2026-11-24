# EXP-D3-07-A — Security Tests

## 1. Test file

- `tests/d3_07_a_anchor.rs`
- Test-only Ed25519 keys are derived from `b"exp-d3-07-a-test-only"` via the D1-style deterministic derivation. No production key material is used.
- All A01–A36 cases construct full `AnchorEnvelope` values and pass them into the verifier. Negative cases are not rejected by a constructor before entering the tested path.

## 2. QC tests

| Case | Tampering | Expected error | Result |
| --- | --- | --- | --- |
| A01 | valid 3-of-4 QC | accept | pass |
| A02 | 2 signatures only | `InsufficientSignatures { got: 2, need: 3 }` | pass |
| A03 | known witness ID with signature from another key | `InvalidSignature("w0")` | pass |
| A04 | repeated witness ID | `DuplicateWitness("w0")` | pass |
| A05 | unknown witness ID | `UnknownWitness("ghost")` | pass |
| A06 | wrong envelope witness-set ID | `WitnessSetIdMismatch` | pass |
| A07 | signed `state_root` modified after QC creation | `CheckpointDigestMismatch` | pass |

A07 confirms that the D1 canonical checkpoint digest covers the D3 `C_prev` carrier. The witness-set root check also prevents a self-supplied key set from being trusted.

## 3. D3 binding tests

| Case | Tampering, with valid re-signed QC | Expected error | Result |
| --- | --- | --- | --- |
| A08 | correct C_prev / epoch / policy / version | accept binding | pass |
| A09 | wrong `state_root` | `StateCommitmentMismatch` | pass |
| A10 | wrong `epoch` | `PrevEpochMismatch` | pass |
| A11 | wrong policy field | `PolicyMismatch` | pass |
| A12 | wrong transition version | `TransitionVersionMismatch` | pass |

A09–A12 are re-signed so the QC path succeeds; the rejection happens in `bind_to_instances`, not in early QC validation.

## 4. Freshness and anti-rollback tests

| Case | Condition | Expected error / behavior | Result |
| --- | --- | --- | --- |
| A13 | timestamp within policy | accept | pass |
| A14 | expired timestamp, validly signed | `Expired` | pass |
| A15 | future timestamp beyond skew | `TooFresh` | pass |
| A16 | lower sequence | `StaleSequence { known: 10, offered: 9 }` | pass |
| A17 | same sequence, different digest | `SameSequenceEquivocation { sequence: 10 }` | pass |
| A18 | same sequence, same digest | first `Advanced`, second `AlreadyCommitted` | pass |
| A19 | higher sequence with correct parent digest | `Advanced` | pass |
| A20 | fresh store instance on same file | persisted sequence and digest observed | pass |
| A21 | eight concurrent commits | high-water mark remains at the accepted sequence/digest | pass |

The time checks are policy checks over a signed D1 `timestamp`; they do not claim global latestness. Local state uses a process mutex plus temp-file/rename persistence.

## 5. Combined verification tests

| Case | Condition | Expected behavior | Result |
| --- | --- | --- | --- |
| A22 | valid anchor + valid D3-C proof | accept; state advances | pass |
| A23 | invalid anchor + valid proof | reject before proof verification | pass |
| A24 | valid anchor + corrupted proof bytes | `Halo2ProofInvalid`; state unchanged | pass |
| A25 | C_prev mismatch | `StateCommitmentMismatch`; state unchanged | pass |
| A26 | epoch mismatch | `PrevEpochMismatch`; state unchanged | pass |
| A27 | policy mismatch | `PolicyMismatch`; state unchanged | pass |
| A28 | proof failure due to tampered instance | reject; state remains genesis | pass |

A22–A28 share one keygen and one honest GG proof. A24 and A28 jointly confirm that proof failure never advances the local checkpoint state.

## 6. Trusted config and profile fail-closed tests (R1)

All eight cases below enter `verify_anchor` with a complete envelope. They are not rejected by a test helper; A29/A30 additionally clear the QC signatures to show that a bad threshold cannot admit a zero-signature QC. A35/A36 use a re-signed envelope so that only the profile field differs from the valid control; because profile checks run before QC verification, these tests do not claim that the QC path was executed.

| Case | Condition | Expected error | Result |
| --- | --- | --- | --- |
| A29 | config `threshold = 0`, empty QC | `InvalidThreshold { got: 0, expected: 3 }` | pass |
| A30 | config `threshold = 1` | `InvalidThreshold { got: 1, expected: 3 }` | pass |
| A31 | three witnesses instead of four | `InvalidWitnessCount { got: 3, expected: 4 }` | pass |
| A32 | repeated `witness_id` in config | `ConfigDuplicateWitnessId("w0")` | pass |
| A33 | repeated public key in config | `ConfigDuplicatePublicKey("w1")` | pass |
| A34 | 31-byte hex key and non-decompressible Ed25519 key | `InvalidConfigPublicKey("w0")` / `InvalidConfigPublicKey("w1")` | pass |
| A35 | `log_root = "LOG-TREE"`, validly re-signed | `UnsupportedLogRoot("LOG-TREE")` | pass |
| A36 | `log_size = 1`, validly re-signed | `NonZeroLogSize(1)` | pass |

A positive control with the untouched 3-of-4 config and `NO_LOG`/`0` profile is verified in the same test, so the rejections are attributable to the changed field. Config validation precedes QC parsing and signature counting.

## 7. Boundary of test evidence

These tests show that the implemented host verifier follows its declared checks. They do not prove:

- that witness persistent locks were honored by external witnesses;
- that a timestamp window implies latest state;
- that first contact can detect historical rollback;
- that a quorum cannot re-sign an old state under broken key/lock assumptions;
- that a caller-supplied trusted config is authentic; config provisioning is external to this verifier;
- Halo2 soundness beyond the existing D3-06-C test suite.
