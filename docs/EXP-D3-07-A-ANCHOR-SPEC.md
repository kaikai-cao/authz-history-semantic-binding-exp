# EXP-D3-07-A — Anchor Envelope Specification

## 1. Scope

This document defines the host-side anchor envelope used to bind a D3-06-C proof to an externally signed checkpoint. It does not define a new consensus protocol and does not modify Halo2.

## 2. Canonical message

The signature payload is byte-identical to D1 `encode_checkpoint`:

```text
b"EXP-D1-E:" ||
enc_str("Checkpoint") ||
enc_str("chain_id")     || enc_str(cp.chain_id) ||
enc_str("epoch")        || enc_int(cp.epoch) ||
enc_str("previous_hash")|| enc_str(cp.previous_hash) ||
enc_str("state_root")   || enc_str(cp.state_root) ||
enc_str("log_root")     || enc_str(cp.log_root) ||
enc_str("policy_version")|| enc_str(cp.policy_version) ||
enc_str("witness_set_root")|| enc_str(cp.witness_set_root) ||
enc_str("log_size")     || enc_int(cp.log_size) ||
enc_str("timestamp")    || enc_int(cp.timestamp)
```

`enc_str(x) = u64_be(len(utf8(x))) || utf8(x)`, `enc_int(x) = i64_be(x)`.

Checkpoint digest: `sha256(encode_checkpoint(cp))`, encoded as lowercase 64-hex.

Any key-field modification changes this digest and invalidates the QC.

## 3. D3 field profile

| D1 field | Required value |
| --- | --- |
| `chain_id` | trusted config chain ID |
| `epoch` | anchor sequence, int64 |
| `previous_hash` | lowercase 64-hex parent checkpoint digest |
| `state_root` | lowercase 64-hex canonical big-endian Pallas field bytes of D3 `C_prev` |
| `log_root` | `"NO_LOG"` in this profile |
| `policy_version` | `d3-transition-v1|<policy_hex>|<version_decimal>` |
| `witness_set_root` | lowercase 64-hex SHA-256 over D1-canonical sorted trusted public keys |
| `log_size` | `0` in this profile |
| `timestamp` | signed issued-at time; time policy is external to D1 |

`policy_hex` is `encode_field_i(policy_id())` in lowercase hex. `version_decimal` is `transition_version()`. The parser requires the exact prefix, exactly one final separator, a canonical Pallas field hex, and a `u32` version.

## 4. Witness QC rules

Trusted config supplies:

- `set_id`;
- `chain_id`;
- threshold (3 in the D1 profile);
- witness IDs and Ed25519 public keys.

The verifier requires:

1. envelope `witness_set_id == config.set_id`;
2. signed `witness_set_root == witness_set_root(config.public_keys)`;
3. `qc.checkpoint_hash == checkpoint_hash(cp)`;
4. `qc.epoch == cp.epoch` and `qc.previous_hash == cp.previous_hash`;
5. no repeated witness ID;
6. every witness ID exists in trusted config;
7. every signature is valid Ed25519 over `encode_checkpoint(cp)`;
8. valid signature count >= threshold.

The envelope's own public keys are never trusted. A self-appointed witness set cannot satisfy the signed root check.

D1 de-duplicates exact repeated signatures; this profile rejects any repeated witness ID. That is stricter than D1 and does not weaken D1 semantics.

## 5. Time policy

D1 signs `timestamp` but defines no expiry rule. This profile adds:

```text
timestamp <= now + max_clock_skew_secs
now       <= timestamp + max_age_secs + max_clock_skew_secs
```

Time validity means only that the checkpoint satisfies this verification policy. It never means globally latest. A QC-valid checkpoint can be old, and a fresh timestamp does not prove that no newer signed checkpoint exists.

## 6. Local anti-rollback state

The local durable state stores:

```text
highest_sequence: i64
highest_digest: String
```

Rules:

- offered sequence < highest: reject;
- same sequence + different digest: reject;
- same sequence + same digest: idempotent success, no state write;
- higher sequence: require `previous_hash == highest_digest`, then accept only after every other check succeeds;
- commit is serialized by a process mutex and written with temp-file + rename;
- local file persistence covers process restarts, not distributed consistency.

First contact must start from a trusted genesis digest. Before that, the verifier cannot identify historical rollback.

## 7. Ordered combined verification

`verify_anchored_transition` enforces:

1. checkpoint digest / QC / witness set / time / anti-rollback;
2. `C_prev`, `prev_epoch`, `policy_id`, `transition_version`, `event_count` binding to the eight D3 instances;
3. Halo2 proof verification;
4. only then commit local anti-rollback state.

Failure at any step prevents step 4. `C_next` is not treated as a newly certified checkpoint.

## 8. Explicit non-claims

- no Halo2 circuit or public-instance change;
- no witness persistent-lock proof;
- no RFC6962 inclusion/consistency in this profile;
- no external latest-checkpoint query;
- no global freshness from time window or local sequence;
- no production key management or rotation protocol.
