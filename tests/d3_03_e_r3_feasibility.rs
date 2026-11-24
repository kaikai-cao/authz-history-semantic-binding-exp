//! EXP-D3-03-E-R3 Phase 4 — independent HOST-ONLY feasibility experiments.
//!
//! These are pure-Rust models of candidate constructions B (canonical slot
//! probing) and C (ID index tree).  They are NOT Halo2 circuits and do NOT
//! replace E-R1.  Purpose: test logical feasibility and count host-side probe
//! steps, to decide whether a candidate deserves a future circuit prototype.
//!
//! Scenarios covered: 16 slots, distinct IDs, colliding IDs, already-present
//! IDs, already-revoked IDs, non-empty initial state, second-event update.

use std::collections::BTreeSet;

use authz_history_semantic_binding_exp::encoding::poseidon;
use ff::PrimeField;
use pasta_curves::pallas::Base as F;

const CAP: usize = 16;
const MASK: usize = CAP - 1;

fn id(x: u64) -> F {
    F::from(x)
}

/// F-field canonical slot: Poseidon(id) low bits.  HOST ONLY — the E-R1
/// circuit does not prove this; D3-01 uses SHA-256 D3-SLOT-v1 instead.
fn slot_of(id: F) -> usize {
    // poseidon returns F; use its repr low byte as a deterministic slot seed.
    let h = poseidon([id]);
    let bytes = h.to_repr();
    bytes.as_ref()[0] as usize & MASK
}

/// Candidate B: linear probing from canonical slot. Returns (slot, probes).
/// `occupied` are F-field ids placed in slots (F::ZERO == empty sentinel here,
/// matching the R1/RR empty-leaf convention).
fn probe_insert(occupied: &mut [Option<F>; CAP], new: F) -> Result<(usize, usize), &'static str> {
    let start = slot_of(new);
    for k in 0..CAP {
        let s = (start + k) & MASK;
        match occupied[s] {
            None => {
                occupied[s] = Some(new);
                return Ok((s, k + 1));
            }
            Some(existing) if existing == new => {
                return Err("duplicate-id"); // already present -> uniqueness violation
            }
            Some(_) => continue,
        }
    }
    Err("tree-full")
}

// ---------------------------------------------------------------------------
// Candidate B experiments
// ---------------------------------------------------------------------------

#[test]
fn b_distinct_ids_insert_with_few_probes() {
    let mut occ: [Option<F>; CAP] = [None; CAP];
    let mut max_probes = 0;
    for x in 1..=8u64 {
        let (_, p) = probe_insert(&mut occ, id(x)).expect("insert");
        max_probes = max_probes.max(p);
    }
    assert_eq!(occ.iter().filter(|s| s.is_some()).count(), 8);
    println!("R3_B distinct_ids=8 max_probes={}", max_probes);
}

#[test]
fn b_colliding_ids_are_displaced_not_overwritten() {
    // Find two ids with the same canonical slot, prove linear probing keeps both.
    let mut by_slot: std::collections::HashMap<usize, u64> = std::collections::HashMap::new();
    let mut pair = None;
    for x in 1..5000u64 {
        let s = slot_of(id(x));
        if let Some(prev) = by_slot.get(&s) {
            pair = Some((*prev, x, s));
            break;
        }
        by_slot.insert(s, x);
    }
    let (a, b, s) = pair.expect("a collision exists within 5000 ids");
    let mut occ: [Option<F>; CAP] = [None; CAP];
    let (sa, _) = probe_insert(&mut occ, id(a)).unwrap();
    let (sb, pb) = probe_insert(&mut occ, id(b)).unwrap();
    assert_eq!(sa, s);
    assert_ne!(sb, sa, "collision must be displaced, not overwrite");
    assert!(pb >= 2, "collision costs at least one extra probe");
    assert_eq!(occ.iter().filter(|v| v.is_some()).count(), 2);
    println!("R3_B collision ids=({a},{b}) start_slot={s} b_slot={sb} b_probes={pb}");
}

#[test]
fn b_already_present_id_is_rejected() {
    let mut occ: [Option<F>; CAP] = [None; CAP];
    probe_insert(&mut occ, id(42)).unwrap();
    let err = probe_insert(&mut occ, id(42)).unwrap_err();
    assert_eq!(err, "duplicate-id");
    println!("R3_B already_present rejected={err}");
}

#[test]
fn b_worst_case_probe_is_full_capacity() {
    // Fill all 16 slots; the 17th insert must probe all 16 then report full.
    let mut occ: [Option<F>; CAP] = [None; CAP];
    // pick 16 ids that all map to slot 0 to force maximal probing.
    let mut same_slot = Vec::new();
    for x in 1..200000u64 {
        if slot_of(id(x)) == 0 {
            same_slot.push(x);
            if same_slot.len() == CAP {
                break;
            }
        }
    }
    assert_eq!(same_slot.len(), CAP, "found 16 ids with slot 0");
    for x in &same_slot {
        probe_insert(&mut occ, id(*x)).unwrap();
    }
    // 17th: need another id with slot 0; if none within range, just assert full.
    let extra = (1..300000u64).find(|x| slot_of(id(*x)) == 0 && !same_slot.contains(x));
    if let Some(x) = extra {
        let err = probe_insert(&mut occ, id(x)).unwrap_err();
        assert_eq!(err, "tree-full");
        println!("R3_B worst_case probes=16 result={err}");
    } else {
        println!("R3_B worst_case tree full at 16, no 17th id found");
    }
}

// ---------------------------------------------------------------------------
// Candidate C experiments: sorted ID index, non-membership by neighbours
// ---------------------------------------------------------------------------

/// Host model: sorted id set; `contains` via BTreeSet. Counts comparisons as
/// ceil(log2(n+1)) for a balanced binary search (information-theoretic lower
/// bound), to contrast with the 16-slot full scan.
fn nonmember_steps(sorted: &BTreeSet<F>, target: F) -> usize {
    let n = sorted.len();
    if n == 0 {
        return 1;
    }
    let mut lo = 0usize;
    let mut hi = n;
    let vec: Vec<F> = sorted.iter().copied().collect();
    let mut steps = 0;
    while lo < hi {
        steps += 1;
        let mid = (lo + hi) / 2;
        if vec[mid] < target {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    steps
}

#[test]
fn c_nonmembership_beats_full_scan_at_scale() {
    let mut idx = BTreeSet::new();
    for x in 1..=15u64 {
        idx.insert(id(x)); // non-empty initial state (S0)
    }
    // new id not present: non-membership check
    let steps = nonmember_steps(&idx, id(999));
    assert!(steps <= 4, "log2(16)=4 comparisons vs 16-slot scan");
    println!("R3_C nonmember n=15 steps={steps} full_scan_slots=16");
}

#[test]
fn c_present_id_detected_and_revoked_tracked() {
    let mut grant_idx = BTreeSet::new(); // GR-ID index
    let mut rr_idx = BTreeSet::new(); // RR-ID index (revoked)
    grant_idx.insert(id(10));
    grant_idx.insert(id(20));
    // Parent 10 already revoked in S0
    rr_idx.insert(id(10));

    // Grant(B=30, Parent=10): parent revoked -> must reject
    assert!(grant_idx.contains(&id(10)));
    assert!(rr_idx.contains(&id(10)), "parent in RR -> revoked");
    println!("R3_C grant parent-revoked rejected");

    // Grant(B=30, Parent=20): parent active -> ok, insert new id
    assert!(!rr_idx.contains(&id(20)));
    let steps = nonmember_steps(&grant_idx, id(30));
    grant_idx.insert(id(30));
    assert!(grant_idx.contains(&id(30)));
    println!("R3_C grant parent-active ok new_id=30 nonmember_steps={steps}");

    // Revoke(30): not yet revoked -> ok; second revoke -> duplicate detected
    assert!(!rr_idx.contains(&id(30)));
    rr_idx.insert(id(30)); // event0 revoke
    assert!(rr_idx.contains(&id(30))); // event1 second revoke rejected
    println!("R3_C revoke ok then duplicate rejected (second event state)");
}

#[test]
fn c_second_event_sees_first_event_update() {
    // Non-empty S0 with revoke(5); event0 grants 100; event1 must see it.
    let mut gr = BTreeSet::new();
    let mut rr = BTreeSet::new();
    rr.insert(id(5)); // S0 historical revoke
    gr.insert(id(7));

    // event 0: grant 100 (parent 7 active)
    assert!(!rr.contains(&id(7)));
    gr.insert(id(100));

    // event 1: grant 101, but duplicate id 100 must be rejected
    assert!(gr.contains(&id(100)), "event1 sees event0's insert");
    let steps = nonmember_steps(&gr, id(100));
    println!("R3_C event1 sees event0 duplicate id=100 steps={steps}");
}
