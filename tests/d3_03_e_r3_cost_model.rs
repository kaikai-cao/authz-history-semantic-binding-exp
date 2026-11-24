//! EXP-D3-03-E-R3 Phase 1 — Poseidon permutation counting model.
//!
//! Counts Poseidon permutations by category for the frozen E-R1 circuit.
//! P128Pow5T3 has rate=2, so `hash_words(N words)` = ceil(N/2) permutations.
//! Event loop count = 2 (`MAX_ACTIVE_EVENTS`), tree capacity = 16, depth = 4.
//! These are structural counts derived from the circuit source, NOT measured
//! proving time and NOT a Halo2 constraint count.

fn perms(words: usize) -> usize {
    (words + 1) / 2 // ceil(N/2) for rate-2 Poseidon
}

#[test]
fn e_r3_poseidon_attribution() {
    const EVENTS: usize = 2;
    const SLOTS: usize = 16;
    const DEPTH: usize = 4;

    // ---- E-R1 full-scan additions (relative to E) ----
    // GR scan: 16 leaf preimages per event, each 9 words.
    let gr_scan_leaf = EVENTS * SLOTS * perms(9);
    // RR scan: 16 revoke leaves per event, each 4 words.
    let rr_scan_leaf = EVENTS * SLOTS * perms(4);
    // Merkle root rebuild per tree: sum_{l=0}^{DEPTH-1} 2^(DEPTH-1-l) internal
    // nodes = 8+4+2+1 = 15 nodes, each 3 words.  Two trees (GR+RR) per event.
    let nodes_per_tree = (1usize << DEPTH) - 1; // 15
    let scan_root_rebuild = EVENTS * 2 * nodes_per_tree * perms(3);
    let total_scan = gr_scan_leaf + rr_scan_leaf + scan_root_rebuild;

    // ---- E baseline Poseidon (present before R1) ----
    // 6 Merkle openings per event (parent/child_old/child_new/target/rr_old/rr_new),
    // each DEPTH=4 node hashes of 3 words.
    let openings = EVENTS * 6 * DEPTH * perms(3);
    // Business leaf hashes: parent_leaf(9), child_leaf(9), target_leaf(9),
    // revoke_leaf(4) per event.
    let business_leaf = EVENTS * (perms(9) * 3 + perms(4));
    // Event commitments: c_grant(9), c_revoke(5) per event.
    let event_commit = EVENTS * (perms(9) + perms(5));
    // Frozen batch commitment: C_prev, C_next, D_E (each 9 words).
    let frozen_batch = 3 * perms(9);
    let total_baseline = openings + business_leaf + event_commit + frozen_batch;

    println!(
        "R3_P struct: events={} slots={} depth={}",
        EVENTS, SLOTS, DEPTH
    );
    println!("R3_P gr_scan_leaf_perms={}", gr_scan_leaf);
    println!("R3_P rr_scan_leaf_perms={}", rr_scan_leaf);
    println!("R3_P scan_root_rebuild_perms={}", scan_root_rebuild);
    println!("R3_P total_scan_perms={}", total_scan);
    println!("R3_P openings_perms={}", openings);
    println!("R3_P business_leaf_perms={}", business_leaf);
    println!("R3_P event_commit_perms={}", event_commit);
    println!("R3_P frozen_batch_perms={}", frozen_batch);
    println!("R3_P total_baseline_perms={}", total_baseline);
    println!("R3_P total_all_perms={}", total_scan + total_baseline);
    println!(
        "R3_P scan_share_pct={:.1}",
        100.0 * total_scan as f64 / (total_scan + total_baseline) as f64
    );

    // Sanity: structural constants match frozen baseline.
    assert_eq!(nodes_per_tree, 15);
    assert_eq!(perms(9), 5);
    assert_eq!(perms(3), 2);
}
