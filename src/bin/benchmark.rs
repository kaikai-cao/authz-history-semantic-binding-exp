//! Reference-implementation cost measurements for EXP-D3-01.
//!
//! IMPORTANT: these numbers measure the Rust reference implementation only.
//! They are NOT Halo2 proof costs and NOT zero-knowledge proving performance.
//!
//! R1-04 fixes: the first measurement is now the genuine first in-loop run and
//! is never overwritten by an extra re-run; all five raw samples are retained;
//! and the Poseidon-call counting boundary is identical for paths A and B.

use std::time::Instant;

use authz_history_semantic_binding_exp::encoding::Hash32;
use authz_history_semantic_binding_exp::event::{Event, RevokeEvent};
use authz_history_semantic_binding_exp::history::{build_linear_history, History};
use authz_history_semantic_binding_exp::policy::RevocationPolicy;
use authz_history_semantic_binding_exp::state::IncrementalEngine;
use authz_history_semantic_binding_exp::{policy_digest, StateTransitionStatement};

const DEPTH: usize = 12;
const SIZES: [usize; 4] = [16, 64, 256, 1024];
const RUNS: usize = 5;

#[derive(serde::Serialize)]
struct Metrics {
    schema: String,
    note: String,
    first_measurement_definition: String,
    hash_count_boundary: String,
    tree_depth: usize,
    runs_per_size: usize,
    sizes: Vec<SizeResult>,
}

#[derive(serde::Serialize)]
struct RunSample {
    run: usize,
    replay_ms: f64,
    incremental_ms: f64,
}

#[derive(serde::Serialize)]
struct SizeResult {
    n: usize,
    event_count: usize,
    revoked_events: usize,
    replay_first_ms: f64,
    replay_stable_mean_ms: f64,
    replay_stable_min_ms: f64,
    incremental_first_ms: f64,
    incremental_stable_mean_ms: f64,
    incremental_stable_min_ms: f64,
    /// All five in-loop samples, unmodified and in execution order.
    raw_runs: Vec<RunSample>,
    grant_tree_hashes_replay: u64,
    grant_tree_hashes_incremental: u64,
    revoke_tree_hashes_replay: u64,
    revoke_tree_hashes_incremental: u64,
    /// Incremental GR node hashes split into all-zero tree initialisation and
    /// path updates caused by leaf inserts/updates/moves/deletes.
    grant_node_init_hashes_incremental: u64,
    grant_node_path_hashes_incremental: u64,
    revoke_node_init_hashes_incremental: u64,
    revoke_node_path_hashes_incremental: u64,
    changed_leaves: u64,
    statement_size_bytes: usize,
    public_input_count: usize,
    state_size_grants: usize,
    state_size_revokes: usize,
    state_size_leaves: usize,
}

#[derive(Clone, Copy)]
struct OnceResult {
    replay_ms: f64,
    incremental_ms: f64,
    replay_gr_hashes: u64,
    incremental_gr_hashes: u64,
    replay_rr_hashes: u64,
    incremental_rr_hashes: u64,
    gr_init_nodes: u64,
    gr_path_nodes: u64,
    rr_init_nodes: u64,
    rr_path_nodes: u64,
    changed_leaves: u64,
    grants: usize,
    revokes: usize,
    leaves: usize,
}

fn mean(values: &[f64]) -> f64 {
    values.iter().sum::<f64>() / values.len() as f64
}

fn min(values: &[f64]) -> f64 {
    values.iter().copied().fold(f64::INFINITY, f64::min)
}

/// Build a history of `n` events: a linear delegation chain plus a few revokes.
///
/// `build_linear_history` is a linear chain in which ONLY `grant-0` is a root
/// grant; each later grant references its predecessor as parent. All grants in
/// that chain have issuer/subject "root-issuer", so "root-issuer" is a valid
/// revoker for every grant, not because every grant is a root grant.
fn build_mixed_history(n: usize) -> History {
    let mut hist = build_linear_history(n);
    let revoke_every = (n / 4).max(1);
    let mut epoch = n as u64 + 1;
    let revokers: Vec<(Hash32, Hash32)> = {
        let mut v = Vec::new();
        for i in (0..n).step_by(revoke_every) {
            v.push((
                Hash32::from_label(&format!("grant-{i}")),
                Hash32::from_label("root-issuer"),
            ));
        }
        v
    };
    for (id, revoker) in revokers {
        hist.push(Event::Revoke(RevokeEvent {
            grant_id: id,
            revoker,
            epoch,
        }));
        epoch += 1;
    }
    hist
}

fn run_once(hist: &History) -> OnceResult {
    // Path A: full replay from genesis, both trees built from scratch. The
    // ReplayOutcome counters already include initialisation node hashes.
    let t0 = Instant::now();
    let a = hist
        .replay_full(RevocationPolicy::DirectOnly, DEPTH)
        .unwrap();
    let replay_ms = t0.elapsed().as_secs_f64() * 1000.0;

    // Path B: incremental updates from genesis.
    let t1 = Instant::now();
    let mut engine = IncrementalEngine::new(RevocationPolicy::DirectOnly, DEPTH);
    let mut changed = 0u64;
    for e in &hist.events {
        changed += engine.apply(e).unwrap().changed_leaves;
    }
    let incremental_ms = t1.elapsed().as_secs_f64() * 1000.0;

    // Sanity check: both paths must produce identical roots under the canonical
    // slot rule, otherwise the measurement would be meaningless.
    assert_eq!(a.grant_root, engine.grant_tree.root_hash());
    assert_eq!(a.revoke_root, engine.revoke_tree.root_hash());

    OnceResult {
        replay_ms,
        incremental_ms,
        replay_gr_hashes: a.grant_hashes,
        incremental_gr_hashes: engine.grant_hashes(),
        replay_rr_hashes: a.revoke_hashes,
        incremental_rr_hashes: engine.revoke_hashes(),
        gr_init_nodes: engine.grant_tree.node_init_hashes,
        gr_path_nodes: engine.grant_tree.node_path_hashes,
        rr_init_nodes: engine.revoke_tree.node_init_hashes,
        rr_path_nodes: engine.revoke_tree.node_path_hashes,
        changed_leaves: changed,
        grants: a.state.grants.len(),
        revokes: a.state.revokes.len(),
        leaves: engine.grant_tree.len() + engine.revoke_tree.len(),
    }
}

fn main() {
    let mut results = Vec::new();

    for n in SIZES {
        let hist = build_mixed_history(n);
        let mut replay_stable = Vec::new();
        let mut incremental_stable = Vec::new();
        let mut raw_runs = Vec::new();
        let mut first: Option<OnceResult> = None;
        let mut counters: Option<OnceResult> = None;

        for run in 0..RUNS {
            let sample = run_once(&hist);
            raw_runs.push(RunSample {
                run: run + 1,
                replay_ms: sample.replay_ms,
                incremental_ms: sample.incremental_ms,
            });
            if run == 0 {
                // Genuine first in-process iteration; retained, never overwritten.
                first = Some(sample);
            } else {
                replay_stable.push(sample.replay_ms);
                incremental_stable.push(sample.incremental_ms);
            }
            eprintln!(
                "n={n} run={} replay={:.3}ms incremental={:.3}ms",
                run + 1,
                sample.replay_ms,
                sample.incremental_ms
            );
            counters = Some(sample);
        }
        let first = first.expect("at least one run");
        let counters = counters.expect("at least one run");

        let stmt = StateTransitionStatement {
            previous_grant_root: Hash32::from_label("dummy-prev-gr"),
            previous_revoke_root: Hash32::from_label("dummy-prev-rr"),
            next_grant_root: Hash32::from_label("dummy-next-gr"),
            next_revoke_root: Hash32::from_label("dummy-next-rr"),
            previous_epoch: 0,
            next_epoch: 1,
            event_batch_digest: hist.batch_digest(),
            event_count: hist.events.len() as u32,
            policy_digest: policy_digest(RevocationPolicy::DirectOnly),
        };

        results.push(SizeResult {
            n,
            event_count: hist.events.len(),
            revoked_events: hist
                .events
                .iter()
                .filter(|e| matches!(e, Event::Revoke(_)))
                .count(),
            replay_first_ms: first.replay_ms,
            replay_stable_mean_ms: mean(&replay_stable),
            replay_stable_min_ms: min(&replay_stable),
            incremental_first_ms: first.incremental_ms,
            incremental_stable_mean_ms: mean(&incremental_stable),
            incremental_stable_min_ms: min(&incremental_stable),
            raw_runs,
            grant_tree_hashes_replay: counters.replay_gr_hashes,
            grant_tree_hashes_incremental: counters.incremental_gr_hashes,
            revoke_tree_hashes_replay: counters.replay_rr_hashes,
            revoke_tree_hashes_incremental: counters.incremental_rr_hashes,
            grant_node_init_hashes_incremental: counters.gr_init_nodes,
            grant_node_path_hashes_incremental: counters.gr_path_nodes,
            revoke_node_init_hashes_incremental: counters.rr_init_nodes,
            revoke_node_path_hashes_incremental: counters.rr_path_nodes,
            changed_leaves: counters.changed_leaves,
            statement_size_bytes: stmt.statement_size_bytes(),
            public_input_count: stmt.public_input_count(),
            state_size_grants: counters.grants,
            state_size_revokes: counters.revokes,
            state_size_leaves: counters.leaves,
        });
    }

    let metrics = Metrics {
        schema: "D3-01-benchmark-v2".to_string(),
        note: "Reference Rust implementation only; not Halo2 or ZK proof performance.".to_string(),
        first_measurement_definition: "The first in-process iteration of the five-run loop; it is informational only and is NOT a strictly cold process start.".to_string(),
        hash_count_boundary: "Poseidon invocations only: grant_leaf/revoke_leaf leaf commitments plus node_hash calls (tree initialisation + incremental path updates). NOT circuit constraints and not generic cryptographic operations.".to_string(),
        tree_depth: DEPTH,
        runs_per_size: RUNS,
        sizes: results,
    };

    let json = serde_json::to_string_pretty(&metrics).unwrap();
    std::fs::write("results/performance.json", format!("{json}\n")).unwrap();
    println!("wrote results/performance.json");
}
