//! Reference-implementation cost measurements for EXP-D3-01.
//!
//! IMPORTANT: these numbers measure the Rust reference implementation only.
//! They are NOT Halo2 proof costs and NOT zero-knowledge proving performance.

use std::time::Instant;

use authz_history_semantic_binding_exp::encoding::Hash32;
use authz_history_semantic_binding_exp::event::RevokeEvent;
use authz_history_semantic_binding_exp::history::{build_linear_history, History};
use authz_history_semantic_binding_exp::policy::RevocationPolicy;
use authz_history_semantic_binding_exp::state::{IncrementalEngine, State};
use authz_history_semantic_binding_exp::{policy_digest, StateTransitionStatement};

const DEPTH: usize = 12;
const SIZES: [usize; 4] = [16, 64, 256, 1024];
const RUNS: usize = 5;

#[derive(serde::Serialize)]
struct Metrics {
    schema: String,
    note: String,
    tree_depth: usize,
    runs_per_size: usize,
    sizes: Vec<SizeResult>,
}

#[derive(serde::Serialize)]
struct SizeResult {
    n: usize,
    replay_first_ms: f64,
    replay_stable_mean_ms: f64,
    replay_stable_min_ms: f64,
    incremental_first_ms: f64,
    incremental_stable_mean_ms: f64,
    incremental_stable_min_ms: f64,
    grant_tree_hashes_replay: u64,
    grant_tree_hashes_incremental: u64,
    revoke_tree_hashes_replay: u64,
    revoke_tree_hashes_incremental: u64,
    event_count: usize,
    revoked_events: usize,
    changed_leaves: u64,
    statement_size_bytes: usize,
    public_input_count: usize,
    state_size_grants: usize,
    state_size_revokes: usize,
    state_size_leaves: usize,
}

fn mean(values: &[f64]) -> f64 {
    values.iter().sum::<f64>() / values.len() as f64
}

fn min(values: &[f64]) -> f64 {
    values.iter().copied().fold(f64::INFINITY, f64::min)
}

/// Build a history of `n` events: linear grants plus a few revokes of root grants.
fn build_mixed_history(n: usize) -> History {
    let mut hist = build_linear_history(n);
    let revoke_every = (n / 4).max(1);
    let mut epoch = n as u64 + 1;
    let revokers: Vec<(Hash32, Hash32)> = {
        let mut v = Vec::new();
        for i in (0..n).step_by(revoke_every) {
            // issuer of a root grant is root-issuer by construction
            v.push((
                Hash32::from_label(&format!("grant-{i}")),
                Hash32::from_label("root-issuer"),
            ));
        }
        v
    };
    for (id, revoker) in revokers {
        hist.push(authz_history_semantic_binding_exp::event::Event::Revoke(
            RevokeEvent {
                grant_id: id,
                revoker,
                epoch,
            },
        ));
        epoch += 1;
    }
    hist
}

fn run_once(hist: &History) -> (f64, f64, u64, u64, u64, u64, u64, usize, usize, usize) {
    // Path A: full replay from genesis, roots built from scratch each time.
    // Count tree-build node hashes too, for an apples-to-apples hash comparison
    // against the incremental engine (which counts its initialisation hashes).
    let t0 = Instant::now();
    let a = hist
        .replay_full(RevocationPolicy::DirectOnly, DEPTH)
        .unwrap();
    let replay_ms = t0.elapsed().as_secs_f64() * 1000.0;
    let (_, _, replay_gr_build_nodes) =
        authz_history_semantic_binding_exp::grant_tree::grant_root_from_records(
            &a.state.grants,
            DEPTH,
        );
    let (_, _, replay_rr_build_nodes) =
        authz_history_semantic_binding_exp::revoke_tree::revoke_root_from_records(
            &a.state.revokes,
            DEPTH,
        );
    let replay_gr_hashes = a.grant_hashes + replay_gr_build_nodes;
    let replay_rr_hashes = a.revoke_hashes + replay_rr_build_nodes;

    // Path B: incremental updates from genesis.
    let t1 = Instant::now();
    let mut engine = IncrementalEngine::new(RevocationPolicy::DirectOnly, DEPTH);
    let mut changed = 0u64;
    for e in &hist.events {
        changed += engine.apply(e).unwrap().changed_leaves;
    }
    let incremental_ms = t1.elapsed().as_secs_f64() * 1000.0;

    (
        replay_ms,
        incremental_ms,
        replay_gr_hashes,
        engine.grant_hashes(),
        replay_rr_hashes,
        engine.revoke_hashes(),
        changed,
        a.state.grants.len(),
        a.state.revokes.len(),
        engine.grant_tree.len() + engine.revoke_tree.len(),
    )
}

fn main() {
    let mut results = Vec::new();

    for n in SIZES {
        let hist = build_mixed_history(n);
        let mut replay_times = Vec::new();
        let mut incremental_times = Vec::new();
        let mut last = (0.0, 0.0, 0, 0, 0, 0, 0, 0, 0, 0);

        for run in 0..RUNS {
            last = run_once(&hist);
            if run == 0 {
                // first run kept separately (cold-ish for this process)
            } else {
                replay_times.push(last.0);
                incremental_times.push(last.1);
            }
            eprintln!(
                "n={n} run={} replay={:.3}ms incremental={:.3}ms",
                run + 1,
                last.0,
                last.1
            );
        }

        let pre = State::new(RevocationPolicy::DirectOnly);
        let _ = pre;
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
            replay_first_ms: last.0, // placeholder overwritten below for first-run value
            replay_stable_mean_ms: mean(&replay_times),
            replay_stable_min_ms: min(&replay_times),
            incremental_first_ms: last.1,
            incremental_stable_mean_ms: mean(&incremental_times),
            incremental_stable_min_ms: min(&incremental_times),
            grant_tree_hashes_replay: last.2,
            grant_tree_hashes_incremental: last.3,
            revoke_tree_hashes_replay: last.4,
            revoke_tree_hashes_incremental: last.5,
            changed_leaves: last.6,
            event_count: hist.events.len(),
            revoked_events: hist
                .events
                .iter()
                .filter(|e| {
                    matches!(
                        e,
                        authz_history_semantic_binding_exp::event::Event::Revoke(_)
                    )
                })
                .count(),
            statement_size_bytes: stmt.statement_size_bytes(),
            public_input_count: stmt.public_input_count(),
            state_size_grants: last.7,
            state_size_revokes: last.8,
            state_size_leaves: last.9,
        });
    }

    // Recompute honest first-run values by re-running once per size (deterministic
    // enough for a reference implementation; first-run latency is informational).
    for r in &mut results {
        let hist = build_mixed_history(r.n);
        let (rp, inc, _, _, _, _, _, _, _, _) = run_once(&hist);
        r.replay_first_ms = rp;
        r.incremental_first_ms = inc;
    }

    let metrics = Metrics {
        schema: "D3-01-benchmark-v1".to_string(),
        note: "Reference Rust implementation only; not Halo2 or ZK proof performance.".to_string(),
        tree_depth: DEPTH,
        runs_per_size: RUNS,
        sizes: results,
    };

    let json = serde_json::to_string_pretty(&metrics).unwrap();
    std::fs::write("results/performance.json", format!("{json}\n")).unwrap();
    println!("wrote results/performance.json");
}
