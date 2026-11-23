//! Generate deterministic fixed vectors for EXP-D3-01 (event encoding, roots,
//! batch digest, statement encoding). All values are produced by this reference
//! implementation and re-verified by the test suite.

use serde::Serialize;

use authz_history_semantic_binding_exp::encoding::Hash32;
use authz_history_semantic_binding_exp::event::{Event, GrantEvent, RevokeEvent};
use authz_history_semantic_binding_exp::history::History;
use authz_history_semantic_binding_exp::policy::RevocationPolicy;
use authz_history_semantic_binding_exp::{policy_digest, StateTransitionStatement};

const DEPTH: usize = 12;

#[derive(Serialize)]
struct Vectors {
    schema: String,
    note: String,
    tree_depth: usize,
    event_vectors: Vec<EventVector>,
    histories: Vec<HistoryVector>,
}

#[derive(Serialize)]
struct EventVector {
    id: &'static str,
    encoding_hex: String,
    digest_hex: String,
}

#[derive(Serialize)]
struct HistoryVector {
    name: &'static str,
    policy: &'static str,
    event_count: usize,
    batch_digest_hex: String,
    grant_root_hex: String,
    revoke_root_hex: String,
    state_summary_hex: String,
    statement_digest_hex: String,
    statement_size_bytes: usize,
}

fn ev_vec(id: &'static str, event: &Event) -> EventVector {
    EventVector {
        id,
        encoding_hex: hex::encode(event.encode()),
        digest_hex: event.digest().to_hex(),
    }
}

fn history_vec(name: &'static str, hist: &History, policy: RevocationPolicy) -> HistoryVector {
    let out = hist.replay_full(policy, DEPTH).unwrap();
    let stmt = StateTransitionStatement {
        previous_grant_root: Hash32::from_label("genesis-gr"),
        previous_revoke_root: Hash32::from_label("genesis-rr"),
        next_grant_root: out.grant_root,
        next_revoke_root: out.revoke_root,
        previous_epoch: 0,
        next_epoch: out.state.last_epoch,
        event_batch_digest: hist.batch_digest(),
        event_count: hist.events.len() as u32,
        policy_digest: policy_digest(policy),
    };
    HistoryVector {
        name,
        policy: policy.code(),
        event_count: hist.events.len(),
        batch_digest_hex: hist.batch_digest().to_hex(),
        grant_root_hex: out.grant_root.to_hex(),
        revoke_root_hex: out.revoke_root.to_hex(),
        state_summary_hex: out.state.summary().to_hex(),
        statement_digest_hex: stmt.digest().to_hex(),
        statement_size_bytes: stmt.statement_size_bytes(),
    }
}

fn main() {
    let g0 = Event::Grant(GrantEvent {
        grant_id: Hash32::from_label("vec-grant-1"),
        issuer: Hash32::from_label("vec-issuer"),
        subject: Hash32::from_label("vec-subject"),
        resource: Hash32::from_label("vec-resource"),
        scope: 0b0111,
        parent_grant_id: None,
        epoch: 1,
    });
    let g1 = Event::Grant(GrantEvent {
        grant_id: Hash32::from_label("vec-grant-2"),
        issuer: Hash32::from_label("vec-subject"),
        subject: Hash32::from_label("vec-subject-2"),
        resource: Hash32::from_label("vec-resource"),
        scope: 0b0011,
        parent_grant_id: Some(Hash32::from_label("vec-grant-1")),
        epoch: 2,
    });
    let r0 = Event::Revoke(RevokeEvent {
        grant_id: Hash32::from_label("vec-grant-1"),
        revoker: Hash32::from_label("vec-issuer"),
        epoch: 3,
    });

    let mut h_direct = History::new();
    h_direct.push(g0.clone());
    h_direct.push(g1.clone());
    h_direct.push(r0.clone());

    let mut h_cascade = History::new();
    h_cascade.push(g0.clone());
    h_cascade.push(g1.clone());
    h_cascade.push(r0.clone());

    let vectors = Vectors {
        schema: "D3-01-vectors-v1".to_string(),
        note: "Fixed vectors from the Rust reference implementation; event encoding uses 8-byte BE length prefix, SHA-256; roots use Poseidon P128Pow5T3 over Pallas base field.".to_string(),
        tree_depth: DEPTH,
        event_vectors: vec![
            ev_vec("grant-root", &g0),
            ev_vec("grant-child", &g1),
            ev_vec("revoke", &r0),
        ],
        histories: vec![
            history_vec("h3-direct", &h_direct, RevocationPolicy::DirectOnly),
            history_vec("h3-cascade", &h_cascade, RevocationPolicy::Cascade),
        ],
    };

    let json = serde_json::to_string_pretty(&vectors).unwrap();
    std::fs::write("tests/vectors/fixed_vectors.json", format!("{json}\n")).unwrap();
    println!("wrote tests/vectors/fixed_vectors.json");
}
