//! Re-verify the committed fixed vectors from tests/vectors/fixed_vectors.json.

const VECTOR_DEPTH: usize = 12;

use authz_history_semantic_binding_exp::encoding::Hash32;
use authz_history_semantic_binding_exp::event::{Event, GrantEvent, RevokeEvent};
use authz_history_semantic_binding_exp::history::History;
use authz_history_semantic_binding_exp::policy::RevocationPolicy;
use authz_history_semantic_binding_exp::{policy_digest, StateTransitionStatement};

#[test]
fn fixed_vectors_reproduce() {
    let raw = std::fs::read_to_string("tests/vectors/fixed_vectors.json").unwrap();
    let json: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(json["schema"], "D3-01-vectors-v1");
    assert_eq!(json["tree_depth"], VECTOR_DEPTH as u64);

    // Event encodings
    let ev = &json["event_vectors"][0];
    let g0 = Event::Grant(GrantEvent {
        grant_id: Hash32::from_label("vec-grant-1"),
        issuer: Hash32::from_label("vec-issuer"),
        subject: Hash32::from_label("vec-subject"),
        resource: Hash32::from_label("vec-resource"),
        scope: 0b0111,
        parent_grant_id: None,
        epoch: 1,
    });
    assert_eq!(ev["id"], "grant-root");
    assert_eq!(ev["encoding_hex"], hex::encode(g0.encode()));
    assert_eq!(ev["digest_hex"], g0.digest().to_hex());

    let rev_ev = &json["event_vectors"][2];
    let r0 = Event::Revoke(RevokeEvent {
        grant_id: Hash32::from_label("vec-grant-1"),
        revoker: Hash32::from_label("vec-issuer"),
        epoch: 3,
    });
    assert_eq!(rev_ev["encoding_hex"], hex::encode(r0.encode()));
    assert_eq!(rev_ev["digest_hex"], r0.digest().to_hex());

    // Histories
    for (idx, policy) in [
        (0usize, RevocationPolicy::DirectOnly),
        (1usize, RevocationPolicy::Cascade),
    ] {
        let hv = &json["histories"][idx];
        let mut hist = History::new();
        hist.push(g0.clone());
        hist.push(Event::Grant(GrantEvent {
            grant_id: Hash32::from_label("vec-grant-2"),
            issuer: Hash32::from_label("vec-subject"),
            subject: Hash32::from_label("vec-subject-2"),
            resource: Hash32::from_label("vec-resource"),
            scope: 0b0011,
            parent_grant_id: Some(Hash32::from_label("vec-grant-1")),
            epoch: 2,
        }));
        hist.push(r0.clone());
        let out = hist.replay_full(policy, VECTOR_DEPTH).unwrap();
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
        assert_eq!(hv["policy"], policy.code());
        assert_eq!(hv["batch_digest_hex"], hist.batch_digest().to_hex());
        assert_eq!(hv["grant_root_hex"], out.grant_root.to_hex());
        assert_eq!(hv["revoke_root_hex"], out.revoke_root.to_hex());
        assert_eq!(hv["state_summary_hex"], out.state.summary().to_hex());
        assert_eq!(hv["statement_digest_hex"], stmt.digest().to_hex());
        assert_eq!(
            hv["statement_size_bytes"],
            stmt.statement_size_bytes() as u64
        );
    }
}
