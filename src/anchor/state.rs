//! Local durable anti-rollback state for accepted anchors.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use super::types::{
    AnchorStateStore, AnchorVerificationError, CommitOutcome, LocalAnchorState, VerifiedAnchor,
};

#[derive(Serialize, Deserialize)]
struct PersistedState {
    highest_sequence: i64,
    highest_digest: String,
}

impl AnchorStateStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Create the initial state only when the file does not yet exist.
    pub fn initialize(&self, genesis_digest: &str) -> Result<(), AnchorVerificationError> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| AnchorVerificationError::Io("anchor state mutex poisoned".to_string()))?;
        if self.path.exists() {
            return Ok(());
        }
        self.write_locked(&LocalAnchorState {
            highest_sequence: -1,
            highest_digest: genesis_digest.to_string(),
        })
    }

    /// Test/import helper: create a state file at an explicit high-water mark.
    pub fn initialize_with_sequence(
        &self,
        sequence: i64,
        digest: &str,
    ) -> Result<(), AnchorVerificationError> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| AnchorVerificationError::Io("anchor state mutex poisoned".to_string()))?;
        self.write_locked(&LocalAnchorState {
            highest_sequence: sequence,
            highest_digest: digest.to_string(),
        })
    }

    pub fn load(&self) -> Result<LocalAnchorState, AnchorVerificationError> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| AnchorVerificationError::Io("anchor state mutex poisoned".to_string()))?;
        self.load_locked()
    }

    fn load_locked(&self) -> Result<LocalAnchorState, AnchorVerificationError> {
        if !self.path.exists() {
            return Ok(LocalAnchorState {
                highest_sequence: -1,
                highest_digest: String::new(),
            });
        }
        let raw = fs::read(&self.path)
            .map_err(|e| AnchorVerificationError::Io(format!("read anchor state: {e}")))?;
        let parsed: PersistedState = serde_json::from_slice(&raw)
            .map_err(|e| AnchorVerificationError::Json(format!("parse anchor state: {e}")))?;
        Ok(LocalAnchorState {
            highest_sequence: parsed.highest_sequence,
            highest_digest: parsed.highest_digest,
        })
    }

    fn write_locked(&self, state: &LocalAnchorState) -> Result<(), AnchorVerificationError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                AnchorVerificationError::Io(format!("create anchor state dir: {e}"))
            })?;
        }
        let persisted = PersistedState {
            highest_sequence: state.highest_sequence,
            highest_digest: state.highest_digest.clone(),
        };
        let raw = serde_json::to_vec(&persisted)
            .map_err(|e| AnchorVerificationError::Json(format!("serialize anchor state: {e}")))?;

        let mut tmp = self.path.clone().into_os_string();
        tmp.push(format!(".tmp-{}", std::process::id()));
        let tmp_path = PathBuf::from(tmp);
        {
            let mut file = fs::File::create(&tmp_path).map_err(|e| {
                AnchorVerificationError::Io(format!("create anchor state temp: {e}"))
            })?;
            file.write_all(&raw).map_err(|e| {
                AnchorVerificationError::Io(format!("write anchor state temp: {e}"))
            })?;
            file.sync_all()
                .map_err(|e| AnchorVerificationError::Io(format!("sync anchor state temp: {e}")))?;
        }
        fs::rename(&tmp_path, &self.path).map_err(|e| {
            let _ = fs::remove_file(&tmp_path);
            AnchorVerificationError::Io(format!("commit anchor state atomically: {e}"))
        })?;
        Ok(())
    }

    /// Commit a successful verification.  This is the only place that advances
    /// the local high-water mark.
    pub fn commit(
        &self,
        anchor: &VerifiedAnchor,
    ) -> Result<CommitOutcome, AnchorVerificationError> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| AnchorVerificationError::Io("anchor state mutex poisoned".to_string()))?;
        let current = self.load_locked()?;

        if anchor.sequence() < current.highest_sequence {
            return Err(AnchorVerificationError::StaleSequence {
                known: current.highest_sequence,
                offered: anchor.sequence(),
            });
        }
        if anchor.sequence() == current.highest_sequence {
            if anchor.digest() != current.highest_digest {
                return Err(AnchorVerificationError::SameSequenceEquivocation {
                    sequence: anchor.sequence(),
                });
            }
            return Ok(CommitOutcome::AlreadyCommitted);
        }
        if anchor.checkpoint().previous_hash != current.highest_digest {
            return Err(AnchorVerificationError::BrokenAnchorChain);
        }

        self.write_locked(&LocalAnchorState {
            highest_sequence: anchor.sequence(),
            highest_digest: anchor.digest().to_string(),
        })?;
        Ok(CommitOutcome::Advanced)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anchor::types::AnchorCheckpoint;

    fn verified(seq: i64, digest: &str, prev: &str) -> VerifiedAnchor {
        let cp = AnchorCheckpoint {
            chain_id: "c".into(),
            epoch: seq,
            previous_hash: prev.into(),
            state_root: "00".repeat(32),
            log_root: "NO_LOG".into(),
            policy_version: "pv".into(),
            witness_set_root: "00".repeat(32),
            log_size: 0,
            timestamp: 0,
        };
        VerifiedAnchor {
            digest: digest.into(),
            sequence: seq,
            checkpoint: cp,
            state_commitment_hex: "00".repeat(32),
        }
    }

    #[test]
    fn commit_is_monotonic_and_idempotent() {
        let dir = std::env::temp_dir().join(format!("anchor-state-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = AnchorStateStore::new(dir.join("state.json"));
        store.initialize("genesis").unwrap();
        assert_eq!(
            store.commit(&verified(1, "d1", "genesis")).unwrap(),
            CommitOutcome::Advanced
        );
        assert_eq!(
            store.commit(&verified(1, "d1", "genesis")).unwrap(),
            CommitOutcome::AlreadyCommitted
        );
        assert!(matches!(
            store.commit(&verified(1, "other", "genesis")),
            Err(AnchorVerificationError::SameSequenceEquivocation { .. })
        ));
        assert!(matches!(
            store.commit(&verified(0, "old", "genesis")),
            Err(AnchorVerificationError::StaleSequence { .. })
        ));
        let _ = fs::remove_dir_all(&dir);
    }
}
