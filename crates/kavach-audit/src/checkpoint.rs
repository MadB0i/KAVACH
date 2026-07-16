use chrono::Utc;

use crate::error::AuditError;
use crate::store::AuditStore;

/// A typed checkpoint representing the state of the chain at a point in time.
///
/// Checkpoints are read-only snapshots.  They can be used as a trusted starting
/// point for [`AuditStore::verify_from_checkpoint`] to avoid re-verifying the
/// entire history.
///
/// **Limitation:** An attacker with full machine control can replace both the
/// database and the checkpoint file together.  Checkpoints improve verification
/// performance but do not provide immutability against a fully compromised host.
#[derive(Debug, Clone)]
pub struct Checkpoint {
    /// The last sequence number included in this checkpoint.
    pub ending_sequence: u64,
    /// The hash of the last event at checkpoint time.
    pub ending_hash: String,
    /// ISO-8601 timestamp when the checkpoint was created.
    pub created_at: String,
    /// Total number of events in the chain at checkpoint time.
    pub event_count: u64,
}

impl AuditStore {
    /// Creates a checkpoint from the current chain state.
    ///
    /// This is a read-only operation — no database writes are performed.
    pub fn create_checkpoint(&self) -> Result<Checkpoint, AuditError> {
        let latest = self.latest_event()?;
        let count = self.event_count()?;

        match latest {
            Some(event) => Ok(Checkpoint {
                ending_sequence: event.sequence,
                ending_hash: event.current_hash.to_string(),
                created_at: Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
                event_count: count,
            }),
            None => {
                let genesis = crate::hash::HashValue::genesis();
                Ok(Checkpoint {
                    ending_sequence: 0,
                    ending_hash: genesis.to_string(),
                    created_at: Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
                    event_count: 0,
                })
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn empty_store_checkpoint() {
        let store = AuditStore::builder().open_in_memory().unwrap();
        let cp = store.create_checkpoint().unwrap();
        assert_eq!(cp.ending_sequence, 0);
        assert_eq!(cp.event_count, 0);
        assert!(!cp.ending_hash.is_empty());
    }
}
