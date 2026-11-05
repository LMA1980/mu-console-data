// SPDX-License-Identifier: AGPL-3.0-only
//! CacheStorage offline snapshot.
//!
//! The worker periodically stores the live [`ViewModel`] as a versioned
//! postcard frame (same codec as the worker wire). On start-up it restores
//! the snapshot before live data arrives; the view is then flagged stale
//! (`stale_since_epoch_ms`, source `OfflineCache`). A snapshot written by a
//! different protocol version fails to decode and is ignored.

use mu_console_protocol::{decode, encode, CodecError, DataSource, ViewModel};
use serde::{Deserialize, Serialize};

/// CacheStorage cache name (bump with the format).
pub const CACHE_NAME: &str = "muconsole-offline-v1";
/// Synthetic request URL the snapshot is stored under.
pub const CACHE_KEY: &str = "/__muconsole/offline-snapshot";
/// Minimum spacing of snapshot writes.
pub const SAVE_INTERVAL_MS: u64 = 30_000;

/// Persisted snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfflineSnapshot {
    pub saved_epoch_ms: u64,
    pub view: ViewModel,
}

impl OfflineSnapshot {
    /// Encode as a versioned frame.
    ///
    /// # Errors
    /// Propagates [`CodecError::Encode`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, CodecError> {
        encode(self)
    }

    /// Decode a stored frame.
    ///
    /// # Errors
    /// Fails for other protocol versions or corrupt data.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CodecError> {
        decode(bytes)
    }
}

/// When to write the snapshot.
#[derive(Debug, Default)]
pub struct OfflinePolicy {
    last_save_ms: Option<u64>,
    saved: Option<ViewModel>,
}

impl OfflinePolicy {
    /// Returns the bytes to store when a save is due: live data only, at
    /// most every [`SAVE_INTERVAL_MS`], and only when the view changed.
    pub fn maybe_save(&mut self, now_ms: u64, view: &ViewModel) -> Option<Vec<u8>> {
        if view.source != DataSource::Live || view.repos.is_empty() {
            return None;
        }
        if self
            .last_save_ms
            .is_some_and(|t| now_ms.saturating_sub(t) < SAVE_INTERVAL_MS)
        {
            return None;
        }
        if self.saved.as_ref() == Some(view) {
            return None;
        }
        let bytes = OfflineSnapshot {
            saved_epoch_ms: now_ms,
            view: view.clone(),
        }
        .to_bytes()
        .ok()?;
        self.last_save_ms = Some(now_ms);
        self.saved = Some(view.clone());
        Some(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mu_console_protocol::{RepoId, RepoScore, PROTOCOL_VERSION};

    fn live_view() -> ViewModel {
        ViewModel {
            repos: vec![RepoScore::new(RepoId::new("fixture", "a"))],
            ..ViewModel::default()
        }
    }

    #[test]
    fn saves_live_views_at_most_every_interval() {
        let mut p = OfflinePolicy::default();
        assert!(p.maybe_save(0, &ViewModel::default()).is_none(), "empty");
        let v = live_view();
        let bytes = p.maybe_save(1_000, &v).expect("first save");
        let snap = OfflineSnapshot::from_bytes(&bytes).expect("decode");
        assert_eq!(snap.saved_epoch_ms, 1_000);
        assert_eq!(snap.view, v);
        let mut v2 = v.clone();
        v2.repos[0].score = 50;
        assert!(p.maybe_save(10_000, &v2).is_none(), "too soon");
        assert!(p.maybe_save(40_000, &v).is_none(), "unchanged");
        assert!(p.maybe_save(40_000, &v2).is_some());
        let mut scenario = v2.clone();
        scenario.source = DataSource::Scenario("x".into());
        assert!(
            p.maybe_save(90_000, &scenario).is_none(),
            "never persist fixtures"
        );
    }

    #[test]
    fn foreign_versions_are_rejected() {
        let mut frame = postcard::to_allocvec(&(PROTOCOL_VERSION + 1)).expect("v");
        frame.extend(postcard::to_allocvec(&0_u8).expect("b"));
        assert!(OfflineSnapshot::from_bytes(&frame).is_err());
    }
}
