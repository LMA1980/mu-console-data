// SPDX-License-Identifier: AGPL-3.0-only
//! Snapshot / Patch emission with ≤ 10 Hz coalescing and hidden-tab
//! heartbeat throttling.
//!
//! The engine calls [`Coalescer::poll`] on every timer tick. Store changes
//! that land between two emissions are merged into one [`DataEvent::Patch`]
//! computed by [`mu_console_protocol::diff`] against the last view the UI
//! received, so the UI never sees more than one message per
//! [`MIN_INTERVAL_MS`]. While the tab is hidden only
//! [`DataEvent::Heartbeat`]s go out; the first poll after the tab becomes
//! visible again sends a full [`DataEvent::Snapshot`].

use mu_console_protocol::{diff, DataEvent, ViewModel};

/// Minimum spacing of view emissions (10 Hz).
pub const MIN_INTERVAL_MS: u64 = 100;
/// Heartbeat period while hidden.
pub const HEARTBEAT_MS: u64 = 15_000;

/// Rate limiter and diff source for UI updates.
#[derive(Debug, Default)]
pub struct Coalescer {
    sent: Option<ViewModel>,
    last_emit_ms: Option<u64>,
    last_heartbeat_ms: u64,
    heartbeat_seq: u32,
    hidden: bool,
    force_snapshot: bool,
}

impl Coalescer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn is_hidden(&self) -> bool {
        self.hidden
    }

    /// Last view the UI received.
    #[must_use]
    pub fn sent(&self) -> Option<&ViewModel> {
        self.sent.as_ref()
    }

    /// Tab visibility changed.
    pub fn set_hidden(&mut self, hidden: bool, now_ms: u64) {
        if hidden && !self.hidden {
            self.last_heartbeat_ms = now_ms;
        }
        if !hidden && self.hidden {
            self.force_snapshot = true;
        }
        self.hidden = hidden;
    }

    /// Send a full snapshot on the next eligible poll.
    pub fn force_snapshot(&mut self) {
        self.force_snapshot = true;
    }

    /// Whether a view emission is allowed at `now_ms`.
    #[must_use]
    pub fn ready(&self, now_ms: u64) -> bool {
        !self.hidden
            && self
                .last_emit_ms
                .is_none_or(|t| now_ms.saturating_sub(t) >= MIN_INTERVAL_MS)
    }

    /// Whether the next view emission must be a snapshot.
    #[must_use]
    pub fn needs_snapshot(&self) -> bool {
        self.force_snapshot || self.sent.is_none()
    }

    /// Emit at most one event. `view` is only called when a view emission is
    /// due (`dirty`, a forced snapshot, or the first emission).
    pub fn poll(
        &mut self,
        now_ms: u64,
        dirty: bool,
        view: impl FnOnce() -> ViewModel,
    ) -> Option<DataEvent> {
        if self.hidden {
            if now_ms.saturating_sub(self.last_heartbeat_ms) >= HEARTBEAT_MS {
                self.last_heartbeat_ms = now_ms;
                self.heartbeat_seq = self.heartbeat_seq.wrapping_add(1);
                return Some(DataEvent::Heartbeat {
                    seq: self.heartbeat_seq,
                });
            }
            return None;
        }
        if !self.ready(now_ms) || !(dirty || self.needs_snapshot()) {
            return None;
        }
        let next = view();
        let event = match self.sent.as_ref() {
            Some(prev) if !self.force_snapshot => {
                let patch = diff(prev, &next);
                if patch.is_empty() {
                    return None;
                }
                DataEvent::Patch(patch)
            }
            _ => DataEvent::Snapshot(next.clone()),
        };
        self.force_snapshot = false;
        self.sent = Some(next);
        self.last_emit_ms = Some(now_ms);
        Some(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mu_console_protocol::{apply_all, FabricNode};

    fn vm(n: u32) -> ViewModel {
        ViewModel {
            nodes: (0..n)
                .map(|i| FabricNode {
                    id: format!("node-{i:02}"),
                    online: true,
                })
                .collect(),
            ..ViewModel::default()
        }
    }

    #[test]
    fn first_poll_is_a_snapshot_then_patches() {
        let mut c = Coalescer::new();
        assert!(matches!(
            c.poll(0, false, || vm(1)),
            Some(DataEvent::Snapshot(_))
        ));
        assert_eq!(c.poll(100, false, || vm(2)), None, "not dirty");
        assert!(matches!(
            c.poll(100, true, || vm(2)),
            Some(DataEvent::Patch(p)) if p.len() == 1
        ));
        assert_eq!(c.poll(300, true, || vm(2)), None, "empty diff");
    }

    #[test]
    fn rate_is_capped_at_ten_hz_and_changes_merge() {
        let mut c = Coalescer::new();
        let mut mirror = ViewModel::default();
        let mut emissions: Vec<u64> = Vec::new();
        // The store changes every 7 ms (49 ms under Miri) for 2 s.
        let step = if cfg!(miri) { 49 } else { 7 };
        for (n, now) in (0..2_000_u64).step_by(step).enumerate() {
            let target = vm(u32::try_from(n % 50).unwrap_or(0));
            if let Some(ev) = c.poll(now, true, || target) {
                emissions.push(now);
                match ev {
                    DataEvent::Snapshot(v) => mirror = v,
                    DataEvent::Patch(p) => apply_all(&mut mirror, &p),
                    other => panic!("unexpected {other:?}"),
                }
            }
        }
        assert!(emissions.len() <= 21, "{} emissions", emissions.len());
        assert!(emissions.windows(2).all(|w| w[1] - w[0] >= MIN_INTERVAL_MS));
        assert_eq!(Some(&mirror), c.sent());
    }

    #[test]
    fn hidden_tab_sends_heartbeats_only_then_resyncs() {
        let mut c = Coalescer::new();
        c.poll(0, true, || vm(1));
        c.set_hidden(true, 1_000);
        assert!(c.is_hidden());
        let mut beats = 0;
        for now in (1_000..61_000).step_by(100) {
            match c.poll(now, true, || vm(5)) {
                Some(DataEvent::Heartbeat { .. }) => beats += 1,
                None => {}
                Some(other) => panic!("unexpected while hidden: {other:?}"),
            }
        }
        assert_eq!(beats, 3);
        c.set_hidden(false, 61_000);
        assert!(matches!(
            c.poll(61_000, false, || vm(5)),
            Some(DataEvent::Snapshot(v)) if v.nodes.len() == 5
        ));
    }
}
