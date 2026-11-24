//! Bounded sliding-window log types and deterministic IndexedDB key helpers.
//!
//! Kept free of `web-sys` dependencies so host unit tests and Miri verify all
//! ordering, cursoring, and deduplication invariants cleanly.

use mu_console_protocol::{LogSeverity, OtelLogEntry};
use serde::{Deserialize, Serialize};

/// Maximum number of log rows held in the UI/worker live sliding window.
pub const OBS_LOG_WINDOW_CAPACITY: usize = 500;

/// Default page size for initial fetch, infinite scroll paging, and log search.
pub const OBS_LOG_PAGE_SIZE: usize = 200;

/// Hard FIFO capacity for the browser-local IndexedDB log cache.
pub const IDB_MAX_CACHED_LOGS: usize = 20_000;

/// Browser IndexedDB database name for cached OpenTelemetry logs.
pub const IDB_NAME: &str = "muconsole-obs-logs-v1";

/// Browser IndexedDB object store name holding [`CachedObsLog`] records.
pub const IDB_STORE_LOGS: &str = "logs";

/// IndexedDB record and sliding-window entry for an OpenTelemetry log line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedObsLog {
    /// Fixed-width lexicographic sort key (`<ts_ns:020>:<line_no:010>:<dedup_hash:016x>`).
    pub k: String,
    pub timestamp_unix_nano: i64,
    pub timestamp_ms: u64,
    pub line_no: u32,
    pub dedup_hash: u64,
    pub severity: LogSeverity,
    pub service: String,
    pub span_id: Option<String>,
    pub trace_id: String,
    pub message: String,
}

impl CachedObsLog {
    /// Construct a [`CachedObsLog`] from an [`OtelLogEntry`] and explicit server ordering metadata.
    #[must_use]
    pub fn with_meta(
        mut entry: OtelLogEntry,
        timestamp_unix_nano: i64,
        line_no: u32,
        dedup_hash: u64,
    ) -> Self {
        if entry.timestamp_ms == 0 && timestamp_unix_nano > 0 {
            entry.timestamp_ms = u64::try_from(timestamp_unix_nano.max(0)).unwrap_or(0) / 1_000_000;
        }
        let resolved_ns = if timestamp_unix_nano > 0 {
            timestamp_unix_nano
        } else {
            i64::try_from(entry.timestamp_ms)
                .unwrap_or(i64::MAX / 1_000_000)
                .saturating_mul(1_000_000)
        };
        let resolved_hash = if dedup_hash != 0 {
            dedup_hash
        } else {
            compute_fallback_dedup_hash(
                entry.timestamp_ms,
                &entry.service,
                &entry.trace_id,
                &entry.message,
            )
        };
        let k = make_log_sort_key(resolved_ns, line_no, resolved_hash);
        Self {
            k,
            timestamp_unix_nano: resolved_ns,
            timestamp_ms: entry.timestamp_ms,
            line_no,
            dedup_hash: resolved_hash,
            severity: entry.severity,
            service: entry.service,
            span_id: entry.span_id,
            trace_id: entry.trace_id,
            message: entry.message,
        }
    }

    /// Construct a [`CachedObsLog`] from an [`OtelLogEntry`] with fallback key metadata.
    #[must_use]
    pub fn from_otel_entry(entry: OtelLogEntry) -> Self {
        Self::with_meta(entry, 0, 0, 0)
    }

    /// Recompute [`Self::k`] after normalizing fields such as `service` or `message`.
    pub fn refresh_key(&mut self) {
        if self.dedup_hash == 0 {
            self.dedup_hash = compute_fallback_dedup_hash(
                self.timestamp_ms,
                &self.service,
                &self.trace_id,
                &self.message,
            );
        }
        self.k = make_log_sort_key(self.timestamp_unix_nano, self.line_no, self.dedup_hash);
    }

    /// Convert into an [`OtelLogEntry`] for [`mu_console_protocol::ObserveView`].
    #[must_use]
    pub fn to_otel_entry(&self) -> OtelLogEntry {
        OtelLogEntry {
            timestamp_ms: self.timestamp_ms,
            severity: self.severity,
            service: self.service.clone(),
            span_id: self.span_id.clone(),
            trace_id: self.trace_id.clone(),
            message: self.message.clone(),
        }
    }

    /// Format the keyset cursor expected by `/api/obs/v1/logs?before=...`.
    #[must_use]
    pub fn cursor(&self) -> String {
        format_log_cursor(self.timestamp_unix_nano, self.line_no, self.dedup_hash)
    }
}

/// Build a zero-padded lexicographic key matching `(timestamp_unix_nano, line_no, dedup_hash)`.
#[must_use]
pub fn make_log_sort_key(timestamp_unix_nano: i64, line_no: u32, dedup_hash: u64) -> String {
    let ts = u64::try_from(timestamp_unix_nano).unwrap_or(0);
    format!("{ts:020}:{line_no:010}:{dedup_hash:016x}")
}

/// Format an API keyset `before` cursor matching `mu-observable-hub::parse_log_cursor`.
#[must_use]
pub fn format_log_cursor(timestamp_unix_nano: i64, line_no: u32, dedup_hash: u64) -> String {
    format!("{timestamp_unix_nano}:{line_no}:{dedup_hash}")
}

/// Deterministic 64-bit FNV-1a fallback hash when `dedup_hash` is absent or `0`.
#[must_use]
pub fn compute_fallback_dedup_hash(
    timestamp_ms: u64,
    service: &str,
    trace_id: &str,
    message: &str,
) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut feed = |bytes: &[u8]| {
        for &b in bytes {
            hash ^= u64::from(b);
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
        hash ^= 0xff;
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    };
    feed(&timestamp_ms.to_le_bytes());
    feed(service.as_bytes());
    feed(trace_id.as_bytes());
    feed(message.as_bytes());
    if hash == 0 {
        1
    } else {
        hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sort_key_orders_lexicographically_across_nanos_line_and_hash() {
        let k1 = make_log_sort_key(1_700_000_000_000_000_000, 1, 0x0a);
        let k2 = make_log_sort_key(1_700_000_000_000_000_000, 2, 0x01);
        let k3 = make_log_sort_key(1_700_000_000_000_000_001, 0, 0x00);
        let k4 = make_log_sort_key(1_700_000_000_000_000_001, 0, 0xff);
        assert!(k1 < k2);
        assert!(k2 < k3);
        assert!(k3 < k4);
    }

    #[test]
    fn cached_log_derives_nanos_cursor_and_fallback_hash() {
        let entry = CachedObsLog::with_meta(
            OtelLogEntry {
                timestamp_ms: 1_700_000_123_456,
                severity: LogSeverity::Warn,
                service: "muobserve-collector".into(),
                span_id: Some("sp-1".into()),
                trace_id: "tr-1".into(),
                message: "Slow batch flush".into(),
            },
            0,
            42,
            0,
        );
        assert_eq!(entry.timestamp_unix_nano, 1_700_000_123_456_000_000);
        assert_ne!(entry.dedup_hash, 0);
        assert_eq!(
            entry.cursor(),
            format!("1700000123456000000:42:{}", entry.dedup_hash)
        );
        assert_eq!(entry.to_otel_entry().message, "Slow batch flush");
    }

    #[test]
    fn fallback_dedup_hash_is_deterministic_and_non_zero() {
        let h1 = compute_fallback_dedup_hash(1000, "svc", "tr", "hello");
        let h2 = compute_fallback_dedup_hash(1000, "svc", "tr", "hello");
        let h3 = compute_fallback_dedup_hash(1000, "svc", "tr", "world");
        assert_eq!(h1, h2);
        assert_ne!(h1, 0);
        assert_ne!(h1, h3);
    }
}
