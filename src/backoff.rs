// SPDX-License-Identifier: AGPL-3.0-only
//! Reconnect policy: exponential backoff with deterministic jitter.
//!
//! The delay for attempt `n` (1-based) is
//! `min(max, base * 2^(n-1))` scaled by a jitter factor in `[0.8, 1.2)`.
//! The base is the server's `retry:` value when it sent one. Jitter comes
//! from a SplitMix64 hash of `(seed, attempt)`, so tests are reproducible
//! while different tabs (different seeds) still spread out.

/// Default first-retry delay.
pub const BASE_MS: u32 = 500;
/// Ceiling for the delay.
pub const MAX_MS: u32 = 30_000;

/// Backoff state for one stream.
#[derive(Debug, Clone)]
pub struct Backoff {
    seed: u64,
    attempt: u32,
    server_retry_ms: Option<u32>,
}

impl Backoff {
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            seed,
            attempt: 0,
            server_retry_ms: None,
        }
    }

    /// Failed attempts since the last successful connect.
    #[must_use]
    pub fn attempt(&self) -> u32 {
        self.attempt
    }

    /// Adopt the server's `retry:` hint as the base delay.
    pub fn set_server_retry(&mut self, ms: Option<u32>) {
        if ms.is_some() {
            self.server_retry_ms = ms;
        }
    }

    /// A connection succeeded.
    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    /// Register a failure and return the delay before the next attempt.
    pub fn next_delay_ms(&mut self) -> u32 {
        self.attempt = self.attempt.saturating_add(1);
        let base = u64::from(self.server_retry_ms.unwrap_or(BASE_MS).max(1));
        let shift = (self.attempt - 1).min(16);
        let raw = (base << shift).min(u64::from(MAX_MS));
        // Jitter factor in [0.8, 1.2): 800..1200 per mille.
        let per_mille = 800 + splitmix(self.seed ^ u64::from(self.attempt)) % 400;
        let jittered = raw * per_mille / 1000;
        u32::try_from(jittered.min(u64::from(MAX_MS))).unwrap_or(MAX_MS)
    }
}

fn splitmix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grows_exponentially_within_jitter_and_caps() {
        let mut b = Backoff::new(1);
        let mut prev_raw: u64 = 0;
        for n in 1..=12_u32 {
            let d = u64::from(b.next_delay_ms());
            let raw = (u64::from(BASE_MS) << (n - 1)).min(u64::from(MAX_MS));
            assert!(d >= raw * 8 / 10 && d <= raw * 12 / 10, "attempt {n}: {d}");
            assert!(d <= u64::from(MAX_MS));
            assert!(raw >= prev_raw);
            prev_raw = raw;
        }
        assert_eq!(b.attempt(), 12);
        b.reset();
        assert_eq!(b.attempt(), 0);
        assert!(b.next_delay_ms() <= BASE_MS * 12 / 10);
    }

    #[test]
    fn server_retry_sets_the_base_and_is_deterministic() {
        let mut a = Backoff::new(9);
        let mut b = Backoff::new(9);
        a.set_server_retry(Some(2_000));
        b.set_server_retry(Some(2_000));
        a.set_server_retry(None);
        let da = a.next_delay_ms();
        assert_eq!(da, b.next_delay_ms());
        assert!((1_600..2_400).contains(&da));
    }

    #[test]
    fn huge_attempt_counts_do_not_overflow() {
        let mut b = Backoff::new(5);
        for _ in 0..200 {
            assert!(b.next_delay_ms() <= MAX_MS);
        }
    }
}
