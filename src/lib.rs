// SPDX-License-Identifier: AGPL-3.0-only
//! MuConsole data worker (dedicated Web Worker WASM).
//!
//! All logic is plain Rust and tested natively:
//!
//! - [`sse`]: hand-written SSE line parser for `fetch` + `ReadableStream`;
//! - [`backoff`]: reconnect policy (exponential, jittered, server `retry:`);
//! - [`api`]: REST / SSE payload decoding into store inputs;
//! - [`store`]: normalized store keyed by repo, job and deployment;
//! - [`coalesce`]: Snapshot / Patch emission at ≤ 10 Hz, hidden-tab
//!   heartbeats;
//! - [`offline`]: CacheStorage snapshot policy and format;
//! - [`scenario`]: deterministic fixture scenarios (`?scenario=`);
//! - [`engine`]: the clock-driven state machine tying it together.
//!
//! The `wasm` module (wasm32 only) is the thin browser glue: it forwards
//! worker messages, fetch results, stream chunks and timer ticks to the
//! [`engine::Engine`] and executes the returned [`engine::Effect`]s.
#![forbid(unsafe_code)]

pub mod api;
pub mod backoff;
pub mod coalesce;
pub mod engine;
pub mod offline;
pub mod scenario;
pub mod sse;
pub mod store;

#[cfg(target_arch = "wasm32")]
pub mod wasm;

#[cfg(test)]
mod tests;

pub use engine::{Effect, Engine, HttpError};

/// Upper bound on UI patch rate (Hz) for the coalescer.
pub const MAX_PATCH_HZ: u32 = 10;
