// SPDX-License-Identifier: AGPL-3.0-only
//! Worker entry point. Trunk builds this binary with
//! `data-type="worker"`; the generated loader shim runs `main` inside the
//! dedicated worker. Natively it does nothing (the logic is a library).

fn main() {
    #[cfg(target_arch = "wasm32")]
    mu_console_data::wasm::start();
}
