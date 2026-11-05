# mu-console-data

Dedicated Web Worker WASM data module for MuConsole: fetch + SSE client, normalized store, diffing, \<=10 Hz coalescing, offline snapshot and fixture scenario player.

## Architecture

- **Worker Engine & State Machine (`engine`)**: Pure, clock-driven state machine managing data fetch, SSE stream ingestion, and timer-driven diff emissions.
- **Normalized In-Memory Store (`store`)**: Normalized entity state (repositories, pipelines, canaries, telemetry) with diffing.
- **SSE Stream Frame Parser (`sse`)**: Hand-written WHATWG Server-Sent Events line parser supporting mixed line endings, BOMs, retry timers, and reconnect resilience.
- **Event Coalescing (`coalesce`)**: Throttles UI updates to \<=10 Hz and drops back to lightweight heartbeats when the browser tab is hidden.
- **Offline Snapshot & Watermarking (`offline`)**: Snapshot persistence via CacheStorage API with schema watermarking and automatic recovery on reconnect.
- **Fixture Scenario Player (`scenario`)**: Deterministic playback engine for offline testing, demos, and capability showcase.
- **REST / SSE DTO Decoders (`api`)**: Maps backend responses from `ActionRunner-controller`, `MuConDe`, `MuRegist`, and `MuObserve` into normalized store inputs.

## Testing & Verification

```bash
cargo test --all-targets
cargo check --target wasm32-unknown-unknown
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

## License

`mu-console-data` is licensed under the GNU Affero General Public License version 3.0 (`AGPL-3.0-only`). See [LICENSE](LICENSE).
