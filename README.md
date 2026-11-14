# mu-console-data

Dedicated Web Worker WASM data module for MuConsole (Protocol v6): fail-closed folio/RBAC state machine, REST + SSE client across all 8 console areas / 27 subviews, normalized store with diffing, `<= 10 Hz` coalescing, offline CacheStorage persistence, and fixture scenario player.

## Architecture

- **Fail-Closed Folio & Session Engine (`engine`)**: Pure, clock-driven state machine (`#![forbid(unsafe_code)]`) enforcing cold-boot session resolution (`/api/auth/session` before any operational REST, SSE, or offline restore), `anonymous_lockdown` suppression, non-dismissible `PasskeyEnrollmentGate` (`passkey_count == 0`), and folio-bounded endpoint/SSE gating.
- **Role Lease Timers & Selective Scrubbing (`store`)**: Independent per-role `[seconds_remaining][idle_timer]` countdowns (`RoleLeaseView`), explicit `RecordUserActivity`-only `idle_timer` reset keeping `hard_expires_at_ms` fixed, single-role expiry deactivation that scrubs only exclusive restricted slices, forces `DataEvent::Snapshot`, closes newly disallowed SSE streams, and triggers `/api/auth/session` refresh.
- **8-Area / 27-Subview Store & Area Badges (`store`, `api`)**: Normalizes and projects `AreaBadges` and `ViewModel` slices across System/Home, CI, CD (`/api/cd/runs`), A/B Deploy (`/api/cd/deployments/{id}/rollback`), Artifact Registry, Observability (`/api/obs/v1/status/subsystems`, `subsystem_status_changed` SSE, ingress/store), Model Runner (`/api/mr/v1/status`, `/api/mr/v1/connection`), and Platform/Identity (`/api/auth/{profile,passkeys/*,roles/*,elevate/finish,activity,folios,role-folio-index,users,invites}`).
- **SSE Stream Frame Parser (`sse`)**: WHATWG Server-Sent Events line parser supporting mixed line endings, BOMs, retry timers, and bounded jittered exponential backoff across CI, CD, and Obs streams.
- **Event Coalescing (`coalesce`)**: Throttles UI diffs to `<= 10 Hz` (`MIN_INTERVAL_MS = 100`) and drops to heartbeats when hidden.
- **Offline Snapshot & Watermarking (`offline`)**: Sanitized `ViewModel` snapshot persistence via `CacheStorage` for authenticated `Active` Passkey sessions with schema watermarking.
- **Fixture Scenario Player (`scenario`)**: Deterministic playback engine for offline testing and demos.

## Testing & Verification

```bash
cargo fmt --all -- --check
mdformat --check --wrap keep README.md skills/mu-console-data/SKILL.md
cargo clippy --all-targets -- -D warnings
cargo clippy --target wasm32-unknown-unknown --lib -- -D warnings
cargo test --all-targets
cargo build --target wasm32-unknown-unknown
MIRIFLAGS="-Zmiri-disable-isolation" cargo +nightly miri test --lib
```

## License

`mu-console-data` is licensed under the GNU Affero General Public License version 3.0 (`AGPL-3.0-only`). See [LICENSE](LICENSE).
