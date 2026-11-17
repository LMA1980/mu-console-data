# mu-console-data

Dedicated Web Worker WASM data module for [`mu-console`](https://github.com/LMA1980/mu-console) (`Protocol v8`, [`mu-console-protocol`](https://github.com/LMA1980/mu-console-protocol)): fail-closed folio/RBAC state machine, REST + SSE client across all 8 console areas / 27 subviews, normalized store with diffing, `<= 10 Hz` coalescing, offline CacheStorage persistence, and fixture scenario player.

## Architecture

- **Fail-Closed Folio & Session Engine (`engine`)**: Pure, clock-driven state machine (`#![forbid(unsafe_code)]`) enforcing cold-boot session resolution (`/api/auth/session` before any operational REST, SSE, or offline restore), `anonymous_lockdown` suppression, dismissible guiding `PasskeyEnrollmentGate` (`passkey_count == 0`) with baseline public read fallback when not locked down, and folio-bounded endpoint/SSE gating backed by [`mu-auth`](https://github.com/LMA1980/mu-auth).
- **Role Lease Timers, Passkey Renewal & Selective Scrubbing (`store`)**: Independent per-role `[seconds_remaining][idle_timer]` countdowns (`RoleLeaseView`), explicit `RecordUserActivity`-only `idle_timer` reset keeping `hard_expires_at_ms` fixed, `RenewRoleWithPasskey` (`POST /api/auth/roles/{id}/renew/start` and `POST /api/auth/roles/{id}/renew`) for final-2m lease extension, single-role expiry deactivation that scrubs only exclusive restricted slices, forces `DataEvent::Snapshot`, closes newly disallowed SSE streams, and triggers `/api/auth/session` refresh.
- **8-Area / 27-Subview Store & Area Badges (`store`, `api`)**: Normalizes and projects `AreaBadges` and `ViewModel` slices across:
  - **Dashboard** (`Area::Dashboard`): Aggregate operational health, fleet status, and attention queue.
  - **CI** ([`mu-ci-controller`](https://github.com/LMA1980/mu-ci-controller)): `/api/repos`, `/api/repos/{owner}/{repo}/summary`, `/api/repos/{owner}/{repo}/topology`, `/api/queue`, `/api/jobs/{id}`, `/api/jobs/{id}/log`, `/api/jobs/{id}/{restart,resume}`, `/api/cluster/nodes`, and `/api/events`.
  - **CD & A|B Deploy** ([`mu-cd-controller`](https://github.com/LMA1980/mu-cd-controller)): `/api/cd/runs`, `/api/cd/deployments`, `/api/cd/deployments/{id}/gate`, `/api/cd/deployments/{id}/rollback`, `/api/cd/leases`, and `/api/cd/events`.
  - **Registry** ([`mu-registry`](https://github.com/LMA1980/mu-registry)): `/api/reg/v1/packages`, `/api/reg/v1/canaries`, and `/api/reg/v1/cas/status`.
  - **Observability** ([`mu-observable-hub`](https://github.com/LMA1980/mu-observable-hub)): `/api/obs/v1/smartscape`, `/api/obs/v1/problems`, `/api/obs/v1/traces*`, `/api/obs/v1/logs`, `/api/obs/v1/metrics/timeseries`, `/api/obs/v1/store/status`, `/api/obs/v1/status/subsystems*`, `/api/obs/v1/ingress/{overview,routes,upstreams}`, and `/api/obs/v1/events`.
  - **Model Runner** ([`jero-manager`](https://github.com/LMA1980/jero-manager)): `/api/mr/v1/status` and `/api/mr/v1/connection`.
  - **Platform** ([`mu-auth`](https://github.com/LMA1980/mu-auth)): `/api/auth/{session,redeem,profile,passkeys/*,roles/*,elevate/*,activity,folios,role-folio-index,users/*,invites/*}`.
- **SSE Stream Frame Parser (`sse`)**: WHATWG Server-Sent Events line parser supporting mixed line endings, BOMs, retry timers, and bounded jittered exponential backoff across CI, CD, and Obs streams.
- **Event Coalescing (`coalesce`)**: Throttles UI diffs to `<= 10 Hz` (`MIN_INTERVAL_MS = 100`) and drops to heartbeats when hidden.
- **Offline Snapshot & Watermarking (`offline`)**: Sanitized `ViewModel` snapshot persistence via `CacheStorage` for authenticated `Active` Passkey sessions with schema watermarking.
- **Fixture Scenario Player (`scenario`)**: Deterministic playback engine for offline testing and demos.

## Ecosystem Integration

- **Parent & UI**: [`mu-console`](https://github.com/LMA1980/mu-console), [`mu-console-protocol`](https://github.com/LMA1980/mu-console-protocol), [`mu-console-ui`](https://github.com/LMA1980/mu-console-ui)
- **Backend Controllers**: [`mu-auth`](https://github.com/LMA1980/mu-auth), [`mu-ci-controller`](https://github.com/LMA1980/mu-ci-controller), [`mu-cd-controller`](https://github.com/LMA1980/mu-cd-controller), [`mu-registry`](https://github.com/LMA1980/mu-registry), [`mu-observable-hub`](https://github.com/LMA1980/mu-observable-hub), [`jero-manager`](https://github.com/LMA1980/jero-manager)

## Testing & Verification

```bash
cargo fmt --all -- --check
./scripts/format_docs.sh --check
cargo clippy --all-targets -- -D warnings
cargo clippy --target wasm32-unknown-unknown --lib -- -D warnings
cargo test --all-targets
cargo build --target wasm32-unknown-unknown
MIRIFLAGS="-Zmiri-disable-isolation" cargo +nightly miri test --lib
```

## License

`mu-console-data` is licensed under the GNU Affero General Public License version 3.0 (`AGPL-3.0-only`). See [LICENSE](LICENSE).
