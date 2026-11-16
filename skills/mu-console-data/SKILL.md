---
name: mu-console-data
description: "Implement, test, and consume the mu-console-data crate for dedicated Web Worker state management, fail-closed folio RBAC gating, event coalescing, and offline data storage in MuConsole."
---

# `mu-console-data` Architecture & Guidelines

Use these guidelines when developing or integrating `mu-console-data`, the dedicated Web Worker data processing engine (`#![forbid(unsafe_code)]`, Protocol v6) for MuConsole:

## 1. Fail-Closed Session & Folio State Machine (`engine`, `wasm`)

- **Cold-Boot Fail-Closed Gate**:
  - At `t = 0` (`Configure`), `AuthState` starts `Unresolved`. The worker emits `Ready` + `Connecting` and dispatches **only** `GET /api/auth/session`, withholding `LoadOffline`, SSE streams, all operational REST calls, and operational `ViewModel` state until session resolution completes.
- **`anonymous_lockdown`, `AuthorizationDenied`, and `0`-Passkey Gating**:
  - When `anonymous_lockdown == true` or `AuthStatus::AuthorizationDenied`, all non-auth REST calls, `LoadOffline`, and SSE streams stay suppressed and restricted store slices remain scrubbed.
  - When authenticated with `passkey_count == 0` (`AuthStatus::PasskeyEnrollmentRequired`), `Store` opens a dismissible `DialogModel::PasskeyEnrollmentGate` (`CloseDialog` dismisses it) and permits `/api/auth/session`, `/api/auth/passkeys*`, `/api/auth/activity`, plus baseline public reads/streams (`system:status.read`, `ci:queue.read`, `ci:repos.public.read`) unless `anonymous_lockdown == true`; operator/private endpoints and `/api/auth/profile` wait for `AuthStatus::Active`.
  - Non-lockdown `Anonymous` sessions fetch and project **only** `active_policies`-authorized endpoints (withholding raw build logs, cluster nodes, observability logs, and registry slices unless explicitly permitted).
- **8-Area / 27-Subview REST & SSE Coverage (`api`, `wasm`)**:
  - Handles all Protocol v6 endpoints across System/Home (`/api/obs/v1/status/subsystems`, `subsystem_status_changed` SSE on `StreamId::Obs`, maintenance toggling), CI, CD (`/api/cd/runs`), A/B Deploy (`/api/cd/deployments/{id}/rollback`), Registry, Observability (Smartscape, PurePath, Problems, Logs, Metrics, DataStore, Ingress), Model Runner (`/api/mr/v1/status`, `/api/mr/v1/connection`), and Platform/Identity (`/api/auth/{profile,passkeys/*,roles/*,elevate/finish,activity,folios,role-folio-index,users,invites}`).

## 2. Role Lease Timers, Selective Scrubbing & Coalescing (`store`, `coalesce`)

- **Independent Per-Role Lease Countdowns**:
  - `Store::tick` advances `[seconds_remaining][idle_timer]` independently for every active `RoleLeaseView`.
  - `UiCommand::RecordUserActivity` resets only `idle_timer` without extending `hard_expires_at_ms`; non-activity REST/SSE traffic never resets idle leases.
  - When a `Timed` role reaches `00:00`, it deactivates locally, recomputes active policies from baseline + `Elective` + remaining unexpired `Timed` roles, scrubs only exclusive restricted slices while preserving still-authorized data, sets `force_snapshot_pending` (`DataEvent::Snapshot`), closes disallowed SSE streams, and triggers `/api/auth/session` confirmation.
- **Area Badges & Throttling (`coalesce`)**:
  - Computes 8-area `AreaBadges` health/status indicators across every tick/mutation.
  - Throttles UI diffs to `<= 10 Hz` (`MIN_INTERVAL_MS = 100`) and switches to heartbeats when the browser tab is hidden.

## 3. Resilience & Offline Support (`sse`, `offline`)

- **SSE Stream Parsing (`sse`)**:
  - WHATWG event stream parser with BOM stripping, mixed line endings, custom `retry:` support, and exponential backoff with deterministic jitter on reconnects.
- **CacheStorage Persistence (`offline`)**:
  - Persists sanitized `ViewModel` snapshots into `CacheStorage` under schema-watermarked keys only when `AuthStatus::Active` with enrolled Passkeys (`passkey_count > 0`) and replays them on `LoadOffline` only once operational data emission is authorized.

## 4. Privacy & Lab Boundary Invariants

- **Public Repository Cleanliness**:
  - Public documentation, logs, tests, and skills must never expose internal hostnames, private network ranges, or internal domains.
  - Use generic placeholders (`node-a`, `worker-riscv64`, `192.0.2.x`, `console.example.org`) across all tests and documentation.
