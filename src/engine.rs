// SPDX-License-Identifier: AGPL-3.0-only
//! The data worker engine: a pure, clock-driven state machine.
//!
//! The browser glue (`wasm` module) only forwards inputs: UI frames,
//! fetch results, SSE chunks, stream open/close, timer ticks, offline cache
//! reads. It then executes the returned [`Effect`]s. All decisions
//! (subscriptions, reconnect timing, coalescing, scenario playback, offline
//! snapshots) live here and are tested natively.

use std::collections::BTreeSet;

use mu_console_protocol::dto::paths;
use mu_console_protocol::{
    decode, encode, AbDeploySubView, Area, AreaBadges, AuthStatus, CdSubView, CiSubView,
    CodecError, ConnState, DataEvent, DataSource, DialogModel, ModelRunnerSubView,
    ObservabilitySubView, PlatformSubView, RepoId, RepositorySubView, Selection, SubView,
    UiCommand, UiError, WorkerConfig, PROTOCOL_VERSION,
};

use crate::api::{parse_event, parse_fetch, sanitize_obs_log_search_query, FetchKind, StreamId};
use crate::backoff::Backoff;
use crate::coalesce::Coalescer;
use crate::log_cache::{CachedObsLog, OBS_LOG_PAGE_SIZE, OBS_LOG_WINDOW_CAPACITY};
use crate::offline::{OfflinePolicy, OfflineSnapshot};
use crate::scenario::{Scenario, ScenarioPlayer};
use crate::sse::SseParser;
use crate::store::{auth_can_access_area, auth_has_policy, Input, Store};

/// History-strip length requested from `/api/cd/deployments`.
pub const HISTORY_LIMIT: u32 = 8;
/// After this many failed attempts with no live data, report `Offline`.
pub const OFFLINE_AFTER_ATTEMPTS: u32 = 3;
/// Rotary-selector settle window before committing a new selection.
pub const SELECT_SETTLE_MS: u64 = 350;
/// Active CI job detail & log tailing poll interval (ms) while a job is running or queued.
pub const LIVE_ACTIVE_JOB_POLL_MS: u64 = 2_000;
/// Minimum interval (ms) between `/api/auth/activity` heartbeats for timed role idle timers.
pub const ACTIVITY_HEARTBEAT_MS: u64 = 5_000;
/// Minimum duration (ms) an SSE connection must stay open before its backoff resets.
pub const MIN_STABLE_STREAM_MS: u64 = 5_000;

/// Side effect for the browser glue to execute.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// Post a message to the UI (transferable `ArrayBuffer`).
    Post(DataEvent),
    /// `GET url`; report back with [`Engine::on_fetch`].
    Fetch { kind: FetchKind, url: String },
    /// Open an SSE stream with `fetch` + `ReadableStream`
    /// (`Accept: text/event-stream`, `Last-Event-ID` when set).
    OpenStream {
        stream: StreamId,
        url: String,
        last_event_id: Option<String>,
    },
    /// Abort a stream.
    CloseStream(StreamId),
    /// Write the offline snapshot bytes to CacheStorage.
    SaveOffline(Vec<u8>),
    /// Read the offline snapshot; report back with
    /// [`Engine::on_offline_loaded`].
    LoadOffline,
    /// Persist newly received log rows into the browser-local IndexedDB cache.
    CacheObsLogs(Vec<CachedObsLog>),
    /// Read up to `limit` logs strictly older than `before_key` from IndexedDB.
    ReadObsLogCacheOlder {
        before_key: String,
        limit: usize,
        gen: u64,
    },
    /// Read up to `limit` logs strictly newer than `after_key` from IndexedDB.
    ReadObsLogCacheNewer {
        after_key: String,
        limit: usize,
        gen: u64,
    },
    /// Read the newest `limit` logs from IndexedDB.
    ReadObsLogCacheLatest { limit: usize, gen: u64 },
    /// Fail-closed wipe of all cached logs in browser IndexedDB.
    ClearObsLogCache,
}

/// Failed fetch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpError {
    /// HTTP status, `0` for network errors.
    pub status: u32,
    pub message: String,
}

#[derive(Debug)]
struct StreamState {
    parser: SseParser,
    backoff: Backoff,
    open: bool,
    opened_at: Option<u64>,
    reconnect_at: Option<u64>,
}

impl StreamState {
    fn new(seed: u64) -> Self {
        Self {
            parser: SseParser::new(),
            backoff: Backoff::new(seed),
            open: false,
            opened_at: None,
            reconnect_at: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Waiting for [`UiCommand::Configure`].
    Idle,
    Live,
    Scenario,
}

/// Data worker engine.
#[derive(Debug)]
pub struct Engine {
    mode: Mode,
    config: WorkerConfig,
    store: Store,
    out: Coalescer,
    offline: OfflinePolicy,
    streams: [StreamState; 3],
    player: Option<ScenarioPlayer>,
    conn: Option<ConnState>,
    badges: Option<AreaBadges>,
    asked_deployments: BTreeSet<String>,
    asked_job_details: BTreeSet<u64>,
    fallback_job_logs: BTreeSet<u64>,
    selected_job_id: Option<u64>,
    active_subview: Option<SubView>,
    last_live_poll_ms: u64,
    last_activity_post_ms: Option<u64>,
    offline_requested: bool,
    selection_gen: u64,
    pending_select: Option<(u64, Selection)>,
    obs_log_query_gen: u64,
    active_obs_log_query: Option<String>,
    last_auth_login: Option<String>,
}

impl Engine {
    /// `seed` spreads reconnect jitter across tabs (e.g. `Date.now()`).
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            mode: Mode::Idle,
            config: WorkerConfig::default(),
            store: Store::new(DataSource::Live),
            out: Coalescer::new(),
            offline: OfflinePolicy::default(),
            streams: [
                StreamState::new(seed),
                StreamState::new(seed.rotate_left(17)),
                StreamState::new(seed.rotate_left(33)),
            ],
            player: None,
            conn: None,
            badges: None,
            asked_deployments: BTreeSet::new(),
            asked_job_details: BTreeSet::new(),
            fallback_job_logs: BTreeSet::new(),
            selected_job_id: None,
            active_subview: None,
            last_live_poll_ms: 0,
            last_activity_post_ms: None,
            offline_requested: false,
            selection_gen: 0,
            pending_select: None,
            obs_log_query_gen: 0,
            active_obs_log_query: None,
            last_auth_login: None,
        }
    }

    /// Current selection generation token (bumped on every selection change).
    #[must_use]
    pub fn selection_gen(&self) -> u64 {
        self.selection_gen
    }

    /// Record a rotary detent; commits after [`SELECT_SETTLE_MS`] of quiet time.
    pub fn rotary_detent(&mut self, sel: Selection, now_ms: u64) {
        self.pending_select = Some((now_ms.saturating_add(SELECT_SETTLE_MS), sel));
    }

    /// Set the scenario playback speed in percent (`100` = 1x, `0` = manual).
    pub fn set_scenario_speed(&mut self, speed_pct: u32) {
        if let Some(p) = self.player.as_mut() {
            p.set_speed(speed_pct);
        }
    }

    /// Advance the active scenario by one step immediately.
    pub fn step_scenario(&mut self) -> bool {
        let Some(p) = self.player.as_mut() else {
            return false;
        };
        if let Some((at, input)) = p.step() {
            self.store.apply(input, at);
            true
        } else {
            false
        }
    }

    /// Read-only store access (tests, diagnostics).
    #[must_use]
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Whether the UI is hidden (heartbeat-only).
    #[must_use]
    pub fn is_hidden(&self) -> bool {
        self.out.is_hidden()
    }

    /// Decode a UI frame and handle it. Version mismatches and malformed
    /// frames are reported to the UI instead of panicking.
    pub fn handle_frame(&mut self, frame: &[u8], now_ms: u64) -> Vec<Effect> {
        match decode::<UiCommand>(frame) {
            Ok(cmd) => self.handle(cmd, now_ms),
            Err(CodecError::VersionMismatch { expected, found }) => {
                vec![Effect::Post(DataEvent::Error(UiError::VersionMismatch {
                    expected,
                    found,
                }))]
            }
            Err(e) => vec![Effect::Post(DataEvent::Error(UiError::Decode(
                e.to_string(),
            )))],
        }
    }

    /// Encode an outgoing event as a versioned frame.
    ///
    /// # Errors
    /// Propagates [`CodecError::Encode`].
    pub fn encode_event(ev: &DataEvent) -> Result<Vec<u8>, CodecError> {
        encode(ev)
    }

    /// Handle one UI command.
    pub fn handle(&mut self, cmd: UiCommand, now_ms: u64) -> Vec<Effect> {
        let mut fx = Vec::new();
        match cmd {
            UiCommand::Configure(cfg) => self.configure(cfg, now_ms, &mut fx),
            UiCommand::Subscribe(route) => {
                self.active_subview = Some(route.subview);
                let filter_q = route
                    .filter
                    .as_deref()
                    .map(sanitize_obs_log_search_query)
                    .filter(|s| !s.is_empty());
                let is_log_subview = matches!(
                    route.subview,
                    SubView::Observability(ObservabilitySubView::Logs)
                        | SubView::Ci(CiSubView::QueueLogs)
                );
                if is_log_subview && filter_q != self.active_obs_log_query {
                    self.obs_log_query_gen = self.obs_log_query_gen.wrapping_add(1);
                    self.active_obs_log_query.clone_from(&filter_q);
                    if filter_q.is_none() {
                        self.store.clear_active_log_query();
                        if self.mode == Mode::Live
                            && auth_has_policy(self.store.auth(), "obs:logs.read")
                        {
                            fx.push(Effect::ReadObsLogCacheLatest {
                                limit: OBS_LOG_WINDOW_CAPACITY,
                                gen: self.obs_log_query_gen,
                            });
                        }
                    }
                }
                if let Some(repo) = route.repo {
                    self.select(
                        Selection {
                            repo,
                            submodule: route.submodule,
                        },
                        now_ms,
                        &mut fx,
                    );
                }
                if self.mode == Mode::Live {
                    if let Some(tid) = route.trace_id {
                        self.fetch(FetchKind::ObsTraceDetail(tid), &mut fx);
                    }
                    self.fetch_subview(route.subview, route.filter.as_deref(), &mut fx);
                }
            }
            UiCommand::SelectRepo { repo, submodule } => {
                self.select(Selection { repo, submodule }, now_ms, &mut fx);
            }
            UiCommand::SelectSubView(subview) => {
                self.active_subview = Some(subview);
                if self.active_obs_log_query.is_some() || self.store.is_active_log_query() {
                    self.obs_log_query_gen = self.obs_log_query_gen.wrapping_add(1);
                    self.active_obs_log_query = None;
                }
                self.store.clear_active_log_query();
                if self.mode == Mode::Live {
                    self.fetch_subview(subview, None, &mut fx);
                }
            }
            UiCommand::Retry | UiCommand::ResetStream => self.retry(now_ms, &mut fx),
            UiCommand::SetVisibility { hidden } => {
                self.out.set_hidden(hidden, now_ms);
                let state = if hidden {
                    ConnState::Paused
                } else {
                    self.resting_conn(now_ms)
                };
                self.set_conn(state, &mut fx);
                if !hidden {
                    self.badges = None;
                }
            }
            UiCommand::Page { .. } | UiCommand::Navigate { .. } => {}
            UiCommand::SetCrtFont(font) => {
                self.store.apply(
                    Input::LocalUserPrefs {
                        skin: None,
                        font: Some(font),
                    },
                    now_ms,
                );
            }
            UiCommand::SetSkin(skin) => {
                self.store.apply(
                    Input::LocalUserPrefs {
                        skin: Some(skin),
                        font: None,
                    },
                    now_ms,
                );
            }
            UiCommand::RefreshSession => {
                if self.mode == Mode::Live {
                    self.fetch(FetchKind::AuthSession, &mut fx);
                }
            }
            UiCommand::SetAuthSession(dto) => {
                let prev_allowed = self.store.can_emit_operational_data();
                let prev_policies = self.store.auth().active_policies.clone();
                self.store.apply(Input::AuthSession(dto), now_ms);
                self.on_auth_transition(prev_allowed, &prev_policies, now_ms, &mut fx);
            }
            UiCommand::RedeemInvite { token } => {
                if self.mode == Mode::Live && !token.is_empty() {
                    self.fetch(FetchKind::AuthRedeem(token), &mut fx);
                }
            }
            UiCommand::EnableRole { role_id } => {
                self.dispatch_role_action(
                    FetchKind::AuthEnableRole(role_id),
                    "Active session required to enable roles",
                    now_ms,
                    &mut fx,
                );
            }
            UiCommand::DisableRole { role_id } => {
                self.dispatch_role_action(
                    FetchKind::AuthDisableRole(role_id),
                    "Active session required to disable roles",
                    now_ms,
                    &mut fx,
                );
            }
            UiCommand::ElevateWithPasskey {
                role_id,
                assertion_json,
            } => {
                self.dispatch_role_action(
                    FetchKind::AuthElevateFinish {
                        role_id,
                        assertion_json,
                    },
                    "Active session required for role elevation",
                    now_ms,
                    &mut fx,
                );
            }
            UiCommand::RenewRoleWithPasskey {
                role_id,
                assertion_json,
            } => {
                self.dispatch_role_action(
                    FetchKind::AuthRenewRole {
                        role_id,
                        assertion_json,
                    },
                    "Active session required for role renewal",
                    now_ms,
                    &mut fx,
                );
            }
            UiCommand::LockTimedRoles => {
                self.dispatch_role_action(
                    FetchKind::AuthLockRoles,
                    "Active session required to lock timed roles",
                    now_ms,
                    &mut fx,
                );
            }
            UiCommand::RecordUserActivity => {
                self.store.apply(Input::UserActivityRecorded, now_ms);
                if self.mode == Mode::Live
                    && !self.store.auth().leases.is_empty()
                    && self
                        .last_activity_post_ms
                        .is_none_or(|prev| now_ms >= prev.saturating_add(ACTIVITY_HEARTBEAT_MS))
                {
                    self.last_activity_post_ms = Some(now_ms);
                    self.fetch(FetchKind::AuthActivity, &mut fx);
                }
            }
            UiCommand::UpdateUserProfile {
                display_name,
                preferred_skin,
                preferred_font,
            } => {
                let kind = FetchKind::AuthProfilePut {
                    display_name: display_name.clone(),
                    preferred_skin,
                    preferred_font,
                };
                if self.can_fetch(&kind) {
                    self.store.apply(
                        Input::UpdateProfileOptimistic {
                            display_name,
                            preferred_skin,
                            preferred_font,
                        },
                        now_ms,
                    );
                    if self.mode == Mode::Live {
                        self.fetch(kind, &mut fx);
                    }
                } else {
                    deny_403(&mut fx, "Authenticated session required to update profile");
                }
            }
            UiCommand::EnrollPasskey {
                label,
                attestation_json,
            } => {
                let kind = FetchKind::AuthPasskeyRegisterFinish {
                    label,
                    attestation_json,
                };
                if self.can_fetch(&kind) {
                    if self.mode == Mode::Live {
                        self.fetch(kind, &mut fx);
                    }
                } else {
                    deny_403(&mut fx, "Authenticated session required to enroll passkeys");
                }
            }
            UiCommand::RemovePasskey {
                credential_id,
                step_up_assertion_json,
            } => {
                let kind = FetchKind::AuthPasskeyDelete {
                    credential_id,
                    step_up_assertion_json,
                };
                if self.can_fetch(&kind) {
                    if self.mode == Mode::Live {
                        self.fetch(kind, &mut fx);
                    }
                } else {
                    deny_403(&mut fx, "Authenticated session required to remove passkeys");
                }
            }
            UiCommand::OpenDialog(dlg) => {
                if self.mode == Mode::Live {
                    match &dlg {
                        DialogModel::UserProfile(_) => {
                            self.fetch(FetchKind::AuthProfile, &mut fx);
                            self.fetch(FetchKind::AuthPasskeys, &mut fx);
                        }
                        DialogModel::SessionRoles(_) => {
                            self.fetch(FetchKind::AuthSession, &mut fx);
                            if self.can_fetch(&FetchKind::AuthRoles) {
                                self.fetch(FetchKind::AuthRoles, &mut fx);
                            }
                        }
                        _ => {}
                    }
                }
                self.store.apply(Input::OpenDialog(dlg), now_ms);
            }
            UiCommand::CloseDialog => {
                self.store.apply(Input::CloseDialog, now_ms);
            }
            UiCommand::RestartJob { job_id } => {
                if self.require_policy(
                    "ci:jobs.restart",
                    &mut fx,
                    "Policy ci:jobs.restart required to restart jobs",
                ) {
                    self.store.apply(Input::JobRestarted(job_id), now_ms);
                    if self.mode == Mode::Live {
                        self.fetch(FetchKind::RestartJob(job_id), &mut fx);
                        self.fetch(FetchKind::CiQueue, &mut fx);
                    }
                }
            }
            UiCommand::ResumeJob { job_id } => {
                if self.require_policy(
                    "ci:jobs.resume",
                    &mut fx,
                    "Policy ci:jobs.resume required to resume jobs",
                ) {
                    self.store.apply(Input::JobResumed(job_id), now_ms);
                    if self.mode == Mode::Live {
                        self.fetch(FetchKind::ResumeJob(job_id), &mut fx);
                        self.fetch(FetchKind::CiQueue, &mut fx);
                    }
                }
            }
            UiCommand::SelectJob { job_id } => {
                if job_id > 0 {
                    self.selected_job_id = Some(job_id);
                    if self.mode == Mode::Live {
                        self.fetch(FetchKind::JobDetail(job_id), &mut fx);
                        if self.fallback_job_logs.contains(&job_id)
                            && !auth_has_policy(self.store.auth(), "ci:jobs.logs.read")
                        {
                            self.fetch_obs_job_log(job_id, &mut fx);
                        } else {
                            self.fetch_active_job_log(job_id, &mut fx);
                        }
                    }
                }
            }
            UiCommand::TriggerAbRollback {
                deployment_id,
                note,
            } => {
                if self.require_policy(
                    "ab:rollback",
                    &mut fx,
                    "Policy ab:rollback required for emergency rollback",
                ) && self.mode == Mode::Live
                {
                    self.fetch(
                        FetchKind::AbRollback {
                            deployment_id,
                            note,
                        },
                        &mut fx,
                    );
                }
            }
            UiCommand::SetSubsystemMaintenance {
                subsystem,
                mode,
                reason,
                auto_clear_secs,
            } => {
                if self.require_policy(
                    "platform:maintenance.write",
                    &mut fx,
                    "Policy platform:maintenance.write required to update maintenance mode",
                ) && self.mode == Mode::Live
                {
                    self.fetch(
                        FetchKind::SetSubsystemMaintenance {
                            subsystem,
                            mode,
                            reason,
                            auto_clear_secs,
                        },
                        &mut fx,
                    );
                }
            }
            UiCommand::CreateInvite { note, ttl_secs } => {
                if self.require_policy(
                    "platform:invites.write",
                    &mut fx,
                    "Policy platform:invites.write required to create invites",
                ) && self.mode == Mode::Live
                {
                    self.fetch(FetchKind::AuthCreateInvite { note, ttl_secs }, &mut fx);
                }
            }
            UiCommand::RevokeInvite { invite_id } => {
                if self.require_policy(
                    "platform:invites.write",
                    &mut fx,
                    "Policy platform:invites.write required to revoke invites",
                ) && self.mode == Mode::Live
                {
                    self.fetch(FetchKind::AuthRevokeInvite(invite_id), &mut fx);
                }
            }
            UiCommand::UpdateUserRoles {
                github_login,
                bound_roles,
            } => {
                if self.require_policy(
                    "platform:users.write",
                    &mut fx,
                    "Policy platform:users.write required to update user roles",
                ) && self.mode == Mode::Live
                {
                    self.fetch(
                        FetchKind::AuthUpdateUserRoles {
                            github_login,
                            bound_roles,
                        },
                        &mut fx,
                    );
                }
            }
            UiCommand::ResetUserPasskeys { github_login } => {
                if self.require_policy(
                    "platform:users.write",
                    &mut fx,
                    "Policy platform:users.write required to reset user passkeys",
                ) && self.mode == Mode::Live
                {
                    self.fetch(FetchKind::AuthResetUserPasskeys(github_login), &mut fx);
                }
            }
            UiCommand::RevokeUser { github_login } => {
                if self.require_policy(
                    "platform:users.write",
                    &mut fx,
                    "Policy platform:users.write required to revoke user bindings",
                ) && self.mode == Mode::Live
                {
                    self.fetch(FetchKind::AuthRevokeUser(github_login), &mut fx);
                }
            }
            UiCommand::UpsertRoleSpec(spec) => {
                if self.require_policy(
                    "platform:roles.write",
                    &mut fx,
                    "Policy platform:roles.write required to modify role specifications",
                ) && self.mode == Mode::Live
                {
                    self.fetch(FetchKind::AuthUpsertRole(spec), &mut fx);
                }
            }
            UiCommand::DeleteRoleSpec { role_id } => {
                if self.require_policy(
                    "platform:roles.write",
                    &mut fx,
                    "Policy platform:roles.write required to delete role specifications",
                ) && self.mode == Mode::Live
                {
                    self.fetch(FetchKind::AuthDeleteRole(role_id), &mut fx);
                }
            }
            UiCommand::UpsertPolicyFolio(folio) => {
                if self.require_policy(
                    "platform:folios.write",
                    &mut fx,
                    "Policy platform:folios.write required to modify policy folios",
                ) && self.mode == Mode::Live
                {
                    self.fetch(FetchKind::AuthUpsertFolio(folio), &mut fx);
                }
            }
            UiCommand::DeletePolicyFolio { folio_id } => {
                if self.require_policy(
                    "platform:folios.write",
                    &mut fx,
                    "Policy platform:folios.write required to delete policy folios",
                ) && self.mode == Mode::Live
                {
                    self.fetch(FetchKind::AuthDeleteFolio(folio_id), &mut fx);
                }
            }
            UiCommand::UpdateRoleFolioIndex(index) => {
                if self.require_policy(
                    "platform:folios.write",
                    &mut fx,
                    "Policy platform:folios.write required to update role-folio bindings",
                ) && self.mode == Mode::Live
                {
                    self.fetch(FetchKind::AuthUpdateRoleFolioIndex(index), &mut fx);
                }
            }
            UiCommand::LoadOlderObsLogs => {
                if self.mode == Mode::Live
                    && auth_has_policy(self.store.auth(), "obs:logs.read")
                    && self.store.can_load_older_obs_logs()
                {
                    if self.store.is_active_log_query() {
                        if self.store.has_buffered_older_search_logs() {
                            self.store.step_search_window_older(OBS_LOG_PAGE_SIZE);
                            self.flush_view_if_ready(now_ms, &mut fx);
                        } else if let (Some(query), Some(cursor)) = (
                            self.active_obs_log_query.clone(),
                            self.store.search_next_cursor(),
                        ) {
                            self.store.set_obs_loading_older(true);
                            let gen = self.obs_log_query_gen;
                            self.fetch(
                                FetchKind::ObsLogsQueryPage {
                                    query,
                                    before: Some(cursor),
                                    limit: OBS_LOG_PAGE_SIZE,
                                    gen,
                                },
                                &mut fx,
                            );
                        }
                    } else if let Some(before_key) = self.store.oldest_obs_log_key() {
                        self.store.set_obs_loading_older(true);
                        fx.push(Effect::ReadObsLogCacheOlder {
                            before_key,
                            limit: OBS_LOG_PAGE_SIZE,
                            gen: self.obs_log_query_gen,
                        });
                    }
                }
            }
            UiCommand::LoadNewerObsLogs => {
                if self.mode == Mode::Live
                    && auth_has_policy(self.store.auth(), "obs:logs.read")
                    && self.store.can_load_newer_obs_logs()
                {
                    if self.store.is_active_log_query() {
                        if self.store.can_step_search_window_newer() {
                            self.store.step_search_window_newer(OBS_LOG_PAGE_SIZE);
                            self.flush_view_if_ready(now_ms, &mut fx);
                        } else if let Some(query) = self.active_obs_log_query.clone() {
                            self.obs_log_query_gen = self.obs_log_query_gen.wrapping_add(1);
                            self.store.set_obs_loading_newer(true);
                            let gen = self.obs_log_query_gen;
                            self.fetch(
                                FetchKind::ObsLogsQueryPage {
                                    query,
                                    before: None,
                                    limit: OBS_LOG_PAGE_SIZE,
                                    gen,
                                },
                                &mut fx,
                            );
                        }
                    } else if let Some(after_key) = self.store.newest_obs_log_key() {
                        self.store.set_obs_loading_newer(true);
                        fx.push(Effect::ReadObsLogCacheNewer {
                            after_key,
                            limit: OBS_LOG_PAGE_SIZE,
                            gen: self.obs_log_query_gen,
                        });
                    }
                }
            }
            UiCommand::JumpToLatestObsLogs => {
                if self.mode == Mode::Live && auth_has_policy(self.store.auth(), "obs:logs.read") {
                    self.obs_log_query_gen = self.obs_log_query_gen.wrapping_add(1);
                    let gen = self.obs_log_query_gen;
                    self.store.set_obs_loading_older(false);
                    self.store.set_obs_loading_newer(false);
                    if self.store.is_active_log_query() {
                        if let Some(query) = self.active_obs_log_query.clone() {
                            self.fetch(
                                FetchKind::ObsLogsQueryPage {
                                    query,
                                    before: None,
                                    limit: OBS_LOG_PAGE_SIZE,
                                    gen,
                                },
                                &mut fx,
                            );
                        }
                    } else {
                        fx.push(Effect::ReadObsLogCacheLatest {
                            limit: OBS_LOG_WINDOW_CAPACITY,
                            gen,
                        });
                        self.fetch(FetchKind::ObsLogs, &mut fx);
                    }
                }
            }
        }
        fx
    }

    fn configure(&mut self, cfg: WorkerConfig, now_ms: u64, fx: &mut Vec<Effect>) {
        if self.mode != Mode::Idle {
            // Re-configuration: drop live streams before switching.
            for s in StreamId::ALL {
                if self.streams[s.index()].open {
                    fx.push(Effect::CloseStream(s));
                }
            }
            *self = Self::new(now_ms);
        }
        let scenario = match cfg.scenario.as_deref() {
            None => None,
            Some(name) => {
                let found = Scenario::from_name(name);
                if found.is_none() {
                    fx.push(Effect::Post(DataEvent::Error(UiError::UnknownScenario(
                        name.to_owned(),
                    ))));
                }
                found
            }
        };
        self.config = cfg;
        if let Some(sc) = scenario {
            self.mode = Mode::Scenario;
            let source = DataSource::Scenario(sc.name().to_owned());
            self.store = Store::new(source.clone());
            self.player = Some(ScenarioPlayer::new(sc, now_ms));
            fx.push(Effect::ClearObsLogCache);
            fx.push(Effect::Post(DataEvent::Ready {
                protocol: PROTOCOL_VERSION,
                source,
            }));
            let conn = if sc.is_offline() {
                ConnState::Offline
            } else {
                ConnState::Scenario
            };
            self.set_conn(conn, fx);
            self.play(now_ms);
        } else {
            self.mode = Mode::Live;
            self.config.scenario = None;
            fx.push(Effect::Post(DataEvent::Ready {
                protocol: PROTOCOL_VERSION,
                source: DataSource::Live,
            }));
            // Fail-closed cold boot (t = 0): hold all non-auth REST fetches,
            // LoadOffline, and SSE streams until /api/auth/session resolves.
            self.set_conn(ConnState::Connecting, fx);
            self.fetch(FetchKind::AuthSession, fx);
        }
    }

    fn retry(&mut self, now_ms: u64, fx: &mut Vec<Effect>) {
        match self.mode {
            Mode::Idle => {}
            Mode::Scenario => {
                if let Some(p) = self.player.as_mut() {
                    let sc = p.scenario();
                    p.restart(now_ms);
                    self.store = Store::new(DataSource::Scenario(sc.name().to_owned()));
                    self.out.force_snapshot();
                    self.play(now_ms);
                }
            }
            Mode::Live => {
                self.fetch(FetchKind::AuthSession, fx);
                if !self.store.can_emit_operational_data() {
                    return;
                }
                for s in StreamId::ALL {
                    let can_open = self.can_open_stream(s);
                    let st = &mut self.streams[s.index()];
                    st.backoff.reset();
                    st.opened_at = None;
                    if can_open && !st.open {
                        st.reconnect_at = None;
                        self.open_stream(s, fx);
                    }
                }
                self.fetch_permitted_bootstrap(fx);
                self.fetch_selection(fx);
                if let Some(sv) = self.active_subview {
                    if !matches!(
                        sv,
                        SubView::Ci(
                            CiSubView::Trainway | CiSubView::Scorecards | CiSubView::WorkerNodes
                        ) | SubView::Observability(
                            ObservabilitySubView::Logs | ObservabilitySubView::DataStore
                        ) | SubView::Repository(_)
                    ) {
                        self.fetch_subview(sv, None, fx);
                    }
                }
            }
        }
    }

    fn fetch_permitted_bootstrap(&mut self, fx: &mut Vec<Effect>) {
        for kind in [
            FetchKind::ObsSubsystemStatus,
            FetchKind::Repos,
            FetchKind::ClusterNodes,
            FetchKind::CiQueue,
            FetchKind::ObsLogs,
            FetchKind::ObsStoreStatus,
            FetchKind::RegPackages,
            FetchKind::RegCanaries,
            FetchKind::RegCasStatus,
        ] {
            self.fetch(kind, fx);
        }
    }

    fn fetch_obs_logs_or_sanitized_query(&mut self, filter: Option<&str>, fx: &mut Vec<Effect>) {
        if let Some(q) = filter
            .map(sanitize_obs_log_search_query)
            .filter(|s| !s.is_empty())
        {
            if self.active_obs_log_query.as_deref() != Some(q.as_str()) {
                self.obs_log_query_gen = self.obs_log_query_gen.wrapping_add(1);
                self.active_obs_log_query = Some(q.clone());
            }
            self.fetch(
                FetchKind::ObsLogsQueryPage {
                    query: q,
                    before: None,
                    limit: OBS_LOG_PAGE_SIZE,
                    gen: self.obs_log_query_gen,
                },
                fx,
            );
        } else {
            if self.active_obs_log_query.is_some() {
                self.obs_log_query_gen = self.obs_log_query_gen.wrapping_add(1);
                self.active_obs_log_query = None;
            }
            self.store.clear_active_log_query();
            if auth_has_policy(self.store.auth(), "obs:logs.read") {
                self.fetch(FetchKind::ObsLogs, fx);
            }
        }
    }

    fn fetch_subview(&mut self, subview: SubView, filter: Option<&str>, fx: &mut Vec<Effect>) {
        match subview {
            SubView::Dashboard(_) => {
                self.fetch(FetchKind::ObsSubsystemStatus, fx);
                self.fetch(FetchKind::Repos, fx);
            }
            SubView::Ci(CiSubView::Scorecards | CiSubView::Trainway) => {
                self.fetch_selection(fx);
                self.fetch(FetchKind::CiQueue, fx);
            }
            SubView::Ci(CiSubView::QueueLogs) => {
                self.fetch(FetchKind::CiQueue, fx);
                self.fetch_obs_logs_or_sanitized_query(filter, fx);
                if let Some(job_id) = self
                    .selected_job_id
                    .or_else(|| self.store.view().ci_jobs.first().map(|j| j.job_id))
                {
                    self.fetch(FetchKind::JobDetail(job_id), fx);
                    self.fetch_active_job_log(job_id, fx);
                }
            }
            SubView::Ci(CiSubView::WorkerNodes) => {
                self.fetch(FetchKind::ClusterNodes, fx);
                self.fetch(FetchKind::CiQueue, fx);
            }
            SubView::Ci(CiSubView::SandboxProfiles) => {
                self.fetch(FetchKind::Repos, fx);
            }
            SubView::Cd(cd_sv) => {
                if let Some(repo) = self
                    .store
                    .selection()
                    .map(|s| s.repo.clone())
                    .or_else(|| self.store.repo_ids().next().cloned())
                {
                    self.fetch(
                        FetchKind::CdRuns {
                            repo,
                            ecosystem: None,
                            limit: 25,
                        },
                        fx,
                    );
                }
                if cd_sv == CdSubView::Pipelines {
                    self.fetch_selection(fx);
                }
            }
            SubView::AbDeploy(
                AbDeploySubView::IntegrationGate
                | AbDeploySubView::DeploymentsSlots
                | AbDeploySubView::GateTestLogs,
            ) => {
                self.fetch_selection(fx);
                self.fetch(FetchKind::RegCanaries, fx);
            }
            SubView::AbDeploy(AbDeploySubView::ActiveLeases) => {
                self.fetch(FetchKind::Leases, fx);
                self.fetch(FetchKind::RegCanaries, fx);
            }
            SubView::Repository(RepositorySubView::Packages) => {
                self.fetch(FetchKind::RegPackages, fx);
            }
            SubView::Repository(RepositorySubView::CanaryTaints) => {
                self.fetch(FetchKind::RegCanaries, fx);
            }
            SubView::Repository(RepositorySubView::CasHealth) => {
                self.fetch(FetchKind::RegCasStatus, fx);
            }
            SubView::Observability(ObservabilitySubView::Smartscape) => {
                self.fetch(FetchKind::ObsSmartscape, fx);
            }
            SubView::Observability(ObservabilitySubView::PurePath) => {
                self.fetch(FetchKind::CiQueue, fx);
                self.fetch(FetchKind::ObsTraces, fx);
            }
            SubView::Observability(ObservabilitySubView::ProblemsSlos) => {
                self.fetch(FetchKind::ObsProblems, fx);
            }
            SubView::Observability(ObservabilitySubView::Logs) => {
                self.fetch(FetchKind::CiQueue, fx);
                self.fetch_obs_logs_or_sanitized_query(filter, fx);
            }
            SubView::Observability(ObservabilitySubView::Metrics) => {
                self.fetch(FetchKind::ObsMetrics, fx);
            }
            SubView::Observability(ObservabilitySubView::DataStore) => {
                self.fetch(FetchKind::ObsStoreStatus, fx);
            }
            SubView::Observability(ObservabilitySubView::Ingress) => {
                self.fetch(FetchKind::ObsIngressOverview, fx);
                self.fetch(FetchKind::ObsIngressRoutes, fx);
                self.fetch(FetchKind::ObsIngressUpstreams, fx);
            }
            SubView::ModelRunner(ModelRunnerSubView::RuntimeQueue) => {
                self.fetch(FetchKind::MrStatus, fx);
            }
            SubView::ModelRunner(ModelRunnerSubView::ConnectionVpn) => {
                self.fetch(FetchKind::MrConnection, fx);
            }
            SubView::Platform(PlatformSubView::Maintenance) => {
                self.fetch(FetchKind::ObsSubsystemStatus, fx);
            }
            SubView::Platform(PlatformSubView::UsersAndInvites) => {
                self.fetch(FetchKind::AuthUsers, fx);
                self.fetch(FetchKind::AuthInvites, fx);
                self.fetch(FetchKind::AuthRoles, fx);
            }
            SubView::Platform(PlatformSubView::RolesAndFolios) => {
                self.fetch(FetchKind::AuthRoles, fx);
                self.fetch(FetchKind::AuthFolios, fx);
                self.fetch(FetchKind::AuthRoleFolioIndex, fx);
            }
        }
    }

    fn dispatch_role_action(
        &mut self,
        kind: FetchKind,
        err_msg: &str,
        now_ms: u64,
        fx: &mut Vec<Effect>,
    ) {
        if self.require_active_auth(fx, err_msg) {
            self.store.apply(Input::SessionRolesError(None), now_ms);
            if self.mode == Mode::Live {
                self.fetch(kind, fx);
            }
        } else {
            self.store
                .apply(Input::SessionRolesError(Some(err_msg.to_owned())), now_ms);
        }
    }

    fn require_active_auth(&self, fx: &mut Vec<Effect>, msg: &str) -> bool {
        if self.store.auth().status == AuthStatus::Active {
            true
        } else {
            deny_403(fx, msg);
            false
        }
    }

    fn require_policy(&self, policy: &str, fx: &mut Vec<Effect>, msg: &str) -> bool {
        if self.store.can_emit_operational_data() && auth_has_policy(self.store.auth(), policy) {
            true
        } else {
            deny_403(fx, msg);
            false
        }
    }

    fn can_fetch(&self, kind: &FetchKind) -> bool {
        can_fetch_for_auth(
            self.store.can_emit_operational_data(),
            self.store.auth().status,
            self.store.auth(),
            kind,
        )
    }

    fn can_open_stream(&self, s: StreamId) -> bool {
        if !self.store.can_emit_operational_data() {
            return false;
        }
        let auth = self.store.auth();
        match s {
            StreamId::Ci => auth_can_access_area(auth, Area::Ci),
            StreamId::Cd => {
                auth_can_access_area(auth, Area::Cd) || auth_can_access_area(auth, Area::AbDeploy)
            }
            StreamId::Obs => {
                auth_can_access_area(auth, Area::Observability)
                    || auth_has_policy(auth, "system:status.read")
                    || auth_has_policy(auth, "system:dashboard.read")
                    || auth_has_policy(auth, "platform:maintenance.read")
            }
        }
    }

    fn close_disallowed_streams(&mut self, fx: &mut Vec<Effect>) {
        for s in StreamId::ALL {
            if !self.can_open_stream(s) {
                let st = &mut self.streams[s.index()];
                st.reconnect_at = None;
                st.opened_at = None;
                if st.open {
                    st.open = false;
                    fx.push(Effect::CloseStream(s));
                }
            }
        }
    }

    fn on_auth_transition(
        &mut self,
        prev_allowed: bool,
        prev_policies: &[String],
        now_ms: u64,
        fx: &mut Vec<Effect>,
    ) {
        if self.store.take_force_snapshot() {
            self.out.force_snapshot();
        }
        let current_login = self
            .store
            .auth()
            .github_login
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        let can_cache_obs = self.store.can_cache_obs_logs();
        let user_switched = matches!(
            (&self.last_auth_login, &current_login),
            (Some(prev), Some(curr)) if prev != curr
        ) || (self.last_auth_login.is_some() && current_login.is_none());
        if self.mode == Mode::Live && (!can_cache_obs || user_switched) {
            self.obs_log_query_gen = self.obs_log_query_gen.wrapping_add(1);
            fx.push(Effect::ClearObsLogCache);
        }
        self.last_auth_login = if can_cache_obs { current_login } else { None };
        if !self.store.can_emit_operational_data() {
            self.close_disallowed_streams(fx);
            if self.mode == Mode::Live {
                self.update_conn(now_ms, fx);
            }
            return;
        }
        self.close_disallowed_streams(fx);
        if self.mode != Mode::Live {
            return;
        }
        if self.store.can_cache_offline() && !self.offline_requested && !self.store.has_live_data()
        {
            self.offline_requested = true;
            fx.push(Effect::LoadOffline);
        }
        if can_cache_obs && (!prev_allowed || !prev_policies.iter().any(|p| p == "obs:logs.read")) {
            fx.push(Effect::ReadObsLogCacheLatest {
                limit: OBS_LOG_WINDOW_CAPACITY,
                gen: self.obs_log_query_gen,
            });
        }
        for s in StreamId::ALL {
            if self.can_open_stream(s) && !self.streams[s.index()].open {
                let st = &mut self.streams[s.index()];
                st.backoff.reset();
                st.opened_at = None;
                self.open_stream(s, fx);
            }
        }
        let gained_policy = |p: &str| !prev_allowed || !prev_policies.iter().any(|x| x == p);
        let bootstrap: [(&[&str], FetchKind); 9] = [
            (
                &[
                    "system:status.read",
                    "system:dashboard.read",
                    "platform:maintenance.read",
                ],
                FetchKind::ObsSubsystemStatus,
            ),
            (
                &["ci:repos.public.read", "ci:repos.private.read"],
                FetchKind::Repos,
            ),
            (&["ci:nodes.read"], FetchKind::ClusterNodes),
            (&["ci:queue.read", "ci:jobs.read"], FetchKind::CiQueue),
            (&["obs:logs.read"], FetchKind::ObsLogs),
            (&["obs:store.read"], FetchKind::ObsStoreStatus),
            (&["reg:packages.read"], FetchKind::RegPackages),
            (
                &["reg:canaries.read", "reg:taints.read"],
                FetchKind::RegCanaries,
            ),
            (&["reg:cas.read"], FetchKind::RegCasStatus),
        ];
        for (policies, kind) in bootstrap {
            if self.can_fetch(&kind)
                && policies
                    .iter()
                    .any(|p| auth_has_policy(self.store.auth(), p) && gained_policy(p))
            {
                self.fetch(kind, fx);
            }
        }
        let gained_any = !prev_allowed
            || self
                .store
                .auth()
                .active_policies
                .iter()
                .any(|p| !prev_policies.iter().any(|x| x == p));
        if gained_any {
            self.fetch_selection(fx);
        }
        if let Some(sv) = self.active_subview {
            if !matches!(
                sv,
                SubView::Ci(CiSubView::Trainway | CiSubView::Scorecards | CiSubView::WorkerNodes)
                    | SubView::Observability(
                        ObservabilitySubView::Logs | ObservabilitySubView::DataStore
                    )
                    | SubView::Repository(_)
            ) && gained_any
            {
                self.fetch_subview(sv, None, fx);
            }
        }
        self.update_conn(now_ms, fx);
    }

    fn select(&mut self, sel: Selection, now_ms: u64, fx: &mut Vec<Effect>) {
        self.pending_select = None;
        if self.store.apply(Input::Select(sel.clone()), now_ms) {
            self.selection_gen = self.selection_gen.wrapping_add(1);
        }
        if self.mode == Mode::Live {
            self.fetch_selection(fx);
            if matches!(self.active_subview, Some(SubView::Cd(_))) {
                self.fetch(
                    FetchKind::CdRuns {
                        repo: sel.repo,
                        ecosystem: None,
                        limit: 25,
                    },
                    fx,
                );
            }
        }
    }

    fn fetch_selection(&mut self, fx: &mut Vec<Effect>) {
        let Some(sel) = self.store.selection().cloned() else {
            return;
        };
        if let Some(topo_repo) = self.store.topology_repo() {
            self.fetch(FetchKind::Topology(topo_repo), fx);
        }
        self.fetch(FetchKind::Summary(sel.repo.clone()), fx);
        self.fetch(FetchKind::Deployments(sel.repo), fx);
    }

    fn fetch(&self, kind: FetchKind, fx: &mut Vec<Effect>) {
        if !self.can_fetch(&kind) {
            return;
        }
        let path = match &kind {
            FetchKind::Repos => paths::REPOS.to_owned(),
            FetchKind::ClusterNodes => paths::CLUSTER_NODES.to_owned(),
            FetchKind::CiQueue => paths::CI_QUEUE.to_owned(),
            FetchKind::Summary(r) => paths::summary(&r.owner, &r.repo),
            FetchKind::Topology(r) => paths::topology(&r.owner, &r.repo),
            FetchKind::Deployments(r) => paths::deployments(&r.owner, &r.repo, HISTORY_LIMIT),
            FetchKind::CdRuns {
                repo,
                ecosystem,
                limit,
            } => {
                if repo.owner.is_empty() || repo.repo.is_empty() {
                    paths::CD_RUNS.to_owned()
                } else {
                    paths::cd_runs(&repo.owner, &repo.repo, ecosystem.as_deref(), *limit)
                }
            }
            FetchKind::Gate(id) => paths::gate(id),
            FetchKind::Leases => paths::LEASES.to_owned(),
            FetchKind::AbRollback { deployment_id, .. } => paths::ab_rollback(deployment_id),
            FetchKind::RegPackages => paths::REG_PACKAGES.to_owned(),
            FetchKind::RegCanaries => paths::REG_CANARIES.to_owned(),
            FetchKind::RegCasStatus => paths::REG_CAS_STATUS.to_owned(),
            FetchKind::ObsSmartscape => paths::OBS_SMARTSCAPE.to_owned(),
            FetchKind::ObsProblems => paths::OBS_PROBLEMS.to_owned(),
            FetchKind::ObsTraces => paths::OBS_TRACES.to_owned(),
            FetchKind::ObsTraceDetail(id) => paths::obs_trace(id),
            FetchKind::ObsLogs => paths::obs_logs_page(None, OBS_LOG_PAGE_SIZE),
            FetchKind::ObsLogsOlder { before, limit, .. } => {
                paths::obs_logs_page(Some(before), *limit)
            }
            FetchKind::ObsMetrics => paths::OBS_METRICS.to_owned(),
            FetchKind::ObsStoreStatus => paths::OBS_STORE_STATUS.to_owned(),
            FetchKind::ObsSubsystemStatus => paths::OBS_SUBSYSTEM_STATUS.to_owned(),
            FetchKind::SetSubsystemMaintenance { subsystem, .. } => {
                paths::subsystem_maintenance(*subsystem)
            }
            FetchKind::ObsIngressOverview => paths::OBS_INGRESS_OVERVIEW.to_owned(),
            FetchKind::ObsIngressRoutes => paths::OBS_INGRESS_ROUTES.to_owned(),
            FetchKind::ObsIngressUpstreams => paths::OBS_INGRESS_UPSTREAMS.to_owned(),
            FetchKind::ObsLogsQuery(q) => paths::obs_logs_query(q, OBS_LOG_PAGE_SIZE),
            FetchKind::ObsLogsQueryPage {
                query,
                before,
                limit,
                ..
            } => paths::obs_logs_query_page(query, before.as_deref(), *limit),
            FetchKind::MrStatus => paths::MR_STATUS.to_owned(),
            FetchKind::MrConnection => paths::MR_CONNECTION.to_owned(),
            FetchKind::AuthSession => paths::AUTH_SESSION.to_owned(),
            FetchKind::AuthRedeem(_) => paths::AUTH_REDEEM.to_owned(),
            FetchKind::AuthProfile | FetchKind::AuthProfilePut { .. } => {
                paths::AUTH_PROFILE.to_owned()
            }
            FetchKind::AuthPasskeys => paths::AUTH_PASSKEYS.to_owned(),
            FetchKind::AuthPasskeyRegisterFinish { .. } => {
                paths::AUTH_PASSKEYS_REGISTER_FINISH.to_owned()
            }
            FetchKind::AuthPasskeyDelete { credential_id, .. } => {
                paths::auth_passkey(credential_id)
            }
            FetchKind::AuthEnableRole(role_id) => paths::role_enable(role_id),
            FetchKind::AuthDisableRole(role_id) => paths::role_disable(role_id),
            FetchKind::AuthElevateFinish { .. } => paths::AUTH_ELEVATE_FINISH.to_owned(),
            FetchKind::AuthRenewRole { role_id, .. } => paths::role_renew(role_id),
            FetchKind::AuthLockRoles => paths::AUTH_ROLE_LOCK.to_owned(),
            FetchKind::AuthActivity => paths::AUTH_ACTIVITY.to_owned(),
            FetchKind::AuthRoles | FetchKind::AuthUpsertRole(_) => paths::AUTH_ROLES.to_owned(),
            FetchKind::AuthDeleteRole(role_id) => format!("{}/{role_id}", paths::AUTH_ROLES),
            FetchKind::AuthFolios | FetchKind::AuthUpsertFolio(_) => paths::AUTH_FOLIOS.to_owned(),
            FetchKind::AuthDeleteFolio(folio_id) => format!("{}/{folio_id}", paths::AUTH_FOLIOS),
            FetchKind::AuthRoleFolioIndex | FetchKind::AuthUpdateRoleFolioIndex(_) => {
                paths::AUTH_ROLE_FOLIO_INDEX.to_owned()
            }
            FetchKind::AuthUsers => paths::AUTH_USERS.to_owned(),
            FetchKind::AuthUpdateUserRoles { github_login, .. } => {
                paths::auth_user_roles(github_login)
            }
            FetchKind::AuthResetUserPasskeys(login) => paths::auth_user_passkeys_reset(login),
            FetchKind::AuthRevokeUser(login) => paths::auth_user(login),
            FetchKind::AuthInvites | FetchKind::AuthCreateInvite { .. } => {
                paths::AUTH_INVITES.to_owned()
            }
            FetchKind::AuthRevokeInvite(invite_id) => paths::auth_invite(invite_id),
            FetchKind::RestartJob(job_id) => {
                paths::job_restart_id(&self.store.resolve_job_id_str(*job_id))
            }
            FetchKind::ResumeJob(job_id) => {
                paths::job_resume_id(&self.store.resolve_job_id_str(*job_id))
            }
            FetchKind::JobDetail(job_id) => {
                paths::job_detail_id(&self.store.resolve_job_id_str(*job_id))
            }
            FetchKind::JobLog(job_id) => paths::job_log_id(&self.store.resolve_job_id_str(*job_id)),
        };
        fx.push(Effect::Fetch {
            kind,
            url: self.config.url(&path),
        });
    }

    fn fetch_obs_job_log(&self, job_id: u64, fx: &mut Vec<Effect>) {
        if !self.store.can_emit_operational_data()
            || !auth_has_policy(self.store.auth(), "obs:logs.read")
        {
            return;
        }
        let jid = self.store.resolve_job_id_str(job_id);
        let path = paths::job_obs_log_id(&jid);
        fx.push(Effect::Fetch {
            kind: FetchKind::JobLog(job_id),
            url: self.config.url(&path),
        });
    }

    fn fetch_active_job_log(&self, job_id: u64, fx: &mut Vec<Effect>) {
        if auth_has_policy(self.store.auth(), "ci:jobs.logs.read") {
            self.fetch(FetchKind::JobLog(job_id), fx);
        } else if auth_has_policy(self.store.auth(), "obs:logs.read") {
            self.fetch_obs_job_log(job_id, fx);
        }
    }

    fn open_stream(&mut self, s: StreamId, fx: &mut Vec<Effect>) {
        if !self.can_open_stream(s) {
            return;
        }
        let path = match s {
            StreamId::Ci => paths::CI_EVENTS,
            StreamId::Cd => paths::CD_EVENTS,
            StreamId::Obs => paths::OBS_EVENTS,
        };
        let st = &mut self.streams[s.index()];
        st.parser.reset_connection();
        st.reconnect_at = None;
        st.opened_at = None;
        fx.push(Effect::OpenStream {
            stream: s,
            url: self.config.url(path),
            last_event_id: st.parser.last_event_id().map(str::to_owned),
        });
    }

    fn set_conn(&mut self, state: ConnState, fx: &mut Vec<Effect>) {
        if self.conn != Some(state) {
            self.conn = Some(state);
            fx.push(Effect::Post(DataEvent::Connection(state)));
        }
    }

    /// Connection state ignoring visibility.
    fn resting_conn(&self, now_ms: u64) -> ConnState {
        match self.mode {
            Mode::Idle => ConnState::Connecting,
            Mode::Scenario => {
                if self
                    .player
                    .as_ref()
                    .is_some_and(|p| p.scenario().is_offline())
                {
                    ConnState::Offline
                } else {
                    ConnState::Scenario
                }
            }
            Mode::Live => {
                if !self.store.auth().is_resolved() {
                    return ConnState::Connecting;
                }
                let permitted: Vec<StreamId> = StreamId::ALL
                    .into_iter()
                    .filter(|&s| self.can_open_stream(s))
                    .collect();
                if permitted.is_empty() {
                    return ConnState::Live;
                }
                let ci_perm = permitted.contains(&StreamId::Ci);
                let cd_perm = permitted.contains(&StreamId::Cd);
                let obs_open =
                    permitted.contains(&StreamId::Obs) && self.streams[StreamId::Obs.index()].open;
                let ci = &self.streams[StreamId::Ci.index()];
                let cd = &self.streams[StreamId::Cd.index()];
                if obs_open
                    || (ci_perm
                        && cd_perm
                        && ((ci.open && (cd.open || cd.backoff.attempt() > 0))
                            || (cd.open && (ci.open || ci.backoff.attempt() > 0))))
                    || (!(ci_perm && cd_perm)
                        && permitted.iter().any(|&s| self.streams[s.index()].open))
                {
                    return ConnState::Live;
                }
                let worst = permitted
                    .iter()
                    .map(|&s| &self.streams[s.index()])
                    .filter(|s| !s.open)
                    .map(|s| s.backoff.attempt())
                    .max();
                match worst {
                    None => ConnState::Live,
                    Some(0) => ConnState::Connecting,
                    Some(a) if a >= OFFLINE_AFTER_ATTEMPTS && !self.store.has_live_data() => {
                        ConnState::Offline
                    }
                    Some(a) => ConnState::Reconnecting {
                        attempt: a,
                        retry_in_ms: permitted
                            .iter()
                            .filter_map(|&s| self.streams[s.index()].reconnect_at)
                            .min()
                            .map_or(0, |t| {
                                u32::try_from(t.saturating_sub(now_ms)).unwrap_or(u32::MAX)
                            }),
                    },
                }
            }
        }
    }

    fn update_conn(&mut self, now_ms: u64, fx: &mut Vec<Effect>) {
        if self.out.is_hidden() {
            return;
        }
        let state = self.resting_conn(now_ms);
        self.set_conn(state, fx);
    }

    /// Generation-checked REST response; drops selection-scoped responses
    /// whose generation token is older than [`Self::selection_gen`].
    pub fn on_fetch_gen(
        &mut self,
        gen: u64,
        kind: &FetchKind,
        result: Result<String, HttpError>,
        now_ms: u64,
    ) -> Vec<Effect> {
        let is_selection_scoped = matches!(
            kind,
            FetchKind::Summary(_)
                | FetchKind::Topology(_)
                | FetchKind::Deployments(_)
                | FetchKind::CdRuns { .. }
                | FetchKind::Gate(_)
        );
        if is_selection_scoped && gen != self.selection_gen {
            return Vec::new();
        }
        self.on_fetch(kind, result, now_ms)
    }

    /// REST response (`Ok(body)`) or failure.
    pub fn on_fetch(
        &mut self,
        kind: &FetchKind,
        result: Result<String, HttpError>,
        now_ms: u64,
    ) -> Vec<Effect> {
        let mut fx = Vec::new();
        if self.mode != Mode::Live {
            return fx;
        }
        let is_stale_obs_query = match kind {
            FetchKind::ObsLogsOlder { gen, .. } | FetchKind::ObsLogsQueryPage { gen, .. } => {
                *gen != self.obs_log_query_gen
            }
            _ => false,
        };
        if is_stale_obs_query {
            return fx;
        }
        let body = match result {
            Ok(b) => b,
            Err(e) => {
                match kind {
                    FetchKind::ObsLogsOlder { .. } => self.store.set_obs_loading_older(false),
                    FetchKind::ObsLogsQueryPage { .. } => {
                        self.store.apply_search_logs_error();
                    }
                    _ => {}
                }
                // Non-fatal 404/502/503 on optional auxiliary daemon probes.
                // `FetchKind::AuthSession` is excluded so cold-boot auth probe failures
                // always surface `DataEvent::Error` instead of leaving the UI stuck.
                let is_optional_probe = matches!(
                    kind,
                    FetchKind::Deployments(_)
                        | FetchKind::CdRuns { .. }
                        | FetchKind::Gate(_)
                        | FetchKind::Leases
                        | FetchKind::ClusterNodes
                        | FetchKind::CiQueue
                        | FetchKind::AuthProfile
                        | FetchKind::AuthProfilePut { .. }
                        | FetchKind::AuthPasskeys
                        | FetchKind::AuthActivity
                        | FetchKind::AuthRoles
                        | FetchKind::AuthFolios
                        | FetchKind::AuthRoleFolioIndex
                        | FetchKind::AuthUsers
                        | FetchKind::AuthInvites
                        | FetchKind::RegPackages
                        | FetchKind::RegCanaries
                        | FetchKind::RegCasStatus
                        | FetchKind::ObsSmartscape
                        | FetchKind::ObsProblems
                        | FetchKind::ObsTraces
                        | FetchKind::ObsTraceDetail(_)
                        | FetchKind::ObsLogs
                        | FetchKind::ObsLogsOlder { .. }
                        | FetchKind::ObsLogsQueryPage { .. }
                        | FetchKind::ObsMetrics
                        | FetchKind::ObsStoreStatus
                        | FetchKind::ObsSubsystemStatus
                        | FetchKind::ObsIngressOverview
                        | FetchKind::ObsIngressRoutes
                        | FetchKind::ObsIngressUpstreams
                        | FetchKind::MrStatus
                        | FetchKind::MrConnection
                        | FetchKind::RestartJob(_)
                        | FetchKind::ResumeJob(_)
                        | FetchKind::JobDetail(_)
                        | FetchKind::JobLog(_)
                );
                if let FetchKind::JobLog(job_id) = kind {
                    if matches!(e.status, 401 | 403)
                        && auth_has_policy(self.store.auth(), "obs:logs.read")
                        && self.fallback_job_logs.insert(*job_id)
                    {
                        self.fetch_obs_job_log(*job_id, &mut fx);
                        return fx;
                    }
                }
                let is_auth_gated_log =
                    matches!(kind, FetchKind::JobLog(_)) && matches!(e.status, 401 | 403);
                if !((is_optional_probe && matches!(e.status, 404 | 502 | 503))
                    || is_auth_gated_log)
                {
                    if is_session_role_mutation(kind) {
                        let inline_err = format_role_action_http_error(e.status, &e.message);
                        self.store
                            .apply(Input::SessionRolesError(Some(inline_err)), now_ms);
                    }
                    let message = if matches!(kind, FetchKind::AuthSession) {
                        let trimmed = e.message.trim();
                        if trimmed.is_empty() {
                            "GET /api/auth/session".to_owned()
                        } else if trimmed.contains("/api/auth/session") {
                            trimmed.to_owned()
                        } else {
                            format!("GET /api/auth/session: {trimmed}")
                        }
                    } else {
                        e.message
                    };
                    fx.push(Effect::Post(DataEvent::Error(UiError::Http {
                        status: e.status,
                        message,
                    })));
                }
                if matches!(kind, FetchKind::ObsLogsQueryPage { .. }) {
                    self.flush_view_if_ready(now_ms, &mut fx);
                }
                return fx;
            }
        };
        let input = match parse_fetch(kind, &body) {
            Ok(i) => i,
            Err(msg) => {
                match kind {
                    FetchKind::ObsLogsOlder { .. } => self.store.set_obs_loading_older(false),
                    FetchKind::ObsLogsQueryPage { .. } => {
                        self.store.apply_search_logs_error();
                    }
                    _ => {}
                }
                if is_session_role_mutation(kind) {
                    let inline_err = crate::api::extract_http_error_message(&msg, Some(&body));
                    self.store
                        .apply(Input::SessionRolesError(Some(inline_err)), now_ms);
                }
                fx.push(Effect::Post(DataEvent::Error(UiError::Decode(msg))));
                if matches!(kind, FetchKind::ObsLogsQueryPage { .. }) {
                    self.flush_view_if_ready(now_ms, &mut fx);
                }
                return fx;
            }
        };
        let is_auth_kind = is_session_role_mutation(kind)
            || matches!(
                kind,
                FetchKind::AuthSession
                    | FetchKind::AuthRedeem(_)
                    | FetchKind::AuthPasskeyRegisterFinish { .. }
                    | FetchKind::AuthPasskeyDelete { .. }
            );
        let prev_allowed = self.store.can_emit_operational_data();
        let prev_policies = if is_auth_kind {
            self.store.auth().active_policies.clone()
        } else {
            Vec::new()
        };
        self.store.apply(input, now_ms);
        let to_cache = self.store.take_pending_cache_obs_logs();
        if !to_cache.is_empty() && self.store.can_cache_obs_logs() {
            fx.push(Effect::CacheObsLogs(to_cache));
        }
        if is_session_role_mutation(kind) {
            self.store.apply(Input::CloseSessionRolesDialog, now_ms);
        }
        if is_auth_kind {
            self.on_auth_transition(prev_allowed, &prev_policies, now_ms, &mut fx);
        }
        match kind {
            FetchKind::Repos => {
                let first = self.store.repo_ids().next().cloned();
                if self.store.selection().is_none() {
                    if let Some(first) = first {
                        self.select(
                            Selection {
                                repo: first,
                                submodule: None,
                            },
                            now_ms,
                            &mut fx,
                        );
                    }
                }
                self.update_conn(now_ms, &mut fx);
            }
            FetchKind::CiQueue => {
                let first_job = self
                    .store
                    .view()
                    .ci_jobs
                    .first()
                    .filter(|j| j.raw_log_lines.is_empty())
                    .map(|j| j.job_id);
                if let Some(job_id) = first_job {
                    self.asked_job_details.insert(job_id);
                    self.fetch(FetchKind::JobDetail(job_id), &mut fx);
                    self.fetch_active_job_log(job_id, &mut fx);
                }
            }
            FetchKind::Summary(repo) | FetchKind::Topology(repo) => {
                if let Some(job_id) = self.store.repo_latest_job(repo) {
                    if job_id > 0 && self.asked_job_details.insert(job_id) {
                        self.fetch(FetchKind::JobDetail(job_id), &mut fx);
                        self.fetch_active_job_log(job_id, &mut fx);
                    }
                }
            }
            FetchKind::Deployments(repo) => self.fetch_latest_gate(repo, &mut fx),
            FetchKind::AbRollback { .. } => {
                if let Some(sel) = self.store.selection().cloned() {
                    self.fetch(FetchKind::Deployments(sel.repo), &mut fx);
                }
                self.fetch(FetchKind::Leases, &mut fx);
                self.fetch(FetchKind::RegCanaries, &mut fx);
            }
            FetchKind::SetSubsystemMaintenance { .. } => {
                self.fetch(FetchKind::ObsSubsystemStatus, &mut fx);
            }
            FetchKind::AuthPasskeyRegisterFinish { .. } | FetchKind::AuthPasskeyDelete { .. } => {
                self.fetch(FetchKind::AuthSession, &mut fx);
                self.fetch(FetchKind::AuthPasskeys, &mut fx);
            }
            FetchKind::AuthCreateInvite { .. } | FetchKind::AuthRevokeInvite(_) => {
                self.fetch(FetchKind::AuthInvites, &mut fx);
            }
            FetchKind::AuthUpdateUserRoles { .. }
            | FetchKind::AuthResetUserPasskeys(_)
            | FetchKind::AuthRevokeUser(_) => {
                self.fetch(FetchKind::AuthUsers, &mut fx);
            }
            FetchKind::AuthUpdateRoleFolioIndex(_) => {
                self.fetch(FetchKind::AuthSession, &mut fx);
            }
            FetchKind::ObsTraces => {
                let first_empty_tid = self
                    .store
                    .view()
                    .observe
                    .traces
                    .iter()
                    .find(|t| t.spans.is_empty())
                    .map(|t| t.trace_id.clone());
                if let Some(tid) = first_empty_tid {
                    self.fetch(FetchKind::ObsTraceDetail(tid), &mut fx);
                }
            }
            _ => {}
        }
        fx
    }

    /// A CD event named a deployment whose gate is not loaded: a new
    /// deployment started, so refresh the selected repo's history (once per
    /// id).
    fn on_unknown_deployment(&mut self, id: String, fx: &mut Vec<Effect>) {
        if !self.asked_deployments.insert(id) {
            return;
        }
        if let Some(sel) = self.store.selection().cloned() {
            self.fetch(FetchKind::Deployments(sel.repo), fx);
        }
    }

    fn fetch_latest_gate(&self, repo: &RepoId, fx: &mut Vec<Effect>) {
        if let Some(id) = self.store.latest_deployment(repo) {
            if !self.store.has_gate(id) {
                self.fetch(FetchKind::Gate(id.to_owned()), fx);
            }
        }
    }

    /// The stream's response headers arrived with a 2xx status.
    pub fn on_stream_open(&mut self, s: StreamId, now_ms: u64) -> Vec<Effect> {
        let mut fx = Vec::new();
        let st = &mut self.streams[s.index()];
        st.open = true;
        st.opened_at = Some(now_ms);
        st.reconnect_at = None;
        self.update_conn(now_ms, &mut fx);
        fx
    }

    /// A body chunk from an open stream.
    pub fn on_stream_chunk(&mut self, s: StreamId, chunk: &[u8], now_ms: u64) -> Vec<Effect> {
        let mut fx = Vec::new();
        let st = &mut self.streams[s.index()];
        let events = st.parser.feed(chunk);
        let retry = st.parser.retry_ms();
        st.backoff.set_server_retry(retry);
        for ev in events {
            match parse_event(s, &ev.event, &ev.data) {
                Ok(Some(input)) => {
                    let unknown = deployment_of(&input)
                        .filter(|id| !self.store.has_gate(id))
                        .map(str::to_owned);
                    let stage_changed = match &input {
                        Input::JobStageChanged(e) => {
                            Some((RepoId::new(&e.owner, &e.repo), e.job_id))
                        }
                        _ => None,
                    };
                    let is_ingress_changed = matches!(&input, Input::ObsIngressChanged);
                    self.store.apply(input, now_ms);
                    let to_cache = self.store.take_pending_cache_obs_logs();
                    if !to_cache.is_empty() && self.store.can_cache_obs_logs() {
                        fx.push(Effect::CacheObsLogs(to_cache));
                    }
                    if is_ingress_changed {
                        self.fetch(FetchKind::ObsIngressOverview, &mut fx);
                    }
                    if let Some(id) = unknown {
                        self.on_unknown_deployment(id, &mut fx);
                    }
                    if let Some((repo, job_id)) = stage_changed {
                        self.fetch(FetchKind::CiQueue, &mut fx);
                        self.fetch(FetchKind::Summary(repo), &mut fx);
                        self.fetch(FetchKind::ObsProblems, &mut fx);
                        if job_id > 0 {
                            self.fetch(FetchKind::JobDetail(job_id), &mut fx);
                            self.fetch_active_job_log(job_id, &mut fx);
                        }
                    }
                }
                Ok(None) => {}
                Err(msg) => fx.push(Effect::Post(DataEvent::Error(UiError::Decode(msg)))),
            }
        }
        fx
    }

    /// The stream ended or failed (`error` is `None` for a clean EOF).
    pub fn on_stream_closed(
        &mut self,
        s: StreamId,
        error: Option<String>,
        now_ms: u64,
    ) -> Vec<Effect> {
        let mut fx = Vec::new();
        if self.mode != Mode::Live {
            return fx;
        }
        let peer_open = StreamId::ALL
            .iter()
            .filter(|&&other| other != s)
            .any(|&other| self.streams[other.index()].open);
        let can_open = self.can_open_stream(s);
        let st = &mut self.streams[s.index()];
        st.open = false;
        let was_stable = st
            .opened_at
            .take()
            .is_some_and(|t| now_ms.saturating_sub(t) >= MIN_STABLE_STREAM_MS);
        if !can_open {
            st.reconnect_at = None;
            return fx;
        }
        if was_stable {
            st.backoff.reset();
        }
        let delay = st.backoff.next_delay_ms();
        let attempt = st.backoff.attempt();
        st.reconnect_at = Some(now_ms + u64::from(delay));
        if let Some(msg) = error {
            if !peer_open {
                fx.push(Effect::Post(DataEvent::Error(UiError::Stream(msg))));
            }
        }
        if !self.out.is_hidden() {
            if peer_open {
                self.update_conn(now_ms, &mut fx);
            } else {
                let state = if attempt >= OFFLINE_AFTER_ATTEMPTS && !self.store.has_live_data() {
                    ConnState::Offline
                } else {
                    ConnState::Reconnecting {
                        attempt,
                        retry_in_ms: delay,
                    }
                };
                self.set_conn(state, &mut fx);
            }
        }
        fx
    }

    /// Result of [`Effect::CacheObsLogs`]: sync the total count stored in IndexedDB.
    pub fn on_obs_log_cache_written(&mut self, cached_total: u32, now_ms: u64) -> Vec<Effect> {
        let mut fx = Vec::new();
        if self.mode == Mode::Live && self.store.can_cache_obs_logs() {
            self.store.update_obs_cached_total(cached_total);
            self.flush_view_if_ready(now_ms, &mut fx);
        }
        fx
    }

    /// Result of [`Effect::ReadObsLogCacheOlder`]; falls back to the backend on cache miss.
    pub fn on_obs_log_cache_older(
        &mut self,
        gen: u64,
        items: Vec<CachedObsLog>,
        cached_total: u32,
        now_ms: u64,
    ) -> Vec<Effect> {
        let mut fx = Vec::new();
        if self.mode != Mode::Live
            || gen != self.obs_log_query_gen
            || !auth_has_policy(self.store.auth(), "obs:logs.read")
            || self.store.is_active_log_query()
        {
            return fx;
        }
        let item_len = items.len();
        self.store
            .apply_obs_logs_older_items(items, Some(cached_total));
        if item_len < OBS_LOG_PAGE_SIZE && self.store.obs_server_has_more() {
            if let Some(before) = self.store.oldest_obs_log_cursor() {
                self.store.set_obs_loading_older(true);
                self.fetch(
                    FetchKind::ObsLogsOlder {
                        before,
                        limit: OBS_LOG_PAGE_SIZE,
                        gen,
                    },
                    &mut fx,
                );
            }
        }
        self.flush_view_if_ready(now_ms, &mut fx);
        fx
    }

    /// Result of [`Effect::ReadObsLogCacheNewer`].
    pub fn on_obs_log_cache_newer(
        &mut self,
        gen: u64,
        items: Vec<CachedObsLog>,
        cached_total: u32,
        now_ms: u64,
    ) -> Vec<Effect> {
        let mut fx = Vec::new();
        if self.mode != Mode::Live
            || gen != self.obs_log_query_gen
            || !auth_has_policy(self.store.auth(), "obs:logs.read")
            || self.store.is_active_log_query()
        {
            return fx;
        }
        self.store
            .apply_obs_logs_newer_items(items, Some(cached_total));
        self.flush_view_if_ready(now_ms, &mut fx);
        fx
    }

    /// Result of [`Effect::ReadObsLogCacheLatest`].
    pub fn on_obs_log_cache_latest(
        &mut self,
        gen: u64,
        items: Vec<CachedObsLog>,
        cached_total: u32,
        now_ms: u64,
    ) -> Vec<Effect> {
        let mut fx = Vec::new();
        if self.mode != Mode::Live
            || gen != self.obs_log_query_gen
            || !auth_has_policy(self.store.auth(), "obs:logs.read")
            || self.store.is_active_log_query()
        {
            return fx;
        }
        self.store
            .apply_obs_logs_latest_items(items, Some(cached_total));
        self.flush_view_if_ready(now_ms, &mut fx);
        fx
    }

    fn flush_view_if_ready(&mut self, now_ms: u64, fx: &mut Vec<Effect>) {
        let dirty = self.store.is_dirty();
        if dirty || self.out.needs_snapshot() {
            let store = &mut self.store;
            if let Some(ev) = self.out.poll(now_ms, dirty, || {
                store.take_dirty();
                store.view()
            }) {
                fx.push(Effect::Post(ev));
            }
        }
    }

    /// Result of [`Effect::LoadOffline`].
    pub fn on_offline_loaded(&mut self, bytes: Option<&[u8]>, now_ms: u64) -> Vec<Effect> {
        if !self.store.can_emit_operational_data() {
            return Vec::new();
        }
        if let Some(snap) = bytes.and_then(|b| OfflineSnapshot::from_bytes(b).ok()) {
            self.store.apply(
                Input::Restore {
                    saved_epoch_ms: snap.saved_epoch_ms,
                    view: snap.view,
                },
                now_ms,
            );
        }
        Vec::new()
    }

    fn play(&mut self, now_ms: u64) {
        let Some(p) = self.player.as_mut() else {
            return;
        };
        for (at, input) in p.due(now_ms) {
            self.store.apply(input, at);
        }
    }

    /// Timer tick (every [`crate::coalesce::MIN_INTERVAL_MS`]).
    pub fn tick(&mut self, now_ms: u64) -> Vec<Effect> {
        let mut fx = Vec::new();
        if let Some((due_ms, _)) = self.pending_select.as_ref() {
            if now_ms >= *due_ms {
                if let Some((_, sel)) = self.pending_select.take() {
                    self.select(sel, now_ms, &mut fx);
                }
            }
        }
        match self.mode {
            Mode::Idle => return fx,
            Mode::Scenario => self.play(now_ms),
            Mode::Live => {
                for s in StreamId::ALL {
                    if self.streams[s.index()].open
                        && self.streams[s.index()]
                            .opened_at
                            .is_some_and(|t| now_ms.saturating_sub(t) >= MIN_STABLE_STREAM_MS)
                    {
                        self.streams[s.index()].backoff.reset();
                    }
                    if self.can_open_stream(s)
                        && self.streams[s.index()]
                            .reconnect_at
                            .is_some_and(|t| now_ms >= t)
                    {
                        self.open_stream(s, &mut fx);
                    }
                }
                if !self.out.is_hidden()
                    && self.store.can_emit_operational_data()
                    && now_ms
                        >= self
                            .last_live_poll_ms
                            .saturating_add(LIVE_ACTIVE_JOB_POLL_MS)
                {
                    let mut polled = false;
                    let active_job_id = self
                        .selected_job_id
                        .filter(|id| {
                            self.store.view().ci_jobs.iter().any(|j| {
                                j.job_id == *id
                                    && (j.queue_state == "Active" || j.queue_state == "Queued")
                            })
                        })
                        .or_else(|| {
                            self.store
                                .view()
                                .ci_jobs
                                .iter()
                                .find(|j| j.queue_state == "Active" || j.queue_state == "Queued")
                                .map(|j| j.job_id)
                        });
                    if matches!(
                        self.active_subview,
                        Some(SubView::Observability(ObservabilitySubView::Logs))
                    ) {
                        polled = true;
                        self.fetch(FetchKind::ObsLogs, &mut fx);
                        self.fetch(FetchKind::CiQueue, &mut fx);
                    } else if matches!(self.active_subview, Some(SubView::Ci(CiSubView::QueueLogs)))
                    {
                        polled = true;
                        if auth_has_policy(self.store.auth(), "obs:logs.read") {
                            self.fetch(FetchKind::ObsLogs, &mut fx);
                        }
                        self.fetch(FetchKind::CiQueue, &mut fx);
                    }
                    if let Some(job_id) = active_job_id {
                        polled = true;
                        self.fetch(FetchKind::JobDetail(job_id), &mut fx);
                        self.fetch_active_job_log(job_id, &mut fx);
                    } else if self.active_subview == Some(SubView::Ci(CiSubView::QueueLogs)) {
                        let missing_log_job_id = self
                            .selected_job_id
                            .filter(|id| {
                                self.store
                                    .view()
                                    .ci_jobs
                                    .iter()
                                    .any(|j| j.job_id == *id && j.raw_log_lines.is_empty())
                            })
                            .or_else(|| {
                                self.store
                                    .view()
                                    .ci_jobs
                                    .first()
                                    .filter(|j| j.raw_log_lines.is_empty())
                                    .map(|j| j.job_id)
                            });
                        if let Some(job_id) = missing_log_job_id {
                            polled = true;
                            self.fetch(FetchKind::JobDetail(job_id), &mut fx);
                            self.fetch_active_job_log(job_id, &mut fx);
                        }
                    }
                    if polled {
                        self.last_live_poll_ms = now_ms;
                    }
                }
            }
        }
        self.store.tick(now_ms);
        if self.store.take_force_snapshot() {
            self.out.force_snapshot();
        }
        if self.mode == Mode::Live && self.store.take_session_refresh() {
            self.close_disallowed_streams(&mut fx);
            self.fetch(FetchKind::AuthSession, &mut fx);
        }
        let dirty = self.store.is_dirty();
        if dirty || self.out.needs_snapshot() || self.out.is_hidden() {
            let store = &mut self.store;
            if let Some(ev) = self.out.poll(now_ms, dirty, || {
                store.take_dirty();
                store.view()
            }) {
                fx.push(Effect::Post(ev));
            }
        } else if self.store.is_lease_timer_dirty() && self.out.ready(now_ms) {
            self.store.take_lease_timer_dirty();
            let active_dialog = self.store.projected_active_dialog();
            if let Some(ev) = self
                .out
                .poll_auth_only(now_ms, self.store.auth(), &active_dialog)
            {
                fx.push(Effect::Post(ev));
            }
        }
        if !self.out.is_hidden() {
            let badges = self.store.badges();
            if self.badges != Some(badges) {
                self.badges = Some(badges);
                fx.push(Effect::Post(DataEvent::AreaBadges(badges)));
            }
        }
        if self.mode == Mode::Live && self.store.has_live_data() && self.store.can_cache_offline() {
            if let Some(view) = self.out.sent() {
                if let Some(bytes) = self.offline.maybe_save(now_ms, view) {
                    fx.push(Effect::SaveOffline(bytes));
                }
            }
        }
        fx
    }
}

fn deny_403(fx: &mut Vec<Effect>, message: &str) {
    fx.push(Effect::Post(DataEvent::Error(UiError::Http {
        status: 403,
        message: message.to_owned(),
    })));
}

const fn is_session_role_mutation(kind: &FetchKind) -> bool {
    matches!(
        kind,
        FetchKind::AuthEnableRole(_)
            | FetchKind::AuthDisableRole(_)
            | FetchKind::AuthElevateFinish { .. }
            | FetchKind::AuthRenewRole { .. }
            | FetchKind::AuthLockRoles
    )
}

fn format_role_action_http_error(status: u32, raw_message: &str) -> String {
    let fallback = if status == 0 {
        String::from("Network error")
    } else {
        format!("HTTP {status}")
    };
    let extracted = crate::api::extract_http_error_message(&fallback, Some(raw_message));
    if extracted.is_empty() {
        fallback
    } else {
        extracted
    }
}

fn can_fetch_for_auth(
    can_op_data: bool,
    status: AuthStatus,
    auth: &mu_console_protocol::AuthState,
    kind: &FetchKind,
) -> bool {
    match kind {
        FetchKind::AuthSession | FetchKind::AuthRedeem(_) => true,
        FetchKind::AuthPasskeys
        | FetchKind::AuthPasskeyRegisterFinish { .. }
        | FetchKind::AuthPasskeyDelete { .. }
        | FetchKind::AuthActivity => matches!(
            status,
            AuthStatus::PasskeyEnrollmentRequired | AuthStatus::Active
        ),
        FetchKind::AuthProfile
        | FetchKind::AuthProfilePut { .. }
        | FetchKind::AuthEnableRole(_)
        | FetchKind::AuthDisableRole(_)
        | FetchKind::AuthElevateFinish { .. }
        | FetchKind::AuthRenewRole { .. }
        | FetchKind::AuthLockRoles => status == AuthStatus::Active,
        _ if !can_op_data => false,
        FetchKind::Repos | FetchKind::Summary(_) | FetchKind::Topology(_) => {
            auth_has_policy(auth, "ci:repos.public.read")
                || auth_has_policy(auth, "ci:repos.private.read")
        }
        FetchKind::CiQueue => {
            auth_has_policy(auth, "ci:queue.read") || auth_has_policy(auth, "ci:jobs.read")
        }
        FetchKind::ClusterNodes => auth_has_policy(auth, "ci:nodes.read"),
        FetchKind::JobDetail(_) => auth_has_policy(auth, "ci:jobs.read"),
        FetchKind::JobLog(_) => {
            auth_has_policy(auth, "ci:jobs.logs.read") || auth_has_policy(auth, "obs:logs.read")
        }
        FetchKind::RestartJob(_) => auth_has_policy(auth, "ci:jobs.restart"),
        FetchKind::ResumeJob(_) => auth_has_policy(auth, "ci:jobs.resume"),
        FetchKind::CdRuns { .. } => auth_has_policy(auth, "cd:runs.read"),
        FetchKind::Deployments(_) | FetchKind::Gate(_) | FetchKind::Leases => {
            auth_can_access_area(auth, Area::AbDeploy)
        }
        FetchKind::AbRollback { .. } => auth_has_policy(auth, "ab:rollback"),
        FetchKind::RegPackages => auth_has_policy(auth, "reg:packages.read"),
        FetchKind::RegCanaries => {
            auth_has_policy(auth, "reg:canaries.read") || auth_has_policy(auth, "reg:taints.read")
        }
        FetchKind::RegCasStatus => auth_has_policy(auth, "reg:cas.read"),
        FetchKind::ObsSmartscape => auth_has_policy(auth, "obs:smartscape.read"),
        FetchKind::ObsProblems => auth_has_policy(auth, "obs:problems.read"),
        FetchKind::ObsTraces | FetchKind::ObsTraceDetail(_) => {
            auth_has_policy(auth, "obs:traces.read")
        }
        FetchKind::ObsLogs
        | FetchKind::ObsLogsOlder { .. }
        | FetchKind::ObsLogsQuery(_)
        | FetchKind::ObsLogsQueryPage { .. } => auth_has_policy(auth, "obs:logs.read"),
        FetchKind::ObsMetrics => auth_has_policy(auth, "obs:metrics.read"),
        FetchKind::ObsStoreStatus => auth_has_policy(auth, "obs:store.read"),
        FetchKind::ObsIngressOverview
        | FetchKind::ObsIngressRoutes
        | FetchKind::ObsIngressUpstreams => auth_has_policy(auth, "obs:ingress.read"),
        FetchKind::ObsSubsystemStatus => {
            auth_has_policy(auth, "system:status.read")
                || auth_has_policy(auth, "system:dashboard.read")
                || auth_has_policy(auth, "platform:maintenance.read")
        }
        FetchKind::SetSubsystemMaintenance { .. } => {
            auth_has_policy(auth, "platform:maintenance.write")
        }
        FetchKind::MrStatus => {
            auth_has_policy(auth, "mr:models.read") || auth_has_policy(auth, "mr:queue.read")
        }
        FetchKind::MrConnection => {
            auth_has_policy(auth, "mr:openai_api.read")
                || auth_has_policy(auth, "mr:wireguard_vpn.read")
        }
        FetchKind::AuthRoles => auth_has_policy(auth, "platform:roles.read"),
        FetchKind::AuthUpsertRole(_) | FetchKind::AuthDeleteRole(_) => {
            auth_has_policy(auth, "platform:roles.write")
        }
        FetchKind::AuthFolios | FetchKind::AuthRoleFolioIndex => {
            auth_has_policy(auth, "platform:folios.read")
        }
        FetchKind::AuthUpsertFolio(_)
        | FetchKind::AuthDeleteFolio(_)
        | FetchKind::AuthUpdateRoleFolioIndex(_) => auth_has_policy(auth, "platform:folios.write"),
        FetchKind::AuthUsers => auth_has_policy(auth, "platform:users.read"),
        FetchKind::AuthUpdateUserRoles { .. }
        | FetchKind::AuthResetUserPasskeys(_)
        | FetchKind::AuthRevokeUser(_) => auth_has_policy(auth, "platform:users.write"),
        FetchKind::AuthInvites => auth_has_policy(auth, "platform:invites.read"),
        FetchKind::AuthCreateInvite { .. } | FetchKind::AuthRevokeInvite(_) => {
            auth_has_policy(auth, "platform:invites.write")
        }
    }
}

/// Deployment id a CD input refers to.
fn deployment_of(input: &Input) -> Option<&str> {
    match input {
        Input::ItProgress(e) => Some(&e.deployment_id),
        Input::Promoted(e) => Some(&e.deployment_id),
        Input::RolledBack(e) => Some(&e.deployment_id),
        Input::Tainted(e) => Some(&e.deployment_id),
        Input::LeaseExpired(e) => Some(&e.deployment_id),
        _ => None,
    }
}
