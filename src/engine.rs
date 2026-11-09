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
    decode, encode, AreaBadges, CdSubView, CiSubView, CodecError, ConnState, DataEvent, DataSource,
    ObserveSubView, RegistrySubView, RepoId, Selection, SubView, UiCommand, UiError, WorkerConfig,
    PROTOCOL_VERSION,
};

use crate::api::{parse_event, parse_fetch, FetchKind, StreamId};
use crate::backoff::Backoff;
use crate::coalesce::Coalescer;
use crate::offline::{OfflinePolicy, OfflineSnapshot};
use crate::scenario::{Scenario, ScenarioPlayer};
use crate::sse::SseParser;
use crate::store::{Input, Store};

/// History-strip length requested from `/api/cd/deployments`.
pub const HISTORY_LIMIT: u32 = 8;
/// After this many failed attempts with no live data, report `Offline`.
pub const OFFLINE_AFTER_ATTEMPTS: u32 = 3;
/// Rotary-selector settle window before committing a new selection.
pub const SELECT_SETTLE_MS: u64 = 350;
/// Active CI job detail & log tailing poll interval (ms) while a job is running or queued.
pub const LIVE_ACTIVE_JOB_POLL_MS: u64 = 2_000;

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
    reconnect_at: Option<u64>,
}

impl StreamState {
    fn new(seed: u64) -> Self {
        Self {
            parser: SseParser::new(),
            backoff: Backoff::new(seed),
            open: false,
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
    streams: [StreamState; 2],
    player: Option<ScenarioPlayer>,
    conn: Option<ConnState>,
    badges: Option<AreaBadges>,
    asked_deployments: BTreeSet<String>,
    asked_job_details: BTreeSet<u64>,
    fallback_job_logs: BTreeSet<u64>,
    selected_job_id: Option<u64>,
    last_live_poll_ms: u64,
    selection_gen: u64,
    pending_select: Option<(u64, Selection)>,
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
            ],
            player: None,
            conn: None,
            badges: None,
            asked_deployments: BTreeSet::new(),
            asked_job_details: BTreeSet::new(),
            fallback_job_logs: BTreeSet::new(),
            selected_job_id: None,
            last_live_poll_ms: 0,
            selection_gen: 0,
            pending_select: None,
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
                }
            }
            UiCommand::SelectRepo { repo, submodule } => {
                self.select(Selection { repo, submodule }, now_ms, &mut fx);
            }
            UiCommand::SelectSubView(subview) => {
                if self.mode == Mode::Live {
                    match subview {
                        SubView::Ci(CiSubView::QueueLogs) => {
                            self.fetch(FetchKind::CiQueue, &mut fx);
                            self.fetch(FetchKind::ObsLogs, &mut fx);
                        }
                        SubView::Cd(CdSubView::IntegrationGate | CdSubView::DeploymentsSlots) => {
                            self.fetch_selection(&mut fx);
                            self.fetch(FetchKind::RegCanaries, &mut fx);
                        }
                        SubView::Cd(CdSubView::ActiveLeases) => {
                            self.fetch(FetchKind::Leases, &mut fx);
                            self.fetch(FetchKind::RegCanaries, &mut fx);
                        }
                        SubView::Registry(RegistrySubView::Packages) => {
                            self.fetch(FetchKind::RegPackages, &mut fx);
                        }
                        SubView::Registry(RegistrySubView::CanaryTaints) => {
                            self.fetch(FetchKind::RegCanaries, &mut fx);
                        }
                        SubView::Registry(RegistrySubView::CasHealth) => {
                            self.fetch(FetchKind::RegCasStatus, &mut fx);
                        }
                        SubView::Observe(ObserveSubView::Smartscape) => {
                            self.fetch(FetchKind::ObsSmartscape, &mut fx);
                        }
                        SubView::Observe(ObserveSubView::PurePath) => {
                            self.fetch(FetchKind::CiQueue, &mut fx);
                            self.fetch(FetchKind::ObsTraces, &mut fx);
                        }
                        SubView::Observe(ObserveSubView::ProblemsSlos) => {
                            self.fetch(FetchKind::ObsProblems, &mut fx);
                        }
                        SubView::Observe(ObserveSubView::Logs) => {
                            self.fetch(FetchKind::ObsLogs, &mut fx);
                        }
                        SubView::Observe(ObserveSubView::Metrics) => {
                            self.fetch(FetchKind::ObsMetrics, &mut fx);
                        }
                        SubView::Observe(ObserveSubView::DataStore) => {
                            self.fetch(FetchKind::ObsStoreStatus, &mut fx);
                        }
                        SubView::Fleet(_) => {
                            self.fetch(FetchKind::ClusterNodes, &mut fx);
                        }
                        SubView::Ci(_) => {}
                    }
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
            // UI-local in Phase 3; nothing to fetch.
            UiCommand::Page { .. }
            | UiCommand::SetCrtFont(_)
            | UiCommand::SetSkin(_)
            | UiCommand::Navigate { .. } => {}
            UiCommand::SetAuthSession(dto) => {
                self.store.apply(Input::AuthSession(dto), now_ms);
            }
            UiCommand::RedeemInvite { token } => {
                if self.mode == Mode::Live && !token.is_empty() {
                    self.fetch(FetchKind::AuthRedeem(token), &mut fx);
                }
            }
            UiCommand::RestartJob { job_id } => {
                if self.store.auth().is_operator() {
                    self.store.apply(Input::JobRestarted(job_id), now_ms);
                    if self.mode == Mode::Live {
                        self.fetch(FetchKind::RestartJob(job_id), &mut fx);
                        self.fetch(FetchKind::CiQueue, &mut fx);
                    }
                } else {
                    fx.push(Effect::Post(DataEvent::Error(UiError::Http {
                        status: 403,
                        message: "Operator session required to restart jobs".into(),
                    })));
                }
            }
            UiCommand::ResumeJob { job_id } => {
                if self.store.auth().is_operator() {
                    self.store.apply(Input::JobResumed(job_id), now_ms);
                    if self.mode == Mode::Live {
                        self.fetch(FetchKind::ResumeJob(job_id), &mut fx);
                        self.fetch(FetchKind::CiQueue, &mut fx);
                    }
                } else {
                    fx.push(Effect::Post(DataEvent::Error(UiError::Http {
                        status: 403,
                        message: "Operator session required to resume jobs".into(),
                    })));
                }
            }
            UiCommand::SelectJob { job_id } => {
                if job_id > 0 {
                    self.selected_job_id = Some(job_id);
                    if self.mode == Mode::Live {
                        self.fetch(FetchKind::JobDetail(job_id), &mut fx);
                        self.fetch(FetchKind::JobLog(job_id), &mut fx);
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
            self.set_conn(ConnState::Connecting, fx);
            fx.push(Effect::LoadOffline);
            self.fetch(FetchKind::AuthSession, fx);
            self.fetch(FetchKind::Repos, fx);
            self.fetch(FetchKind::ClusterNodes, fx);
            self.fetch(FetchKind::CiQueue, fx);
            self.fetch(FetchKind::ObsLogs, fx);
            self.fetch(FetchKind::ObsStoreStatus, fx);
            self.fetch(FetchKind::RegPackages, fx);
            self.fetch(FetchKind::RegCanaries, fx);
            self.fetch(FetchKind::RegCasStatus, fx);
            for s in StreamId::ALL {
                self.open_stream(s, fx);
            }
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
                for s in StreamId::ALL {
                    let st = &mut self.streams[s.index()];
                    st.backoff.reset();
                    if !st.open {
                        st.reconnect_at = None;
                        self.open_stream(s, fx);
                    }
                }
                self.fetch(FetchKind::AuthSession, fx);
                self.fetch(FetchKind::Repos, fx);
                self.fetch(FetchKind::ClusterNodes, fx);
                self.fetch(FetchKind::CiQueue, fx);
                self.fetch(FetchKind::ObsLogs, fx);
                self.fetch(FetchKind::ObsStoreStatus, fx);
                self.fetch(FetchKind::RegPackages, fx);
                self.fetch(FetchKind::RegCanaries, fx);
                self.fetch(FetchKind::RegCasStatus, fx);
                self.fetch_selection(fx);
            }
        }
    }

    fn select(&mut self, sel: Selection, now_ms: u64, fx: &mut Vec<Effect>) {
        self.pending_select = None;
        if self.store.apply(Input::Select(sel), now_ms) {
            self.selection_gen = self.selection_gen.wrapping_add(1);
        }
        if self.mode == Mode::Live {
            self.fetch_selection(fx);
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
        let path = match &kind {
            FetchKind::Repos => paths::REPOS.to_owned(),
            FetchKind::ClusterNodes => paths::CLUSTER_NODES.to_owned(),
            FetchKind::CiQueue => paths::CI_QUEUE.to_owned(),
            FetchKind::Summary(r) => paths::summary(&r.owner, &r.repo),
            FetchKind::Topology(r) => paths::topology(&r.owner, &r.repo),
            FetchKind::Deployments(r) => paths::deployments(&r.owner, &r.repo, HISTORY_LIMIT),
            FetchKind::Gate(id) => paths::gate(id),
            FetchKind::Leases => paths::LEASES.to_owned(),
            FetchKind::RegPackages => paths::REG_PACKAGES.to_owned(),
            FetchKind::RegCanaries => paths::REG_CANARIES.to_owned(),
            FetchKind::RegCasStatus => paths::REG_CAS_STATUS.to_owned(),
            FetchKind::ObsSmartscape => paths::OBS_SMARTSCAPE.to_owned(),
            FetchKind::ObsProblems => paths::OBS_PROBLEMS.to_owned(),
            FetchKind::ObsTraces => paths::OBS_TRACES.to_owned(),
            FetchKind::ObsTraceDetail(id) => paths::obs_trace(id),
            FetchKind::ObsLogs => paths::OBS_LOGS.to_owned(),
            FetchKind::ObsMetrics => paths::OBS_METRICS.to_owned(),
            FetchKind::ObsStoreStatus => paths::OBS_STORE_STATUS.to_owned(),
            FetchKind::AuthSession => paths::AUTH_SESSION.to_owned(),
            FetchKind::AuthRedeem(_) => paths::AUTH_REDEEM.to_owned(),
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
        let jid = self.store.resolve_job_id_str(job_id);
        let path = paths::job_obs_log_id(&jid);
        fx.push(Effect::Fetch {
            kind: FetchKind::JobLog(job_id),
            url: self.config.url(&path),
        });
    }

    fn fetch_active_job_log(&self, job_id: u64, fx: &mut Vec<Effect>) {
        if self.store.auth().is_operator() {
            self.fetch(FetchKind::JobLog(job_id), fx);
        } else {
            self.fetch_obs_job_log(job_id, fx);
        }
    }

    fn open_stream(&mut self, s: StreamId, fx: &mut Vec<Effect>) {
        let path = match s {
            StreamId::Ci => paths::CI_EVENTS,
            StreamId::Cd => paths::CD_EVENTS,
        };
        let st = &mut self.streams[s.index()];
        st.parser.reset_connection();
        st.reconnect_at = None;
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
                let ci = &self.streams[StreamId::Ci.index()];
                let cd = &self.streams[StreamId::Cd.index()];
                if ci.open && (cd.open || cd.backoff.attempt() > 0) {
                    return ConnState::Live;
                }
                let worst = self
                    .streams
                    .iter()
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
                        retry_in_ms: self
                            .streams
                            .iter()
                            .filter_map(|s| s.reconnect_at)
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
        let body = match result {
            Ok(b) => b,
            Err(e) => {
                // Non-fatal 404/502/503 on optional auxiliary daemon probes.
                let is_optional_probe = matches!(
                    kind,
                    FetchKind::Deployments(_)
                        | FetchKind::Gate(_)
                        | FetchKind::Leases
                        | FetchKind::ClusterNodes
                        | FetchKind::CiQueue
                        | FetchKind::AuthSession
                        | FetchKind::RegPackages
                        | FetchKind::RegCanaries
                        | FetchKind::RegCasStatus
                        | FetchKind::ObsSmartscape
                        | FetchKind::ObsProblems
                        | FetchKind::ObsTraces
                        | FetchKind::ObsTraceDetail(_)
                        | FetchKind::ObsLogs
                        | FetchKind::ObsMetrics
                        | FetchKind::ObsStoreStatus
                        | FetchKind::RestartJob(_)
                        | FetchKind::ResumeJob(_)
                        | FetchKind::JobDetail(_)
                        | FetchKind::JobLog(_)
                );
                if let FetchKind::JobLog(job_id) = kind {
                    if matches!(e.status, 401 | 403) && self.fallback_job_logs.insert(*job_id) {
                        self.fetch_obs_job_log(*job_id, &mut fx);
                        return fx;
                    }
                }
                let is_auth_gated_log =
                    matches!(kind, FetchKind::JobLog(_)) && matches!(e.status, 401 | 403);
                if !((is_optional_probe && matches!(e.status, 404 | 502 | 503))
                    || is_auth_gated_log)
                {
                    fx.push(Effect::Post(DataEvent::Error(UiError::Http {
                        status: e.status,
                        message: e.message,
                    })));
                }
                return fx;
            }
        };
        let input = match parse_fetch(kind, &body) {
            Ok(i) => i,
            Err(msg) => {
                fx.push(Effect::Post(DataEvent::Error(UiError::Decode(msg))));
                return fx;
            }
        };
        self.store.apply(input, now_ms);
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
                    if self.store.auth().is_operator() {
                        self.fetch(FetchKind::JobLog(job_id), &mut fx);
                    } else {
                        self.fetch_obs_job_log(job_id, &mut fx);
                    }
                }
            }
            FetchKind::Summary(repo) | FetchKind::Topology(repo) => {
                if let Some(job_id) = self.store.repo_latest_job(repo) {
                    if job_id > 0 && self.asked_job_details.insert(job_id) {
                        self.fetch(FetchKind::JobDetail(job_id), &mut fx);
                        if self.store.auth().is_operator() {
                            self.fetch(FetchKind::JobLog(job_id), &mut fx);
                        } else {
                            self.fetch_obs_job_log(job_id, &mut fx);
                        }
                    }
                }
            }
            FetchKind::Deployments(repo) => self.fetch_latest_gate(repo, &mut fx),
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
            FetchKind::AuthRedeem(_) if self.store.auth().is_operator() => {
                self.fetch(FetchKind::Repos, &mut fx);
                self.fetch_selection(&mut fx);
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
        st.backoff.reset();
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
                    self.store.apply(input, now_ms);
                    if let Some(id) = unknown {
                        self.on_unknown_deployment(id, &mut fx);
                    }
                    if let Some((repo, job_id)) = stage_changed {
                        self.fetch(FetchKind::CiQueue, &mut fx);
                        self.fetch(FetchKind::Summary(repo), &mut fx);
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
        let ci_open = self.streams[StreamId::Ci.index()].open;
        let st = &mut self.streams[s.index()];
        st.open = false;
        let delay = st.backoff.next_delay_ms();
        let attempt = st.backoff.attempt();
        st.reconnect_at = Some(now_ms + u64::from(delay));
        if let Some(msg) = error {
            if !(s == StreamId::Cd && ci_open) {
                fx.push(Effect::Post(DataEvent::Error(UiError::Stream(msg))));
            }
        }
        if !self.out.is_hidden() {
            if s == StreamId::Cd && ci_open {
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

    /// Result of [`Effect::LoadOffline`].
    pub fn on_offline_loaded(&mut self, bytes: Option<&[u8]>, now_ms: u64) -> Vec<Effect> {
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
                    if self.streams[s.index()]
                        .reconnect_at
                        .is_some_and(|t| now_ms >= t)
                    {
                        self.open_stream(s, &mut fx);
                    }
                }
                if !self.out.is_hidden()
                    && now_ms
                        >= self
                            .last_live_poll_ms
                            .saturating_add(LIVE_ACTIVE_JOB_POLL_MS)
                {
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
                    if let Some(job_id) = active_job_id {
                        self.last_live_poll_ms = now_ms;
                        self.fetch(FetchKind::JobDetail(job_id), &mut fx);
                        self.fetch_active_job_log(job_id, &mut fx);
                    }
                }
            }
        }
        self.store.tick(now_ms);
        let dirty = self.store.is_dirty();
        let store = &mut self.store;
        if let Some(ev) = self.out.poll(now_ms, dirty, || {
            store.take_dirty();
            store.view()
        }) {
            fx.push(Effect::Post(ev));
        }
        if !self.out.is_hidden() {
            let badges = self.store.badges();
            if self.badges != Some(badges) {
                self.badges = Some(badges);
                fx.push(Effect::Post(DataEvent::AreaBadges(badges)));
            }
        }
        if self.mode == Mode::Live && self.store.has_live_data() {
            if let Some(view) = self.out.sent() {
                if let Some(bytes) = self.offline.maybe_save(now_ms, view) {
                    fx.push(Effect::SaveOffline(bytes));
                }
            }
        }
        fx
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
