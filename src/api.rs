// SPDX-License-Identifier: AGPL-3.0-only
//! REST and SSE payload decoding into store [`Input`]s.

use mu_console_protocol::dto::{
    AbRollbackResponseDto, AuthSessionDto, BranchCreatedDto, BranchDeletedDto, CanaryBundleDto,
    CasStatusDto, CdRunDto, CiQueueDto, CiQueueJobRecordDto, ClusterNodeDto,
    CreatedInviteResponseDto, DeploymentDto, GateDto, IngressOverviewDto, IngressRouteDto,
    IngressUpstreamDto, InviteRecordDto, ItProgressDto, JobStageChangedDto, LeaseDto,
    LeaseExpiredDto, MaintenanceMode, MetricSeriesDto, ModelRunnerConnectionDto,
    ModelRunnerStatusDto, NodeMembershipChangedDto, OtelLogDto, PackageDto, PasskeySummaryDto,
    PlatformUserDto, PolicyFolioDto, PrStateChangedDto, ProblemDto, PromotedDto, RawMetricPointDto,
    RepoDto, RepoListResponseDto, RepoSummaryDto, RoleFolioIndexDto, RoleSpecDto, RolledBackDto,
    SmartscapeDto, StoreStatusDto, SubsystemId, SubsystemStatus, SubsystemStatusEntryDto,
    TaintedDigestDto, TaintedDto, TopologyDto, TraceDto, UserProfileDto,
};
use mu_console_protocol::{
    sanitize_ansi_log_lines, CanaryBundleState, CdLease, ConsoleSkin, CrtFont, LogSeverity, RepoId,
    DEFAULT_MAX_JOB_LOG_LINES,
};
use serde::de::DeserializeOwned;
use serde::Deserialize;

use crate::log_cache::CachedObsLog;
use crate::store::Input;

/// Which REST resource or mutating endpoint a fetch targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchKind {
    Repos,
    ClusterNodes,
    CiQueue,
    Summary(RepoId),
    Topology(RepoId),
    Deployments(RepoId),
    CdRuns {
        repo: RepoId,
        ecosystem: Option<String>,
        limit: u32,
    },
    Gate(String),
    Leases,
    AbRollback {
        deployment_id: String,
        note: Option<String>,
    },
    RegPackages,
    RegCanaries,
    RegCasStatus,
    ObsSmartscape,
    ObsProblems,
    ObsTraces,
    ObsTraceDetail(String),
    ObsLogs,
    ObsLogsOlder {
        before: String,
        limit: usize,
        gen: u64,
    },
    ObsMetrics,
    ObsStoreStatus,
    ObsSubsystemStatus,
    SetSubsystemMaintenance {
        subsystem: SubsystemId,
        mode: MaintenanceMode,
        reason: Option<String>,
        auto_clear_secs: Option<u64>,
    },
    ObsIngressOverview,
    ObsIngressRoutes,
    ObsIngressUpstreams,
    ObsLogsQuery(String),
    ObsLogsQueryPage {
        query: String,
        before: Option<String>,
        limit: usize,
        gen: u64,
    },
    MrStatus,
    MrConnection,
    AuthSession,
    AuthRedeem(String),
    AuthProfile,
    AuthProfilePut {
        display_name: Option<String>,
        preferred_skin: Option<ConsoleSkin>,
        preferred_font: Option<CrtFont>,
    },
    AuthPasskeys,
    AuthPasskeyRegisterFinish {
        label: Option<String>,
        attestation_json: String,
    },
    AuthPasskeyDelete {
        credential_id: String,
        step_up_assertion_json: String,
    },
    AuthEnableRole(String),
    AuthDisableRole(String),
    AuthElevateFinish {
        role_id: String,
        assertion_json: String,
    },
    AuthRenewRole {
        role_id: String,
        assertion_json: String,
    },
    AuthLockRoles,
    AuthActivity,
    AuthRoles,
    AuthUpsertRole(RoleSpecDto),
    AuthDeleteRole(String),
    AuthFolios,
    AuthUpsertFolio(PolicyFolioDto),
    AuthDeleteFolio(String),
    AuthRoleFolioIndex,
    AuthUpdateRoleFolioIndex(RoleFolioIndexDto),
    AuthUsers,
    AuthUpdateUserRoles {
        github_login: String,
        bound_roles: Vec<String>,
    },
    AuthResetUserPasskeys(String),
    AuthRevokeUser(String),
    AuthInvites,
    AuthCreateInvite {
        note: Option<String>,
        ttl_secs: Option<u64>,
    },
    AuthRevokeInvite(String),
    RestartJob(u64),
    ResumeJob(u64),
    JobDetail(u64),
    JobLog(u64),
}

/// Alias for [`FetchKind`] used by protocol consumers.
pub type Endpoint = FetchKind;

/// Which SSE stream an event came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamId {
    /// ActionRunner-controller `/api/events`.
    Ci,
    /// MuConDe-controller `/api/cd/events`.
    Cd,
    /// MuObserve `/api/v1/events` or `/api/obs/v1/events`.
    Obs,
}

impl StreamId {
    pub const ALL: [Self; 3] = [Self::Ci, Self::Cd, Self::Obs];

    /// Index into per-stream arrays.
    #[must_use]
    pub fn index(self) -> usize {
        match self {
            Self::Ci => 0,
            Self::Cd => 1,
            Self::Obs => 2,
        }
    }
}

fn json<T: DeserializeOwned>(body: &str) -> Result<T, String> {
    serde_json::from_str(body).map_err(|e| e.to_string())
}

/// Decode a `/api/auth/session`, `/api/auth/redeem`, `/api/auth/elevate/finish`, or
/// `/api/auth/roles/{role_id}/renew` JSON body (either raw `AuthSessionDto` or `{"session": ...}`).
///
/// # Errors
/// Returns the JSON error message when the payload is malformed.
pub fn parse_auth_session(bytes: &[u8]) -> Result<AuthSessionDto, String> {
    let val: serde_json::Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    if let Some(inner) = val.get("session").filter(|v| v.is_object()) {
        serde_json::from_value(inner.clone()).map_err(|e| e.to_string())
    } else {
        serde_json::from_value(val).map_err(|e| e.to_string())
    }
}

/// Extract a human-readable error message from a JSON (`{"error": ...}` / `{"message": ...}`)
/// or plain-text HTTP error body, falling back to `fallback` when the body is empty or HTML.
#[must_use]
pub fn extract_http_error_message(fallback: &str, body: Option<&str>) -> String {
    if let Some(raw) = body {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            if let Ok(serde_json::Value::Object(map)) =
                serde_json::from_str::<serde_json::Value>(trimmed)
            {
                if let Some(msg) = map
                    .get("error")
                    .or_else(|| map.get("message"))
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    return msg.to_owned();
                }
            }
            if !trimmed.starts_with('<') {
                return trimmed.to_owned();
            }
        }
    }
    fallback.trim().to_owned()
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ReposEnvelope {
    List(Vec<RepoDto>),
    Envelope(RepoListResponseDto),
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ClusterNodesEnvelope {
    List(Vec<ClusterNodeDto>),
    Envelope {
        #[serde(default)]
        nodes: Vec<ClusterNodeDto>,
    },
}

#[derive(Deserialize)]
#[serde(untagged)]
enum JobsEnvelope {
    List(Vec<CiQueueJobRecordDto>),
    Envelope {
        #[serde(default)]
        jobs: Vec<CiQueueJobRecordDto>,
    },
}

#[derive(Deserialize)]
#[serde(untagged)]
enum CdRunsEnvelope {
    List(Vec<CdRunDto>),
    Envelope {
        #[serde(default)]
        runs: Vec<CdRunDto>,
    },
}

#[derive(Deserialize)]
#[serde(untagged)]
enum PasskeysEnvelope {
    List(Vec<PasskeySummaryDto>),
    Envelope {
        #[serde(default)]
        passkeys: Vec<PasskeySummaryDto>,
    },
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RolesEnvelope {
    List(Vec<RoleSpecDto>),
    Envelope {
        #[serde(default)]
        roles: Vec<RoleSpecDto>,
    },
}

#[derive(Deserialize)]
#[serde(untagged)]
enum FoliosEnvelope {
    List(Vec<PolicyFolioDto>),
    Envelope {
        #[serde(default)]
        folios: Vec<PolicyFolioDto>,
    },
}

#[derive(Deserialize)]
#[serde(untagged)]
enum UsersEnvelope {
    List(Vec<PlatformUserDto>),
    Envelope {
        #[serde(default)]
        users: Vec<PlatformUserDto>,
    },
}

#[derive(Deserialize)]
#[serde(untagged)]
enum InvitesEnvelope {
    List(Vec<InviteRecordDto>),
    Envelope {
        #[serde(default)]
        invites: Vec<InviteRecordDto>,
    },
}

#[derive(Deserialize)]
struct FlexSubsystemEntry {
    #[serde(default, alias = "id")]
    subsystem: SubsystemId,
    #[serde(default, alias = "state")]
    effective_status: Option<String>,
    #[serde(default)]
    probe_status: Option<String>,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    maintenance_active: Option<bool>,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    updated_by: Option<String>,
    #[serde(default)]
    updated_at_ms: i64,
    #[serde(default, alias = "expires_at_ms")]
    auto_clear_at_ms: Option<i64>,
    #[serde(default)]
    active_incidents: u32,
}

fn parse_subsystem_status_str(raw: Option<&str>) -> SubsystemStatus {
    match raw
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
        .replace('-', "_")
        .as_str()
    {
        "in_maintenance" | "maintenance" => SubsystemStatus::InMaintenance,
        "partial_maintenance" | "partial" => SubsystemStatus::PartialMaintenance,
        "degraded" => SubsystemStatus::Degraded,
        "offline" | "down" | "unhealthy" => SubsystemStatus::Offline,
        _ => SubsystemStatus::Live,
    }
}

fn parse_maintenance_mode_str(
    raw: Option<&str>,
    effective: SubsystemStatus,
    maint_flag: Option<bool>,
) -> MaintenanceMode {
    match raw
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
        .replace('-', "_")
        .as_str()
    {
        "scheduled_maintenance" => MaintenanceMode::Manual(SubsystemStatus::InMaintenance),
        "partial_maintenance" => MaintenanceMode::Manual(SubsystemStatus::PartialMaintenance),
        "offline_override" => MaintenanceMode::Manual(SubsystemStatus::Offline),
        "manual" | "manual_override" => MaintenanceMode::Manual(effective),
        _ if maint_flag == Some(true) => MaintenanceMode::Manual(effective),
        _ => MaintenanceMode::Auto,
    }
}

impl From<FlexSubsystemEntry> for SubsystemStatusEntryDto {
    fn from(raw: FlexSubsystemEntry) -> Self {
        let effective = parse_subsystem_status_str(raw.effective_status.as_deref());
        let probe = raw
            .probe_status
            .as_deref()
            .map_or(effective, |s| parse_subsystem_status_str(Some(s)));
        let mode =
            parse_maintenance_mode_str(raw.mode.as_deref(), effective, raw.maintenance_active);
        Self {
            subsystem: raw.subsystem,
            effective_status: effective,
            probe_status: probe,
            mode,
            summary: raw.summary.unwrap_or_default(),
            updated_by: raw.updated_by,
            updated_at_ms: u64::try_from(raw.updated_at_ms.max(0)).unwrap_or(0),
            auto_clear_at_ms: raw
                .auto_clear_at_ms
                .and_then(|ms| u64::try_from(ms.max(0)).ok()),
            active_incidents: raw.active_incidents,
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum FlexSubsystemsResponse {
    Entries(Vec<SubsystemStatusEntryDto>),
    ProtocolEnvelope {
        #[serde(default)]
        subsystems: Vec<SubsystemStatusEntryDto>,
    },
    FlexList(Vec<FlexSubsystemEntry>),
    FlexEnvelope {
        #[serde(default)]
        subsystems: Vec<FlexSubsystemEntry>,
    },
}

fn parse_subsystem_entries(body: &str) -> Result<Vec<SubsystemStatusEntryDto>, String> {
    if let Ok(entries) = serde_json::from_str::<Vec<SubsystemStatusEntryDto>>(body) {
        return Ok(entries);
    }
    match json::<FlexSubsystemsResponse>(body)? {
        FlexSubsystemsResponse::Entries(v) => Ok(v),
        FlexSubsystemsResponse::ProtocolEnvelope { subsystems } => Ok(subsystems),
        FlexSubsystemsResponse::FlexList(v) => Ok(v.into_iter().map(Into::into).collect()),
        FlexSubsystemsResponse::FlexEnvelope { subsystems } => {
            Ok(subsystems.into_iter().map(Into::into).collect())
        }
    }
}

fn parse_subsystem_entry(body: &str) -> Result<SubsystemStatusEntryDto, String> {
    if let Ok(wrapped) =
        serde_json::from_str::<mu_console_protocol::SubsystemStatusChangedDto>(body)
    {
        return Ok(wrapped.entry);
    }
    if let Ok(entry) = serde_json::from_str::<SubsystemStatusEntryDto>(body) {
        return Ok(entry);
    }
    Ok(json::<FlexSubsystemEntry>(body)?.into())
}

fn parse_passkey_finish_body(body: &str) -> Result<Input, String> {
    let val = if body.trim().is_empty() {
        serde_json::Value::Object(serde_json::Map::new())
    } else {
        json::<serde_json::Value>(body)?
    };
    if let Some(session_val) = val.get("session") {
        let dto: AuthSessionDto =
            serde_json::from_value(session_val.clone()).map_err(|e| e.to_string())?;
        return Ok(Input::AuthSession(dto));
    }
    if val.get("authenticated").is_some()
        || val.get("active_roles").is_some()
        || val.get("active_policies").is_some()
    {
        let dto: AuthSessionDto = serde_json::from_value(val).map_err(|e| e.to_string())?;
        return Ok(Input::AuthSession(dto));
    }
    if val.get("passkeys").is_some() && val.get("github_login").is_some() {
        let profile: UserProfileDto = serde_json::from_value(val).map_err(|e| e.to_string())?;
        return Ok(Input::UserProfile(profile));
    }
    if val.get("credential_id").is_some() {
        let summary: PasskeySummaryDto = serde_json::from_value(val).map_err(|e| e.to_string())?;
        return Ok(Input::PasskeyEnrolled(Some(summary)));
    }
    Ok(Input::PasskeyEnrolled(None))
}

fn parse_passkey_delete_body(credential_id: &str, body: &str) -> Result<Input, String> {
    if body.trim().is_empty() {
        return Ok(Input::PasskeyDeleted(credential_id.to_owned()));
    }
    let val: serde_json::Value = json(body)?;
    if let Some(session_val) = val.get("session") {
        let dto: AuthSessionDto =
            serde_json::from_value(session_val.clone()).map_err(|e| e.to_string())?;
        return Ok(Input::AuthSession(dto));
    }
    if val.get("authenticated").is_some() {
        let dto: AuthSessionDto = serde_json::from_value(val).map_err(|e| e.to_string())?;
        return Ok(Input::AuthSession(dto));
    }
    if val.get("passkeys").is_some() && val.get("github_login").is_some() {
        let profile: UserProfileDto = serde_json::from_value(val).map_err(|e| e.to_string())?;
        return Ok(Input::UserProfile(profile));
    }
    Ok(Input::PasskeyDeleted(credential_id.to_owned()))
}

#[derive(Deserialize)]
#[serde(untagged)]
enum PackagesEnvelope {
    List(Vec<PackageDto>),
    Envelope {
        #[serde(default)]
        packages: Vec<PackageDto>,
    },
}

#[derive(Deserialize)]
struct RawCanaryBundleDto {
    bundle_id: String,
    #[serde(default)]
    owner: Option<String>,
    #[serde(default)]
    repo: Option<String>,
    #[serde(default, alias = "service_name")]
    service: Option<String>,
    #[serde(default, alias = "binary_digest")]
    artifact_digest: Option<String>,
    #[serde(default, alias = "status")]
    state: Option<String>,
    #[serde(default)]
    taint_reason: Option<String>,
    #[serde(default)]
    deployment_id: Option<String>,
    #[serde(default)]
    trace_id: Option<String>,
}

fn parse_canary_state(raw: Option<&str>) -> CanaryBundleState {
    match raw.unwrap_or("").trim().to_ascii_lowercase().as_str() {
        "promoted" | "active" | "healthy" => CanaryBundleState::Promoted,
        "tainted" => CanaryBundleState::Tainted,
        "rolled_back" | "rolled back" => CanaryBundleState::RolledBack,
        _ => CanaryBundleState::Candidate,
    }
}

impl From<RawCanaryBundleDto> for CanaryBundleDto {
    fn from(r: RawCanaryBundleDto) -> Self {
        let raw_digest = r.artifact_digest.unwrap_or_default();
        let hex_part = raw_digest
            .strip_prefix("sha256:")
            .unwrap_or(&raw_digest)
            .to_string();
        let artifact_digest = if !raw_digest.starts_with("sha256:") && hex_part.len() >= 12 {
            format!("sha256:{}", &hex_part[..12])
        } else {
            raw_digest.clone()
        };
        let bundle_id = if let Some(uuid) = r.bundle_id.strip_prefix("bundle-") {
            let short: String = uuid.chars().take(4).collect();
            format!("cny-{short}")
        } else {
            r.bundle_id
        };
        let deployment_id = match r.deployment_id {
            Some(d) if !d.is_empty() => d,
            _ if hex_part.len() >= 4 => format!("dep-{}", &hex_part[..4]),
            _ => "dep-live".into(),
        };
        let raw_trace = r.trace_id.unwrap_or_default();
        let trimmed_trace = raw_trace.trim();
        let trace_id = if !trimmed_trace.is_empty() {
            trimmed_trace.to_owned()
        } else if !raw_digest.is_empty() || !bundle_id.is_empty() {
            let token: String = hex_part
                .chars()
                .filter(char::is_ascii_alphanumeric)
                .take(6)
                .collect();
            if !token.is_empty() {
                format!("tr-ci-{token}")
            } else {
                format!("tr-reg-{bundle_id}")
            }
        } else {
            String::new()
        };
        Self {
            bundle_id,
            owner: r.owner.unwrap_or_default(),
            repo: r.repo.unwrap_or_default(),
            service: r.service.unwrap_or_default(),
            artifact_digest,
            state: parse_canary_state(r.state.as_deref()),
            taint_reason: r.taint_reason,
            deployment_id,
            trace_id,
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum CanariesEnvelope {
    List(Vec<RawCanaryBundleDto>),
    Envelope {
        #[serde(default)]
        bundles: Vec<RawCanaryBundleDto>,
        #[serde(default)]
        canaries: Vec<RawCanaryBundleDto>,
        #[serde(default)]
        taints: Vec<TaintedDigestDto>,
    },
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ProblemsEnvelope {
    List(Vec<ProblemDto>),
    Envelope {
        #[serde(default)]
        problems: Vec<ProblemDto>,
    },
}

#[derive(Deserialize)]
#[serde(untagged)]
enum TracesEnvelope {
    List(Vec<TraceDto>),
    Envelope {
        #[serde(default)]
        traces: Vec<TraceDto>,
    },
}

fn null_default<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawObsLogItemDto {
    #[serde(default, alias = "timestamp_ns", deserialize_with = "null_default")]
    timestamp_unix_nano: i64,
    #[serde(default, deserialize_with = "null_default")]
    timestamp_ms: u64,
    #[serde(default, alias = "severity_text", deserialize_with = "null_default")]
    severity: LogSeverity,
    #[serde(default, deserialize_with = "null_default")]
    service: String,
    #[serde(default, deserialize_with = "null_default")]
    service_name: String,
    #[serde(default)]
    span_id: Option<String>,
    #[serde(default, deserialize_with = "null_default")]
    trace_id: String,
    #[serde(default, alias = "body", deserialize_with = "null_default")]
    message: String,
    #[serde(default, deserialize_with = "null_default")]
    line_no: u32,
    #[serde(default, deserialize_with = "null_default")]
    dedup_hash: u64,
}

impl RawObsLogItemDto {
    fn resolved_service(&self) -> String {
        if !self.service.trim().is_empty() {
            self.service.clone()
        } else {
            self.service_name.clone()
        }
    }

    fn resolved_span_id(&self) -> Option<String> {
        self.span_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    }

    fn into_cached_log(self) -> CachedObsLog {
        let timestamp_unix_nano = self.timestamp_unix_nano;
        let line_no = self.line_no;
        let dedup_hash = self.dedup_hash;
        let dto = self.into_otel_dto();
        let entry = mu_console_protocol::OtelLogEntry {
            timestamp_ms: dto.timestamp_ms,
            severity: dto.severity,
            service: dto.service,
            span_id: dto.span_id,
            trace_id: dto.trace_id,
            message: dto.message,
        };
        CachedObsLog::with_meta(entry, timestamp_unix_nano, line_no, dedup_hash)
    }

    fn into_otel_dto(self) -> OtelLogDto {
        let service = self.resolved_service();
        let span_id = self.resolved_span_id();
        let timestamp_ms = if self.timestamp_ms > 0 {
            self.timestamp_ms
        } else {
            u64::try_from(self.timestamp_unix_nano.max(0)).unwrap_or(0) / 1_000_000
        };
        OtelLogDto {
            timestamp_ms,
            severity: self.severity,
            service,
            span_id,
            trace_id: self.trace_id,
            message: self.message,
        }
    }
}

/// Paginated response decoded from `GET /api/obs/v1/logs`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ObsLogsPageDto {
    pub logs: Vec<CachedObsLog>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
    pub total_matched: Option<u64>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum LogsEnvelope {
    List(Vec<RawObsLogItemDto>),
    Envelope {
        #[serde(default)]
        logs: Vec<RawObsLogItemDto>,
        #[serde(default)]
        next_cursor: Option<String>,
        #[serde(default)]
        has_more: bool,
        #[serde(default)]
        total_matched: Option<u64>,
    },
}

impl LogsEnvelope {
    fn into_page(self) -> ObsLogsPageDto {
        match self {
            Self::List(v) => ObsLogsPageDto {
                logs: v
                    .into_iter()
                    .map(RawObsLogItemDto::into_cached_log)
                    .collect(),
                next_cursor: None,
                has_more: false,
                total_matched: None,
            },
            Self::Envelope {
                logs,
                next_cursor,
                has_more,
                total_matched,
            } => ObsLogsPageDto {
                logs: logs
                    .into_iter()
                    .map(RawObsLogItemDto::into_cached_log)
                    .collect(),
                next_cursor: next_cursor
                    .map(|s| s.trim().to_owned())
                    .filter(|s| !s.is_empty()),
                has_more,
                total_matched,
            },
        }
    }

    fn into_otel_list(self) -> Vec<OtelLogDto> {
        let items = match self {
            Self::List(v) | Self::Envelope { logs: v, .. } => v,
        };
        items
            .into_iter()
            .map(RawObsLogItemDto::into_otel_dto)
            .collect()
    }
}

#[derive(Deserialize)]
struct ClusterEfficiencyDto {
    #[serde(default)]
    arch: String,
    #[serde(default)]
    cpu_cluster: String,
    #[serde(default)]
    vlen_bits: u32,
    #[serde(default)]
    run_count: u32,
    #[serde(default)]
    avg_ns_per_iter: f64,
    #[serde(default)]
    min_ns_per_iter: f64,
    #[serde(default)]
    max_ns_per_iter: f64,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum MetricsEnvelope {
    List(Vec<RawMetricPointDto>),
    Envelope {
        #[serde(default)]
        series: Option<Vec<RawMetricPointDto>>,
        #[serde(default)]
        metrics: Option<Vec<RawMetricPointDto>>,
        #[serde(default)]
        items: Option<Vec<RawMetricPointDto>>,
        #[serde(default)]
        points: Option<Vec<RawMetricPointDto>>,
        #[serde(default)]
        timeseries: Option<Vec<RawMetricPointDto>>,
        #[serde(default)]
        cluster_efficiency: Option<Vec<ClusterEfficiencyDto>>,
    },
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn ns_to_ms(ns: f64) -> u32 {
    if ns <= 0.0 || ns.is_nan() {
        0
    } else {
        (ns / 1_000_000.0).round().max(1.0) as u32
    }
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn ns_to_u32(ns: f64) -> u32 {
    if ns <= 0.0 || ns.is_nan() {
        0
    } else {
        ns.round() as u32
    }
}

/// Decode a REST response body.
///
/// # Errors
/// Returns the JSON error message.
#[allow(clippy::too_many_lines)]
pub fn parse_fetch(kind: &FetchKind, body: &str) -> Result<Input, String> {
    Ok(match kind {
        FetchKind::Repos => {
            let repos = match json::<ReposEnvelope>(body)? {
                ReposEnvelope::List(v) => v,
                ReposEnvelope::Envelope(e) => e.repos,
            };
            Input::Repos(repos)
        }
        FetchKind::ClusterNodes => {
            let nodes = match json::<ClusterNodesEnvelope>(body)? {
                ClusterNodesEnvelope::List(v) => v,
                ClusterNodesEnvelope::Envelope { nodes } => nodes,
            };
            Input::ClusterNodes(nodes)
        }
        FetchKind::CiQueue => Input::CiQueue(json::<CiQueueDto>(body)?),
        FetchKind::Summary(_) => Input::Summary(json::<RepoSummaryDto>(body)?),
        FetchKind::Topology(_) => Input::Topology(json::<TopologyDto>(body)?),
        FetchKind::Deployments(repo) => Input::Deployments {
            repo: repo.clone(),
            list: json::<Vec<DeploymentDto>>(body)?,
        },
        FetchKind::Gate(_) => Input::Gate(json::<GateDto>(body)?),
        FetchKind::Leases => {
            let leases = json::<Vec<LeaseDto>>(body)?
                .into_iter()
                .map(|l| CdLease {
                    lease_id: l.lease_id,
                    deployment_id: l.deployment_id,
                    target_node: l.target_node,
                    service: l.service,
                    artifact_digest: l.artifact_digest,
                    active_slot: l.active_slot,
                    candidate_slot: l.candidate_slot,
                    ttl_remaining_ms: l.ttl_remaining_ms,
                    promoted: l.promoted,
                })
                .collect();
            Input::Leases(leases)
        }
        FetchKind::RegPackages => {
            let pkgs = match json::<PackagesEnvelope>(body)? {
                PackagesEnvelope::List(v) => v,
                PackagesEnvelope::Envelope { packages } => packages,
            };
            Input::RegPackages(pkgs)
        }
        FetchKind::RegCanaries => {
            let list = match json::<CanariesEnvelope>(body)? {
                CanariesEnvelope::List(v) => v.into_iter().map(CanaryBundleDto::from).collect(),
                CanariesEnvelope::Envelope {
                    mut bundles,
                    canaries,
                    taints,
                } => {
                    if bundles.is_empty() {
                        bundles = canaries;
                    }
                    let mut out: Vec<CanaryBundleDto> =
                        bundles.into_iter().map(CanaryBundleDto::from).collect();
                    for t in taints {
                        let t_hex = t.digest.strip_prefix("sha256:").unwrap_or(&t.digest);
                        let t_prefix = &t_hex[..t_hex.len().min(12)];
                        if let Some(existing) = out.iter_mut().find(|b| {
                            b.artifact_digest == t.digest
                                || (!t_prefix.is_empty() && b.artifact_digest.ends_with(t_prefix))
                        }) {
                            existing.state = CanaryBundleState::Tainted;
                            if existing.taint_reason.is_none() && !t.reason.is_empty() {
                                existing.taint_reason = Some(t.reason);
                            }
                        } else {
                            let bundle_id: String = t.digest.chars().take(12).collect();
                            let trimmed_trace = t.trace_id.trim();
                            let trace_id = if !trimmed_trace.is_empty() {
                                trimmed_trace.to_owned()
                            } else {
                                let token: String = t_hex
                                    .chars()
                                    .filter(char::is_ascii_alphanumeric)
                                    .take(6)
                                    .collect();
                                if !token.is_empty() {
                                    format!("tr-ci-{token}")
                                } else {
                                    format!("tr-reg-{bundle_id}")
                                }
                            };
                            out.push(CanaryBundleDto {
                                bundle_id,
                                owner: "LMA1980".into(),
                                repo: t.service.clone(),
                                service: t.service,
                                artifact_digest: t.digest,
                                state: CanaryBundleState::Tainted,
                                taint_reason: (!t.reason.is_empty()).then_some(t.reason),
                                deployment_id: String::new(),
                                trace_id,
                            });
                        }
                    }
                    out
                }
            };
            Input::RegCanaries(list)
        }
        FetchKind::RegCasStatus => Input::RegCasStatus(json::<CasStatusDto>(body)?),
        FetchKind::ObsSmartscape => Input::ObsSmartscape(json::<SmartscapeDto>(body)?),
        FetchKind::ObsProblems => {
            let list = match json::<ProblemsEnvelope>(body)? {
                ProblemsEnvelope::List(v) => v,
                ProblemsEnvelope::Envelope { problems } => problems,
            };
            Input::ObsProblems(list)
        }
        FetchKind::ObsTraces => {
            let list = match json::<TracesEnvelope>(body)? {
                TracesEnvelope::List(v) => v,
                TracesEnvelope::Envelope { traces } => traces,
            };
            Input::ObsTraces(list)
        }
        FetchKind::ObsTraceDetail(_) => Input::ObsTraceDetail(json::<TraceDto>(body)?),
        FetchKind::ObsLogs => Input::ObsLogsPage(json::<LogsEnvelope>(body)?.into_page()),
        FetchKind::ObsLogsOlder { .. } => {
            Input::ObsLogsOlderPage(json::<LogsEnvelope>(body)?.into_page())
        }
        FetchKind::ObsMetrics => {
            let list = match json::<MetricsEnvelope>(body)? {
                MetricsEnvelope::List(v) => RawMetricPointDto::aggregate_into_series(&v),
                MetricsEnvelope::Envelope {
                    series,
                    metrics,
                    items,
                    points,
                    timeseries,
                    cluster_efficiency,
                } => {
                    let mut raw_points = series.unwrap_or_default();
                    if let Some(m) = metrics {
                        raw_points.extend(m);
                    }
                    if let Some(it) = items {
                        raw_points.extend(it);
                    }
                    if let Some(pts) = points {
                        raw_points.extend(pts);
                    }
                    if let Some(ts) = timeseries {
                        raw_points.extend(ts);
                    }
                    let mut aggregated = RawMetricPointDto::aggregate_into_series(&raw_points);
                    for ce in cluster_efficiency.unwrap_or_default() {
                        aggregated.push(MetricSeriesDto {
                            service: format!("bench ({})", ce.arch),
                            hardware_class: format!(
                                "{} {} (VLEN={})",
                                ce.arch, ce.cpu_cluster, ce.vlen_bits
                            ),
                            rps: ce.run_count,
                            error_rate_bp: 0,
                            p50_ms: ns_to_ms(ce.min_ns_per_iter),
                            p95_ms: ns_to_ms(ce.avg_ns_per_iter),
                            p99_ms: ns_to_ms(ce.max_ns_per_iter),
                            exemplar_trace_id: String::new(),
                            samples: vec![
                                ns_to_u32(ce.min_ns_per_iter),
                                ns_to_u32(ce.avg_ns_per_iter),
                                ns_to_u32(ce.max_ns_per_iter),
                            ],
                        });
                    }
                    aggregated
                }
            };
            Input::ObsMetrics(list)
        }
        FetchKind::ObsStoreStatus => Input::ObsStoreStatus(json::<StoreStatusDto>(body)?),
        FetchKind::ObsIngressOverview => {
            Input::ObsIngressOverview(json::<IngressOverviewDto>(body)?)
        }
        FetchKind::ObsIngressRoutes => Input::ObsIngressRoutes(json::<Vec<IngressRouteDto>>(body)?),
        FetchKind::ObsIngressUpstreams => {
            Input::ObsIngressUpstreams(json::<Vec<IngressUpstreamDto>>(body)?)
        }
        FetchKind::ObsLogsQuery(_) => {
            Input::ObsLogsQueryResult(json::<LogsEnvelope>(body)?.into_otel_list())
        }
        FetchKind::ObsLogsQueryPage { before, .. } => Input::ObsLogsQueryPage {
            page: json::<LogsEnvelope>(body)?.into_page(),
            append: before.is_some(),
        },
        FetchKind::AuthSession
        | FetchKind::AuthRedeem(_)
        | FetchKind::AuthEnableRole(_)
        | FetchKind::AuthDisableRole(_)
        | FetchKind::AuthElevateFinish { .. }
        | FetchKind::AuthRenewRole { .. }
        | FetchKind::AuthLockRoles => Input::AuthSession(parse_auth_session(body.as_bytes())?),
        FetchKind::RestartJob(job_id) => Input::JobRestarted(*job_id),
        FetchKind::ResumeJob(job_id) => Input::JobResumed(*job_id),
        FetchKind::JobDetail(_) => {
            Input::JobDetail(json::<CiQueueJobRecordDto>(body)?.into_unwrapped())
        }
        FetchKind::JobLog(job_id) => Input::JobLog {
            job_id: *job_id,
            lines: sanitize_ansi_log_lines(body, DEFAULT_MAX_JOB_LOG_LINES),
        },
        other => return parse_m2_fetch(other, body),
    })
}

fn parse_m2_fetch(kind: &FetchKind, body: &str) -> Result<Input, String> {
    Ok(match kind {
        FetchKind::CdRuns { .. } => {
            let runs = match json::<CdRunsEnvelope>(body)? {
                CdRunsEnvelope::List(v) => v,
                CdRunsEnvelope::Envelope { runs } => runs,
            };
            Input::CdRuns(runs)
        }
        FetchKind::AbRollback { .. } => {
            Input::AbRollbackResult(json::<AbRollbackResponseDto>(body)?)
        }
        FetchKind::ObsSubsystemStatus => Input::ObsSubsystemStatus(parse_subsystem_entries(body)?),
        FetchKind::SetSubsystemMaintenance { .. } => {
            Input::SubsystemStatusChanged(parse_subsystem_entry(body)?)
        }
        FetchKind::MrStatus => Input::MrStatus(json::<ModelRunnerStatusDto>(body)?),
        FetchKind::MrConnection => Input::MrConnection(json::<ModelRunnerConnectionDto>(body)?),
        FetchKind::AuthProfile | FetchKind::AuthProfilePut { .. } => {
            Input::UserProfile(json::<UserProfileDto>(body)?)
        }
        FetchKind::AuthPasskeys => {
            let list = match json::<PasskeysEnvelope>(body)? {
                PasskeysEnvelope::List(v) => v,
                PasskeysEnvelope::Envelope { passkeys } => passkeys,
            };
            Input::Passkeys(list)
        }
        FetchKind::AuthPasskeyRegisterFinish { .. } => parse_passkey_finish_body(body)?,
        FetchKind::AuthPasskeyDelete { credential_id, .. } => {
            parse_passkey_delete_body(credential_id, body)?
        }
        FetchKind::AuthActivity => {
            let trimmed = body.trim();
            if !trimmed.is_empty() {
                if let Ok(val) = json::<serde_json::Value>(trimmed) {
                    if val.get("authenticated").is_some() || val.get("leases").is_some() {
                        return Ok(Input::AuthSession(
                            serde_json::from_value(val).map_err(|e| e.to_string())?,
                        ));
                    }
                }
            }
            Input::UserActivityRecorded
        }
        FetchKind::AuthRoles => {
            let list = match json::<RolesEnvelope>(body)? {
                RolesEnvelope::List(v) => v,
                RolesEnvelope::Envelope { roles } => roles,
            };
            Input::PlatformRoles(list)
        }
        FetchKind::AuthUpsertRole(fallback) => {
            if let Ok(spec) = serde_json::from_str::<RoleSpecDto>(body) {
                Input::RoleSpecUpserted(spec)
            } else if let Ok(val) = json::<serde_json::Value>(body) {
                if let Some(role) = val.get("role") {
                    Input::RoleSpecUpserted(
                        serde_json::from_value(role.clone()).map_err(|e| e.to_string())?,
                    )
                } else {
                    Input::RoleSpecUpserted(fallback.clone())
                }
            } else {
                Input::RoleSpecUpserted(fallback.clone())
            }
        }
        FetchKind::AuthDeleteRole(id) => Input::RoleSpecDeleted(id.clone()),
        FetchKind::AuthFolios => {
            let list = match json::<FoliosEnvelope>(body)? {
                FoliosEnvelope::List(v) => v,
                FoliosEnvelope::Envelope { folios } => folios,
            };
            Input::PlatformFolios(list)
        }
        FetchKind::AuthUpsertFolio(fallback) => {
            if let Ok(folio) = serde_json::from_str::<PolicyFolioDto>(body) {
                Input::PolicyFolioUpserted(folio)
            } else if let Ok(val) = json::<serde_json::Value>(body) {
                if let Some(folio) = val.get("folio") {
                    Input::PolicyFolioUpserted(
                        serde_json::from_value(folio.clone()).map_err(|e| e.to_string())?,
                    )
                } else {
                    Input::PolicyFolioUpserted(fallback.clone())
                }
            } else {
                Input::PolicyFolioUpserted(fallback.clone())
            }
        }
        FetchKind::AuthDeleteFolio(id) => Input::PolicyFolioDeleted(id.clone()),
        FetchKind::AuthRoleFolioIndex => {
            Input::PlatformRoleFolioIndex(json::<RoleFolioIndexDto>(body)?)
        }
        FetchKind::AuthUpdateRoleFolioIndex(fallback) => {
            if let Ok(idx) = serde_json::from_str::<RoleFolioIndexDto>(body) {
                Input::RoleFolioIndexUpdated(idx)
            } else {
                Input::RoleFolioIndexUpdated(fallback.clone())
            }
        }
        FetchKind::AuthUsers => {
            let list = match json::<UsersEnvelope>(body)? {
                UsersEnvelope::List(v) => v,
                UsersEnvelope::Envelope { users } => users,
            };
            Input::PlatformUsers(list)
        }
        FetchKind::AuthUpdateUserRoles {
            github_login,
            bound_roles,
        } => {
            if let Ok(user) = serde_json::from_str::<PlatformUserDto>(body) {
                Input::PlatformUsersUpsert(user)
            } else {
                Input::UserRolesUpdated {
                    github_login: github_login.clone(),
                    bound_roles: bound_roles.clone(),
                }
            }
        }
        FetchKind::AuthResetUserPasskeys(login) => Input::UserPasskeysReset(login.clone()),
        FetchKind::AuthRevokeUser(login) => Input::UserRevoked(login.clone()),
        FetchKind::AuthInvites => {
            let list = match json::<InvitesEnvelope>(body)? {
                InvitesEnvelope::List(v) => v,
                InvitesEnvelope::Envelope { invites } => invites,
            };
            Input::PlatformInvites(list)
        }
        FetchKind::AuthCreateInvite { .. } => {
            Input::InviteCreated(json::<CreatedInviteResponseDto>(body)?)
        }
        FetchKind::AuthRevokeInvite(id) => Input::InviteRevoked(id.clone()),
        _ => unreachable!("handled in parse_fetch"),
    })
}

/// Decode one SSE event. `Ok(None)` for keep-alives or empty snapshots.
///
/// # Errors
/// Returns the JSON error message for a known kind with a bad payload.
pub fn parse_event(stream: StreamId, event: &str, data: &str) -> Result<Option<Input>, String> {
    let input = match (stream, event) {
        (StreamId::Ci, "branch_created") => Input::BranchCreated(json::<BranchCreatedDto>(data)?),
        (StreamId::Ci, "branch_deleted") => Input::BranchDeleted(json::<BranchDeletedDto>(data)?),
        (StreamId::Ci, "pr_state_changed") => {
            Input::PrStateChanged(json::<PrStateChangedDto>(data)?)
        }
        (StreamId::Ci, "job_stage_changed") => {
            Input::JobStageChanged(json::<JobStageChangedDto>(data)?)
        }
        (StreamId::Ci, "node_membership_changed") => {
            Input::NodeMembership(json::<NodeMembershipChangedDto>(data)?)
        }
        (StreamId::Ci, "queue") => {
            let dto = json::<CiQueueDto>(data)?;
            if dto.active_jobs.is_empty()
                && dto.queued_jobs.is_empty()
                && dto.recent_jobs.is_empty()
                && dto.concurrency == 0
                && dto.queue_depth == 0
            {
                return Ok(None);
            }
            Input::CiQueue(dto)
        }
        (StreamId::Ci, "cluster") => {
            let nodes = match json::<ClusterNodesEnvelope>(data)? {
                ClusterNodesEnvelope::List(v) => v,
                ClusterNodesEnvelope::Envelope { nodes } => nodes,
            };
            if nodes.is_empty() {
                return Ok(None);
            }
            Input::ClusterNodes(nodes)
        }
        (StreamId::Ci, "jobs") => {
            let jobs = match json::<JobsEnvelope>(data)? {
                JobsEnvelope::List(v) => v,
                JobsEnvelope::Envelope { jobs } => jobs,
            };
            if jobs.is_empty() {
                return Ok(None);
            }
            let mut dto = CiQueueDto::default();
            for raw in jobs {
                let rec = raw.into_unwrapped();
                match rec.status.state.as_str() {
                    "Running" => dto.active_jobs.push(rec),
                    "Queued" => dto.queued_jobs.push(rec),
                    _ => dto.recent_jobs.push(rec),
                }
            }
            dto.queue_depth = u32::try_from(dto.queued_jobs.len()).unwrap_or(u32::MAX);
            Input::CiQueue(dto)
        }
        (StreamId::Cd, "it_progress") => Input::ItProgress(json::<ItProgressDto>(data)?),
        (StreamId::Cd, "promoted") => Input::Promoted(json::<PromotedDto>(data)?),
        (StreamId::Cd, "rolled_back") => Input::RolledBack(json::<RolledBackDto>(data)?),
        (StreamId::Cd, "tainted") => Input::Tainted(json::<TaintedDto>(data)?),
        (StreamId::Cd, "lease_expired") => Input::LeaseExpired(json::<LeaseExpiredDto>(data)?),
        (StreamId::Obs, "log_entry") => {
            let entry = json::<RawObsLogItemDto>(data)?.into_otel_dto();
            Input::ObsLogEntry(entry)
        }
        (StreamId::Obs, "problem_opened" | "problem_resolved") => {
            let problem = json::<ProblemDto>(data)?;
            Input::ObsProblemEvent(problem)
        }
        (StreamId::Obs, "ingress_changed") => Input::ObsIngressChanged,
        (StreamId::Obs, "subsystem_status_changed") => {
            Input::SubsystemStatusChanged(parse_subsystem_entry(data)?)
        }
        (StreamId::Obs, "heartbeat") => return Ok(None),
        _ => return Ok(None),
    };
    Ok(Some(input))
}

#[cfg(test)]
pub(crate) mod tests {
    //! The JSON samples here are the ones in `docs/api-contract.md`; keep
    //! them in sync.
    use super::*;
    use mu_console_protocol::dto::LeaseDto;
    use mu_console_protocol::{
        GateOutcome, PrState, RepoStatus, RollbackReason, Slot, StageState, TestState, Visibility,
    };

    pub(crate) const REPOS: &str = r#"[
      {
        "owner": "LMA1980", "repo": "superproject", "visibility": "public",
        "default_branch": "main", "latest_job_id": 1234, "score": 92,
        "coverage": 83.4, "bench_delta": -1.5, "status": "passing",
        "submodules": [
          {"path": "code/engine", "owner": "LMA1980", "repo": "engine", "pinned_sha": "4f2a9c1"}
        ],
        "parents": []
      },
      {"owner": "LMA1980", "repo": "engine", "default_branch": "main",
       "parents": [{"owner": "LMA1980", "repo": "superproject", "path": "code/engine"}],
       "future_field": true}
    ]"#;

    pub(crate) const TOPOLOGY: &str = r#"{
      "owner": "LMA1980", "repo": "superproject", "default_branch": "main",
      "head_sha": "9b8c7d6",
      "stations": [
        {"id": "push", "label": "PUSH"}, {"id": "fmt-check", "label": "FMT"},
        {"id": "clippy-check", "label": "CLIPPY"}, {"id": "merge", "label": "MERGE"}
      ],
      "branches": [
        {"ref": "feat/rvv-gemm", "base_ref": "main", "fork_stage": "push",
         "pr_state": "open", "last_job": 1234}
      ],
      "trains": [
        {"job_id": 1234, "ref": "feat/rvv-gemm", "stage": "clippy-check",
         "stage_states": ["passed", "passed", "running", "pending"], "node_id": "node-a"}
      ],
      "fabric_rev": 482
    }"#;

    pub(crate) const GATE: &str = r#"{
      "deployment_id": "dep-42", "owner": "LMA1980", "repo": "superproject",
      "service": "model-service", "artifact_digest": "sha256:1f2e3d",
      "target_node": "worker-riscv64", "staged_slot": "b", "restore_slot": "a",
      "lease_expires_epoch_ms": 1793560000000, "outcome": "pending",
      "rollback_reason": null, "tainted": false,
      "tests": [
        {"name": "it_boot", "critical": true, "state": "passed", "duration_ms": 1200,
         "crate_name": "engine", "log_excerpt": null},
        {"name": "it_infer", "critical": true, "state": "running", "duration_ms": 0}
      ]
    }"#;

    #[test]
    fn repos_parse_with_defaults_and_unknown_fields() {
        let Input::Repos(r) = parse_fetch(&FetchKind::Repos, REPOS).expect("parse") else {
            panic!("kind");
        };
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].visibility, Visibility::Public);
        assert_eq!(r[0].submodules[0].path, "code/engine");
        assert_eq!(r[1].score, 0);
        assert!(r[1].latest_job_id.is_none());
        assert_eq!(r[1].parents[0].repo, "superproject");
    }

    #[test]
    fn topology_and_gate_parse() {
        let Input::Topology(t) =
            parse_fetch(&FetchKind::Topology(RepoId::new("a", "b")), TOPOLOGY).expect("parse")
        else {
            panic!("kind");
        };
        assert_eq!(t.branches[0].pr_state, PrState::Open);
        assert_eq!(t.trains[0].stage_states[2], StageState::Running);
        assert_eq!(t.fabric_rev, 482);
        let Input::Gate(g) = parse_fetch(&FetchKind::Gate("dep-42".into()), GATE).expect("parse")
        else {
            panic!("kind");
        };
        assert_eq!(g.staged_slot, Slot::B);
        assert_eq!(g.outcome, GateOutcome::Pending);
        assert_eq!(g.tests[1].state, TestState::Running);
        assert!(g.tests[1].crate_name.is_none());
    }

    #[test]
    fn sse_kinds_route_by_stream() {
        let ev = parse_event(
            StreamId::Ci,
            "job_stage_changed",
            r#"{"owner":"o","repo":"r","job_id":7,"ref":"main","stage":"push","state":"failed","fabric_rev":3}"#,
        )
        .expect("parse");
        assert!(matches!(ev, Some(Input::JobStageChanged(j)) if j.state == StageState::Failed));
        let ev = parse_event(
            StreamId::Cd,
            "rolled_back",
            r#"{"deployment_id":"d","restore_slot":"a","reason":"critical_test_failed"}"#,
        )
        .expect("parse");
        assert!(
            matches!(ev, Some(Input::RolledBack(r)) if r.reason == RollbackReason::CriticalTestFailed)
        );
        // Empty queue/cluster snapshots and cross-stream names are ignored.
        assert_eq!(parse_event(StreamId::Ci, "queue", "{}"), Ok(None));
        assert_eq!(parse_event(StreamId::Ci, "cluster", "[]"), Ok(None));
        assert_eq!(parse_event(StreamId::Ci, "jobs", "[]"), Ok(None));
        assert!(matches!(
            parse_event(
                StreamId::Ci,
                "queue",
                r#"{"queue_depth":1,"concurrency":1,"active_jobs":[],"queued_jobs":[],"recent_jobs":[]}"#
            ),
            Ok(Some(Input::CiQueue(q))) if q.queue_depth == 1
        ));
        assert!(matches!(
            parse_event(
                StreamId::Ci,
                "cluster",
                r#"[{"node_id":"worker-riscv64","is_online":true}]"#
            ),
            Ok(Some(Input::ClusterNodes(nodes))) if nodes.len() == 1
        ));
        assert!(matches!(
            parse_event(
                StreamId::Ci,
                "jobs",
                r#"[{"job":{"id":"job-1794054805-5cec9056","repo_name":"LMA1980/mu-console","ref_name":"refs/heads/main","commit_sha":"5cec9056"},"status":{"state":"Running"}}]"#
            ),
            Ok(Some(Input::CiQueue(q))) if q.active_jobs.len() == 1
        ));
        assert_eq!(parse_event(StreamId::Cd, "branch_created", "{}"), Ok(None));
        assert!(parse_event(StreamId::Cd, "tainted", "{not json").is_err());
    }

    #[test]
    fn dto_json_round_trips() {
        let dto: GateDto = serde_json::from_str(GATE).expect("parse");
        let again: GateDto =
            serde_json::from_str(&serde_json::to_string(&dto).expect("ser")).expect("re-parse");
        assert_eq!(dto, again);
        assert!(serde_json::to_string(&dto)
            .expect("ser")
            .contains("\"staged_slot\":\"b\""));
    }

    #[test]
    fn action_runner_controller_contract_samples_deserialize() {
        let ar_repos = r#"{
          "fabric_rev": 482,
          "authenticated": false,
          "repos": [
            {
              "owner": "LMA1980",
              "repo": "parent",
              "visibility": "public",
              "default_branch": "main",
              "latest_job_id": "job-1793563200-44444444",
              "score": 92,
              "coverage": 87.5,
              "bench_delta": 10.0,
              "status": "passing",
              "submodules": [
                { "path": "code/core", "owner": "LMA1980", "repo": "child", "pinned_sha": "aaaaaaaa" }
              ],
              "parents": []
            },
            {
              "owner": "LMA1980",
              "repo": "child",
              "visibility": null,
              "default_branch": "main",
              "latest_job_id": null,
              "score": null,
              "coverage": null,
              "bench_delta": null,
              "status": "unknown",
              "submodules": [],
              "parents": [{ "owner": "LMA1980", "repo": "parent", "path": "code/core" }]
            }
          ]
        }"#;
        let Input::Repos(repos) = parse_fetch(&FetchKind::Repos, ar_repos).expect("ar repos")
        else {
            panic!("kind");
        };
        assert_eq!(repos.len(), 2);
        assert!(repos[0].latest_job_id.is_some());
        assert_eq!(repos[1].status, RepoStatus::Unknown);
        assert_eq!(repos[1].score, 0);

        let ar_summary = r#"{
          "owner": "LMA1980",
          "repo": "parent",
          "visibility": "public",
          "default_branch": "main",
          "branch": "main",
          "status": "passing",
          "latest_job_id": "job-1793563200-44444444",
          "latest_completed_job_id": "job-1793563200-44444444",
          "commit_sha": "4444444444444444444444444444444444444444",
          "score": 92,
          "letter_grade": "A",
          "coverage": 87.5,
          "coverage_bp": 8750,
          "bench_summary": "1 benches (11.0 µs/iter)",
          "bench_delta": 10.0,
          "tests_passed": 10,
          "tests_total": 10,
          "clippy_warnings": 0,
          "advisories_count": 0,
          "updated_at": "2026-11-01T20:00:00Z",
          "history": [
            { "job_id": "job-1793563100-33333333", "commit_sha": "3333", "status": "passed", "score": 88, "coverage": 80.0, "updated_at": "2026-11-01T19:50:00Z" },
            { "job_id": "job-1793563200-44444444", "commit_sha": "4444", "status": "passed", "score": 92, "coverage": 87.5, "updated_at": "2026-11-01T20:00:00Z" }
          ],
          "submodules": [
            { "path": "code/core", "owner": "LMA1980", "repo": "child", "pinned_sha": "aaaa", "score": 95, "letter_grade": "A+", "coverage": 91.2 }
          ]
        }"#;
        let Input::Summary(sum) = parse_fetch(
            &FetchKind::Summary(RepoId::new("LMA1980", "parent")),
            ar_summary,
        )
        .expect("ar summary") else {
            panic!("kind");
        };
        assert_eq!(sum.score, 92);
        assert_eq!(sum.history.len(), 2);

        let ar_topology = r#"{
          "owner": "LMA1980",
          "repo": "railway",
          "default_branch": "main",
          "fabric_rev": 482,
          "stations_source": "workflow",
          "stations": [
            { "id": "fmt", "name": "FMT", "depends_on": [] },
            { "id": "clippy", "name": "CLIPPY", "depends_on": ["fmt"] },
            { "id": "test", "name": "TEST", "depends_on": ["clippy"] }
          ],
          "branches": [
            {
              "ref": "feat/rail",
              "base_ref": "main",
              "fork_stage": "clippy",
              "pr_state": "draft",
              "pr_number": 7,
              "head_sha": "7777",
              "last_job": { "job_id": "job-1793563200-77777777", "status": "running", "commit_sha": "7777", "stage": "clippy" }
            }
          ],
          "trains": [
            {
              "job_id": "job-1793563200-77777777",
              "ref": "feat/rail",
              "status": "running",
              "commit_sha": "7777",
              "stage": "clippy",
              "node_id": "node-a",
              "stage_states": [
                { "station": "fmt", "state": "passed", "node_id": null },
                { "station": "clippy", "state": "running", "node_id": "node-a" },
                { "station": "test", "state": "pending", "node_id": null }
              ]
            }
          ]
        }"#;
        let Input::Topology(topo) = parse_fetch(
            &FetchKind::Topology(RepoId::new("LMA1980", "railway")),
            ar_topology,
        )
        .expect("ar topology") else {
            panic!("kind");
        };
        assert_eq!(topo.stations[1].label, "CLIPPY");
        assert_eq!(topo.branches[0].pr_state, PrState::Open);
        assert_eq!(topo.branches[0].last_job, Some(topo.trains[0].job_id));
        assert_eq!(topo.trains[0].stage_states[1], StageState::Running);

        // SSE events from ActionRunner-controller.
        let bc = parse_event(
            StreamId::Ci,
            "branch_created",
            r#"{"owner":"LMA1980","repo":"railway","ref":"feat/rail","base_ref":"main","fork_stage":null,"head_sha":"7777","fabric_rev":483}"#,
        )
        .expect("branch_created");
        assert!(matches!(bc, Some(Input::BranchCreated(b)) if b.fork_stage.is_empty()));

        let bd = parse_event(
            StreamId::Ci,
            "branch_deleted",
            r#"{"owner":"LMA1980","repo":"railway","ref":"feat/rail","merged":true,"fabric_rev":484}"#,
        )
        .expect("branch_deleted");
        assert!(matches!(bd, Some(Input::BranchDeleted(b)) if b.fabric_rev == 484));

        let pr = parse_event(
            StreamId::Ci,
            "pr_state_changed",
            r#"{"owner":"LMA1980","repo":"railway","ref":"feat/rail","pr_number":7,"pr_state":"merged","previous_state":"open","base_ref":"main","fabric_rev":485}"#,
        )
        .expect("pr_state_changed");
        assert!(matches!(pr, Some(Input::PrStateChanged(p)) if p.pr_state == PrState::Merged));

        let js = parse_event(
            StreamId::Ci,
            "job_stage_changed",
            r#"{"owner":"LMA1980","repo":"railway","job_id":"job-1793563200-77777777","ref":"feat/rail","stage":"clippy","state":"passed","previous_state":"running","node_id":"node-a","fabric_rev":486}"#,
        )
        .expect("job_stage_changed");
        assert!(matches!(js, Some(Input::JobStageChanged(j)) if j.state == StageState::Passed));

        let nm = parse_event(
            StreamId::Ci,
            "node_membership_changed",
            r#"{"node_id":"worker-riscv64","change":"offline","online_nodes":["node-a"],"fabric_rev":487}"#,
        )
        .expect("node_membership_changed");
        assert!(matches!(nm, Some(Input::NodeMembership(n)) if !n.online && n.fabric_rev == 487));
    }

    #[test]
    fn muconde_controller_contract_samples_deserialize() {
        let cd_deployments = r#"[
          {
            "deployment_id": "dep-7f3c",
            "owner": "LMA1980",
            "repo": "example",
            "service": "example-svc",
            "artifact_digest": "sha256:4be1",
            "target_node": "worker-riscv64",
            "active_slot": "b",
            "staged_slot": "b",
            "outcome": "promoted",
            "verdict": "promote",
            "it_passed": 2,
            "it_failed": 0,
            "it_total": 2,
            "critical_failed": 0,
            "rollback_reason": null,
            "tainted": false,
            "started_epoch_ms": 1793563000000,
            "finished_epoch_ms": 1793563012345
          }
        ]"#;
        let Input::Deployments { list, .. } = parse_fetch(
            &FetchKind::Deployments(RepoId::new("LMA1980", "example")),
            cd_deployments,
        )
        .expect("cd deployments") else {
            panic!("kind");
        };
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].outcome, GateOutcome::Promoted);

        let cd_gate = r#"{
          "deployment_id": "dep-7f3c",
          "owner": "LMA1980",
          "repo": "example",
          "service": "example-svc",
          "artifact_digest": "sha256:4be1",
          "target_node": "worker-riscv64",
          "active_slot": "a",
          "staged_slot": "b",
          "restore_slot": "a",
          "lease_id": "lease-91d2",
          "lease_expires_epoch_ms": 1793563300000,
          "lease_ttl_remaining_ms": 287655,
          "outcome": "pending",
          "verdict": "pending",
          "rollback_reason": null,
          "rollback_detail": null,
          "tainted": false,
          "started_epoch_ms": 1793563000000,
          "finished_epoch_ms": null,
          "tests": [
            { "name": "systemd_unit_active", "critical": true, "state": "passed", "duration_ms": 512, "crate_name": null, "log_excerpt": null },
            { "name": "health_endpoint_ready", "critical": true, "state": "running", "duration_ms": 0, "crate_name": null, "log_excerpt": null }
          ]
        }"#;
        let Input::Gate(gate) =
            parse_fetch(&FetchKind::Gate("dep-7f3c".into()), cd_gate).expect("cd gate")
        else {
            panic!("kind");
        };
        assert_eq!(gate.tests.len(), 2);

        let cd_leases = r#"[
          {
            "lease_id": "lease-91d2",
            "deployment_id": "dep-7f3c",
            "target_node": "worker-riscv64",
            "service": "example-svc",
            "artifact_digest": "sha256:4be1",
            "active_slot": "a",
            "candidate_slot": "b",
            "expires_epoch_ms": 1793563300000,
            "ttl_remaining_ms": 287655,
            "promoted": false
          }
        ]"#;
        let leases: Vec<LeaseDto> = serde_json::from_str(cd_leases).expect("cd leases");
        assert_eq!(leases[0].candidate_slot, Slot::B);

        // SSE events from MuConDe-controller.
        let it_ev = parse_event(
            StreamId::Cd,
            "it_progress",
            r#"{"deployment_id":"dep-7f3c","test_name":"health_endpoint_ready","critical":true,"state":"failed","duration_ms":740,"timestamp_epoch_ms":1793563004321}"#,
        )
        .expect("it_progress");
        assert!(matches!(it_ev, Some(Input::ItProgress(p)) if p.state == TestState::Failed));

        let pr_ev = parse_event(
            StreamId::Cd,
            "promoted",
            r#"{"deployment_id":"dep-7f3c","slot":"b"}"#,
        )
        .expect("promoted");
        assert!(matches!(pr_ev, Some(Input::Promoted(p)) if p.slot == Slot::B));

        let rb_ev = parse_event(
            StreamId::Cd,
            "rolled_back",
            r#"{"deployment_id":"dep-7f3c","restore_slot":"a","reason":"critical_test_failed","detail":"Integration tests failed: [\"health_endpoint_ready\"]"}"#,
        )
        .expect("rolled_back");
        assert!(
            matches!(rb_ev, Some(Input::RolledBack(r)) if r.reason == RollbackReason::CriticalTestFailed)
        );

        let tn_ev = parse_event(
            StreamId::Cd,
            "tainted",
            r#"{"deployment_id":"dep-7f3c","artifact_digest":"sha256:4be1","reason":"Integration tests failed"}"#,
        )
        .expect("tainted");
        assert!(matches!(tn_ev, Some(Input::Tainted(t)) if t.deployment_id == "dep-7f3c"));

        let le_ev = parse_event(
            StreamId::Cd,
            "lease_expired",
            r#"{"deployment_id":"dep-7f3c","lease_id":"lease-91d2"}"#,
        )
        .expect("lease_expired");
        assert!(matches!(le_ev, Some(Input::LeaseExpired(l)) if l.deployment_id == "dep-7f3c"));
    }

    #[test]
    fn muregist_and_muobserve_contract_samples_deserialize() {
        let cluster_nodes = r#"[
          {"node_id":"node-a","arch":"x86_64","active_slots":0,"max_slots":1,"is_online":true,"cpu_load_pct":4.2,"ram_used_mb":512,"ram_total_mb":16000},
          {"node_id":"worker-riscv64","arch":"riscv64","active_slots":0,"max_slots":1,"is_online":true,"cpu_load_pct":8.1,"ram_used_mb":1024,"ram_total_mb":32000}
        ]"#;
        let Input::ClusterNodes(nodes) =
            parse_fetch(&FetchKind::ClusterNodes, cluster_nodes).expect("cluster nodes")
        else {
            panic!("kind");
        };
        assert_eq!(nodes.len(), 2);
        assert!(nodes[0].is_online);

        let reg_pkgs = r#"{
          "ecosystem": "all",
          "total": 1,
          "packages": [
            {
              "ecosystem": "cargo",
              "name": "muisolation",
              "latest_version": "0.4.2",
              "sha256": "4a8b91e0c21f00112233",
              "yanked": false,
              "tainted": false,
              "dependency_count": 4
            }
          ]
        }"#;
        let Input::RegPackages(pkgs) =
            parse_fetch(&FetchKind::RegPackages, reg_pkgs).expect("reg packages")
        else {
            panic!("kind");
        };
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].effective_sha256_prefix(), "4a8b91e0");
        assert_eq!(pkgs[0].deps_count, 4);

        let reg_canaries = r#"{
          "status": "all",
          "total_bundles": 1,
          "total_taints": 1,
          "bundles": [
            {
              "bundle_id": "bundle-fa2bf3e5-3b69-41ac-8150-c7260b34c3cb",
              "service_name": "mu-console",
              "binary_digest": "ed4ef429ff61329f9f31d6574c772db3263e65925d76fb979e54b58aa74ec60c",
              "status": "healthy",
              "trace_id": "2c845aa5d1e5b27cf613a435ab41f3f1"
            }
          ],
          "taints": [
            {
              "digest": "sha256:deadbeef9012",
              "service_name": "muregist",
              "reason": "IT regression",
              "trace_id": "tr-reg-taint-01"
            }
          ]
        }"#;
        let Input::RegCanaries(canaries) =
            parse_fetch(&FetchKind::RegCanaries, reg_canaries).expect("reg canaries")
        else {
            panic!("kind");
        };
        assert_eq!(canaries.len(), 2);
        assert_eq!(canaries[0].bundle_id, "cny-fa2b");
        assert_eq!(canaries[0].artifact_digest, "sha256:ed4ef429ff61");
        assert_eq!(canaries[0].deployment_id, "dep-ed4e");
        assert_eq!(canaries[0].state, CanaryBundleState::Promoted);
        assert_eq!(canaries[1].state, CanaryBundleState::Tainted);

        let obs_smartscape = r#"{
          "window_secs": 300,
          "services": [{"id":"svc:muregist","name":"muregist","request_rate_rps":8.9,"error_rate_pct":0.12,"p95_latency_ms":11.2,"health_state":"healthy"}],
          "processes": [{"id":"proc:muregist@node-a","name":"muregist-daemon","health_state":"healthy"}],
          "hosts": [{"id":"host:node-a","name":"node-a","health_state":"healthy"}],
          "edges": [{"source":"svc:muregist","target":"proc:muregist@node-a","relation":"calls","request_rate_rps":8.9,"error_rate_pct":0.12,"p95_latency_ms":11.2}]
        }"#;
        let Input::ObsSmartscape(sm) =
            parse_fetch(&FetchKind::ObsSmartscape, obs_smartscape).expect("obs smartscape")
        else {
            panic!("kind");
        };
        let (sm_nodes, sm_edges) = sm.into_nodes_and_edges();
        assert_eq!(sm_nodes.len(), 3);
        assert_eq!(sm_edges.len(), 1);
        assert_eq!(sm_nodes[0].effective_req_per_sec_bp(), 890);

        let obs_metrics = r#"{
          "metric": "latency",
          "window": "1h",
          "window_secs": 3600,
          "total": 0,
          "series": [],
          "cluster_efficiency": [
            {"arch":"riscv64","cpu_cluster":"A100","vlen_bits":1024,"run_count":42,"avg_ns_per_iter":14000000.0,"min_ns_per_iter":11000000.0,"max_ns_per_iter":17000000.0}
          ]
        }"#;
        let Input::ObsMetrics(metrics) =
            parse_fetch(&FetchKind::ObsMetrics, obs_metrics).expect("obs metrics")
        else {
            panic!("kind");
        };
        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].p50_ms, 11);
        assert_eq!(metrics[0].p95_ms, 14);
        assert_eq!(metrics[0].p99_ms, 17);
        assert_eq!(metrics[0].exemplar_trace_id, "");

        let raw_obs_metrics = r#"{
          "metric": "all",
          "window": "1h",
          "series": [
            {
              "timestamp_ns": 1700000001000000000,
              "service": "muobserve-collector",
              "node_id": "worker-riscv64",
              "metric_name": "host.psi.memory.some_avg60",
              "metric_unit": "%",
              "value_f64": 0.35,
              "arch": "riscv64",
              "cpu_cluster": "X100",
              "vlen_bits": 256
            },
            {
              "timestamp_ns": 1700000002000000000,
              "service": "muobserve-collector",
              "node_id": "worker-riscv64",
              "metric_name": "host.psi.memory.some_avg60",
              "metric_unit": "%",
              "value_f64": 0.65,
              "arch": "riscv64",
              "cpu_cluster": "X100",
              "vlen_bits": 256
            }
          ]
        }"#;
        let Input::ObsMetrics(raw_series) =
            parse_fetch(&FetchKind::ObsMetrics, raw_obs_metrics).expect("raw obs metrics")
        else {
            panic!("kind");
        };
        assert_eq!(raw_series.len(), 1);
        assert_eq!(
            raw_series[0].service,
            "muobserve-collector · host.psi.memory.some_avg60 (%)"
        );
        assert_eq!(
            raw_series[0].hardware_class,
            "worker-riscv64 · riscv64 · X100 · rvv-256"
        );
        assert_eq!(raw_series[0].rps, 2);
        assert_eq!(raw_series[0].samples, vec![35, 65]);

        let null_trace_canaries = r#"{
          "bundles": [
            {
              "bundle_id": "bundle-778899aa-0011",
              "service_name": "muconsole",
              "binary_digest": "sha256:9f82c01a334e",
              "status": "healthy",
              "trace_id": null
            }
          ]
        }"#;
        let Input::RegCanaries(null_canaries) =
            parse_fetch(&FetchKind::RegCanaries, null_trace_canaries).expect("null trace canaries")
        else {
            panic!("kind");
        };
        assert_eq!(null_canaries.len(), 1);
        assert_eq!(null_canaries[0].trace_id, "tr-ci-9f82c0");

        let logs_query_json = r#"{
          "logs": [
            {
              "timestamp_ns": 1700000000000000000,
              "severity": "INFO",
              "service": "mu-query",
              "span_id": "sp-q-1",
              "trace_id": "tr-q-1",
              "message": "Filtered query result"
            }
          ]
        }"#;
        let Input::ObsLogsQueryResult(query_results) =
            parse_fetch(&FetchKind::ObsLogsQuery("query".into()), logs_query_json)
                .expect("obs logs query")
        else {
            panic!("expected ObsLogsQueryResult");
        };
        assert_eq!(query_results.len(), 1);
        assert_eq!(query_results[0].message, "Filtered query result");

        let sse_entry_json = r#"{
          "timestamp_ns": 1700000001000000000,
          "severity": "WARN",
          "service": "mu-sse",
          "span_id": "sp-sse-1",
          "trace_id": "tr-sse-1",
          "message": "Streaming log entry"
        }"#;
        let ev =
            parse_event(StreamId::Obs, "log_entry", sse_entry_json).expect("parse stream event");
        assert!(matches!(ev, Some(Input::ObsLogEntry(entry)) if entry.service == "mu-sse"));
    }

    #[test]
    fn m2_phase3_contract_samples_and_subsystem_sse_deserialize() {
        use mu_console_protocol::{
            CdEcosystem, CdRunState, ConsoleSkin, CrtFont, MaintenanceMode, Slot, SubsystemId,
            SubsystemStatus,
        };

        // Both mu-observable-hub ("mode": "manual", "effective_status": "in-maintenance",
        // "updated_at_ms": ...) and mu-console-protocol SubsystemStatusEntryDto deserialize uniformly.
        let hub_subsystems_json = r#"{
          "subsystems": [
            {
              "subsystem": "ci",
              "effective_status": "live",
              "probe_status": "live",
              "mode": "auto",
              "maintenance_active": false,
              "summary": "All runners nominal",
              "updated_at_ms": 1794000000000
            },
            {
              "subsystem": "cd",
              "effective_status": "in-maintenance",
              "probe_status": "live",
              "mode": "manual",
              "maintenance_active": true,
              "summary": "Planned release cutover",
              "updated_by": "operator",
              "updated_at_ms": 1794000001000,
              "active_incidents": 0
            }
          ]
        }"#;
        let Input::ObsSubsystemStatus(subsystems) =
            parse_fetch(&FetchKind::ObsSubsystemStatus, hub_subsystems_json)
                .expect("obs subsystems")
        else {
            panic!("expected ObsSubsystemStatus");
        };
        assert_eq!(subsystems.len(), 2);
        assert_eq!(subsystems[0].subsystem, SubsystemId::Ci);
        assert_eq!(subsystems[0].effective_status, SubsystemStatus::Live);
        assert_eq!(subsystems[0].mode, MaintenanceMode::Auto);
        assert_eq!(subsystems[1].subsystem, SubsystemId::Cd);
        assert_eq!(
            subsystems[1].effective_status,
            SubsystemStatus::InMaintenance
        );
        assert_eq!(
            subsystems[1].mode,
            MaintenanceMode::Manual(SubsystemStatus::InMaintenance)
        );
        assert_eq!(subsystems[1].updated_by.as_deref(), Some("operator"));

        let sse_sub = r#"{
          "subsystem": "repository",
          "effective_status": "degraded",
          "probe_status": "degraded",
          "mode": "auto",
          "summary": "CAS scrub latency elevated",
          "updated_at_ms": 1794000005000
        }"#;
        let ev =
            parse_event(StreamId::Obs, "subsystem_status_changed", sse_sub).expect("subsystem SSE");
        assert!(matches!(
            ev,
            Some(Input::SubsystemStatusChanged(e))
                if e.subsystem == SubsystemId::Repository
                    && e.effective_status == SubsystemStatus::Degraded
        ));

        let cd_runs_json = r#"[{
          "run_id": "run-cargo-42",
          "ecosystem": "cargo",
          "repo": { "owner": "LMA1980", "repo": "mu-console" },
          "ref_name": "main",
          "commit_sha": "abc12345",
          "state": "failed",
          "started_epoch_ms": 1794000000000,
          "steps": [{
            "step_id": "publish-mu-registry",
            "label": "Publish to MuRegist",
            "state": "failed",
            "duration_ms": 840,
            "failed_package": "mu-console-protocol",
            "exit_code": 1
          }],
          "ab_deployment_id": "dep-42",
          "artifact_digest": "sha256:9f82c01a334e"
        }]"#;
        let Input::CdRuns(runs) = parse_fetch(
            &FetchKind::CdRuns {
                repo: RepoId::new("LMA1980", "mu-console"),
                ecosystem: None,
                limit: 25,
            },
            cd_runs_json,
        )
        .expect("cd runs") else {
            panic!("expected CdRuns");
        };
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].ecosystem, CdEcosystem::Cargo);
        assert_eq!(runs[0].state, CdRunState::Failed);

        let rollback_json = r#"{
          "deployment_id": "dep-42",
          "restored_slot": "a",
          "tainted_digest": "sha256:bad999"
        }"#;
        let Input::AbRollbackResult(rb) = parse_fetch(
            &FetchKind::AbRollback {
                deployment_id: "dep-42".into(),
                note: Some("canary regression".into()),
            },
            rollback_json,
        )
        .expect("rollback response") else {
            panic!("expected AbRollbackResult");
        };
        assert_eq!(rb.restored_slot, Slot::A);
        assert_eq!(rb.tainted_digest.as_deref(), Some("sha256:bad999"));

        let mr_status_json = r#"{
          "total_queue_depth": 2,
          "is_executing": true,
          "estimated_wait_ms": 420,
          "mlock_used_bytes": 12000000000,
          "memlock_ceiling_bytes": 30064771072,
          "models": [{ "model_id": "qwen2.5-coder-7b", "resident_bytes": 8000000000, "state": "loaded" }]
        }"#;
        let Input::MrStatus(mr) =
            parse_fetch(&FetchKind::MrStatus, mr_status_json).expect("mr status")
        else {
            panic!("expected MrStatus");
        };
        assert_eq!(mr.total_queue_depth, 2);
        assert!(mr.is_executing);

        let mr_conn_json = r#"{
          "openai_base_url": "https://192.0.2.10/v1",
          "openai_routes": ["/v1/chat/completions", "/v1/models"],
          "auth_header_guide": "Authorization: Bearer <token>",
          "wireguard_endpoint": "192.0.2.10:51820",
          "tunnel_cidr": "198.51.100.0/24",
          "interface_state": "up",
          "peers": [{ "public_key_prefix": "ab12cd34", "allowed_ips": "198.51.100.2/32" }]
        }"#;
        let Input::MrConnection(conn) =
            parse_fetch(&FetchKind::MrConnection, mr_conn_json).expect("mr conn")
        else {
            panic!("expected MrConnection");
        };
        assert_eq!(conn.interface_state, "up");
        assert_eq!(conn.peers.len(), 1);

        let profile_json = r#"{
          "github_login": "LMA1980",
          "display_name": "Lead Operator",
          "preferences": { "skin": "wireframe", "font": "OpenDyslexic" },
          "passkey_count": 2
        }"#;
        let Input::UserProfile(profile) =
            parse_fetch(&FetchKind::AuthProfile, profile_json).expect("auth profile")
        else {
            panic!("expected UserProfile");
        };
        assert_eq!(profile.preferences.skin, ConsoleSkin::Wireframe);
        assert_eq!(profile.preferences.font, CrtFont::OpenDyslexic);
        assert_eq!(profile.passkey_count, 2);

        let folios_json = r#"{
          "folios": [{ "id": "folio:ci:read", "display_name": "CI Read", "policies": ["ci:queue.read", "ci:jobs.read"] }],
          "policies": [{ "id": "ci:queue.read", "subsystem": "ci", "description": "Read CI queue" }]
        }"#;
        let Input::PlatformFolios(folios) =
            parse_fetch(&FetchKind::AuthFolios, folios_json).expect("auth folios")
        else {
            panic!("expected PlatformFolios");
        };
        assert_eq!(folios.len(), 1);
        assert_eq!(folios[0].policies.len(), 2);
    }

    #[test]
    fn extract_http_error_message_handles_json_plain_html_and_empty() {
        assert_eq!(
            extract_http_error_message(
                "Forbidden",
                Some(r#"{"error":"Invalid Passkey assertion"}"#)
            ),
            "Invalid Passkey assertion"
        );
        assert_eq!(
            extract_http_error_message("Forbidden", Some(r#"{"message":"Step-up expired"}"#)),
            "Step-up expired"
        );
        assert_eq!(
            extract_http_error_message("Forbidden", Some("Role not bound")),
            "Role not bound"
        );
        assert_eq!(
            extract_http_error_message("Bad Gateway", Some("<html><body>502</body></html>")),
            "Bad Gateway"
        );
        assert_eq!(
            extract_http_error_message("HTTP 403", Some("   ")),
            "HTTP 403"
        );
        assert_eq!(extract_http_error_message("HTTP 403", None), "HTTP 403");
    }

    #[test]
    fn paginated_hub_logs_response_and_cursor_decode() {
        let hub_page_json = r#"{
          "severity": "all",
          "total": 2,
          "logs": [
            {
              "timestamp_unix_nano": 1793858300000123456,
              "timestamp_ms": 1793858300000,
              "trace_id": "tr-hub-1",
              "span_id": "",
              "severity_number": 13,
              "severity_text": "WARN",
              "service": "muobserve-collector",
              "service_name": "muobserve-collector",
              "node_id": "worker-riscv64",
              "body": "Batch flush slow",
              "line_no": 7,
              "dedup_hash": 99887766
            }
          ],
          "next_cursor": "1793858300000123456:7:99887766",
          "has_more": true,
          "total_matched": 12450
        }"#;

        let Input::ObsLogsPage(page) =
            parse_fetch(&FetchKind::ObsLogs, hub_page_json).expect("hub obs logs page")
        else {
            panic!("expected ObsLogsPage");
        };
        assert_eq!(page.logs.len(), 1);
        assert_eq!(page.logs[0].timestamp_unix_nano, 1_793_858_300_000_123_456);
        assert_eq!(page.logs[0].line_no, 7);
        assert_eq!(page.logs[0].dedup_hash, 99_887_766);
        assert_eq!(page.logs[0].span_id, None);
        assert_eq!(page.logs[0].severity, LogSeverity::Warn);
        assert_eq!(
            page.next_cursor.as_deref(),
            Some("1793858300000123456:7:99887766")
        );
        assert!(page.has_more);
        assert_eq!(page.total_matched, Some(12_450));

        let Input::ObsLogsQueryPage {
            page: search_page,
            append,
        } = parse_fetch(
            &FetchKind::ObsLogsQueryPage {
                query: "slow".into(),
                before: Some("1793858400000000000:1:2".into()),
                limit: 200,
                gen: 3,
            },
            hub_page_json,
        )
        .expect("hub search page")
        else {
            panic!("expected ObsLogsQueryPage");
        };
        assert!(append);
        assert_eq!(search_page.logs[0].service, "muobserve-collector");
        assert_eq!(search_page.total_matched, Some(12_450));

        // Legacy bare JSON array decodes uniformly via fallback nanos/hash.
        let legacy_json = r#"[{"timestamp_ms":1000,"severity":"INFO","service":"obs","trace_id":"t1","message":"log stays"}]"#;
        let Input::ObsLogsOlderPage(legacy_page) = parse_fetch(
            &FetchKind::ObsLogsOlder {
                before: "2000000000:0:1".into(),
                limit: 200,
                gen: 1,
            },
            legacy_json,
        )
        .expect("legacy array page") else {
            panic!("expected ObsLogsOlderPage");
        };
        assert_eq!(legacy_page.logs.len(), 1);
        assert_eq!(legacy_page.logs[0].timestamp_unix_nano, 1_000_000_000);
        assert_ne!(legacy_page.logs[0].dedup_hash, 0);
        assert!(!legacy_page.has_more);
    }
}
