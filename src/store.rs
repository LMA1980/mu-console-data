// SPDX-License-Identifier: AGPL-3.0-only
//! Normalized store keyed by repository, job and deployment.
//!
//! Every upstream fact (REST payload, SSE event, scenario step) becomes an
//! [`Input`] and goes through [`Store::apply`]; [`Store::view`] projects the
//! store into the canonical [`ViewModel`] for the current selection. Live
//! data and fixture scenarios share this exact path.

use std::collections::BTreeMap;

use mu_console_protocol::dto::{
    parse_job_id_str, AuthSessionDto, BranchCreatedDto, BranchDeletedDto, CanaryBundleDto,
    CasStatusDto, CiQueueDto, CiQueueJobRecordDto, ClusterNodeDto, DeploymentDto, GateDto,
    ItProgressDto, JobStageChangedDto, LeaseExpiredDto, MetricSeriesDto, NodeMembershipChangedDto,
    OtelLogDto, PackageDto, PrStateChangedDto, ProblemDto, PromotedDto, RepoDto, RepoSummaryDto,
    RolledBackDto, SmartscapeDto, StoreStatusDto, TaintedDto, TopologyDto, TraceDto,
};
use mu_console_protocol::{
    format_job_id, sanitize_public_log, AreaBadges, AuthState, Branch, CanaryBundle,
    CanaryBundleState, CasHealth, CdLease, CdScore, CiJobStage, CiJobSummary, DataSource,
    DataStoreHealth, DeploymentGate, DeploymentSummary, FabricNode, FadeReason, GateOutcome,
    GateTest, HardwareMetricSeries, LogSeverity, ObserveView, OtelLogEntry, PackageEcosystem,
    ParentRef, PrState, ProblemCategory, PurePathTrace, RegistryPackage, RegistryView, RepoId,
    RepoScore, RepoStatus, RepoTopology, RollbackReason, SandboxProfileSummary, Selection,
    SidingPhase, SloProblem, Slot, SmartscapeEdge, SmartscapeLayer, SmartscapeNode, StageState,
    Station, SubmoduleRef, TraceSpan, Train, ViewModel,
};

/// A merged or deleted siding is removed this long after it starts fading.
pub const FADE_MS: u64 = 2_000;

/// One upstream fact.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum Input {
    Repos(Vec<RepoDto>),
    ClusterNodes(Vec<ClusterNodeDto>),
    CiQueue(CiQueueDto),
    Summary(RepoSummaryDto),
    Topology(TopologyDto),
    Deployments {
        repo: RepoId,
        list: Vec<DeploymentDto>,
    },
    Gate(GateDto),
    Leases(Vec<CdLease>),
    Sandboxes(Vec<SandboxProfileSummary>),
    RegPackages(Vec<PackageDto>),
    RegCanaries(Vec<CanaryBundleDto>),
    RegCasStatus(CasStatusDto),
    ObsSmartscape(SmartscapeDto),
    ObsProblems(Vec<ProblemDto>),
    ObsTraces(Vec<TraceDto>),
    ObsTraceDetail(TraceDto),
    ObsLogs(Vec<OtelLogDto>),
    ObsMetrics(Vec<MetricSeriesDto>),
    ObsStoreStatus(StoreStatusDto),
    BranchCreated(BranchCreatedDto),
    BranchDeleted(BranchDeletedDto),
    PrStateChanged(PrStateChangedDto),
    JobStageChanged(JobStageChangedDto),
    NodeMembership(NodeMembershipChangedDto),
    ItProgress(ItProgressDto),
    Promoted(PromotedDto),
    RolledBack(RolledBackDto),
    Tainted(TaintedDto),
    LeaseExpired(LeaseExpiredDto),
    Select(Selection),
    /// Operator authentication session state (`/api/auth/session` or `/api/auth/redeem`).
    AuthSession(AuthSessionDto),
    /// Operator restarted a CI job (`POST /api/jobs/{job_id}/restart`).
    JobRestarted(u64),
    /// Operator resumed a CI job (`POST /api/jobs/{job_id}/resume`).
    JobResumed(u64),
    /// Structured job detail & per-stage statuses (`GET /api/jobs/{job_id}`).
    JobDetail(CiQueueJobRecordDto),
    /// Sanitized raw build log lines (`GET /api/jobs/{job_id}/log`).
    JobLog {
        job_id: u64,
        lines: Vec<String>,
    },
    /// Offline snapshot restored from CacheStorage (`saved_epoch_ms`, view).
    Restore {
        saved_epoch_ms: u64,
        view: ViewModel,
    },
}

#[derive(Debug, Clone)]
struct Topo {
    t: RepoTopology,
    head_sha: String,
}

/// Normalized worker state.
#[derive(Debug, Default)]
pub struct Store {
    source: DataSource,
    repos: BTreeMap<RepoId, RepoScore>,
    topologies: BTreeMap<RepoId, Topo>,
    gates: BTreeMap<String, DeploymentGate>,
    history: BTreeMap<RepoId, Vec<DeploymentSummary>>,
    latest: BTreeMap<RepoId, String>,
    nodes: BTreeMap<String, FabricNode>,
    leases: Vec<CdLease>,
    sandboxes: Vec<SandboxProfileSummary>,
    registry: RegistryView,
    observe: ObserveView,
    ci_jobs: Vec<CiJobSummary>,
    job_id_strings: BTreeMap<u64, String>,
    job_logs: BTreeMap<u64, Vec<String>>,
    selection: Option<Selection>,
    auth: AuthState,
    /// Offline snapshot shown until live data arrives.
    offline: Option<(u64, ViewModel)>,
    loaded: bool,
    dirty: bool,
}

fn pct_to_bp(pct: f64) -> u32 {
    if pct.is_nan() {
        return 0;
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let bp = (pct * 100.0).round().clamp(0.0, 10_000.0) as u32;
    bp
}

fn signed_pct_to_bp(pct: f64) -> i32 {
    if pct.is_nan() {
        return 0;
    }
    #[allow(clippy::cast_possible_truncation)]
    let bp = (pct * 100.0).round().clamp(-1_000_000.0, 1_000_000.0) as i32;
    bp
}

fn station_index(stations: &[Station], id: &str) -> u32 {
    stations
        .iter()
        .position(|s| s.id == id)
        .and_then(|i| u32::try_from(i).ok())
        .unwrap_or(0)
}

fn upsert_sorted<T, K: Ord>(v: &mut Vec<T>, item: T, key: impl Fn(&T) -> K) {
    match v.binary_search_by(|x| key(x).cmp(&key(&item))) {
        Ok(i) => v[i] = item,
        Err(i) => v.insert(i, item),
    }
}

fn default_leases() -> Vec<CdLease> {
    vec![
        CdLease {
            lease_id: "lse-042".into(),
            deployment_id: "dep-042".into(),
            target_node: "worker-riscv64".into(),
            service: "muconde-agent".into(),
            artifact_digest: "sha256:9f82c01a334e".into(),
            active_slot: Slot::A,
            candidate_slot: Slot::B,
            ttl_remaining_ms: 42_000,
            promoted: false,
        },
        CdLease {
            lease_id: "lse-041".into(),
            deployment_id: "dep-041".into(),
            target_node: "node-a".into(),
            service: "muregist".into(),
            artifact_digest: "sha256:deadbeef9012".into(),
            active_slot: Slot::A,
            candidate_slot: Slot::B,
            ttl_remaining_ms: 118_000,
            promoted: false,
        },
        CdLease {
            lease_id: "lse-040".into(),
            deployment_id: "dep-040".into(),
            target_node: "node-b".into(),
            service: "muobserve".into(),
            artifact_digest: "sha256:71c4a08823f1".into(),
            active_slot: Slot::B,
            candidate_slot: Slot::B,
            ttl_remaining_ms: 85_000,
            promoted: true,
        },
    ]
}

fn default_sandboxes() -> Vec<SandboxProfileSummary> {
    vec![
        SandboxProfileSummary {
            profile_name: "KernelSandbox::ci-default".into(),
            backend: "LandlockV3+cgroupv2+seccomp".into(),
            max_pids: 256,
            max_slots: 1,
            thread_budget: 6,
            hardware_target: "worker-riscv64 (X100/A100)".into(),
        },
        SandboxProfileSummary {
            profile_name: "KernelSandbox::k3-a100-bench".into(),
            backend: "LandlockV3+set_ai_thread(0xFF00)".into(),
            max_pids: 256,
            max_slots: 1,
            thread_budget: 6,
            hardware_target: "SpacemiT K3 Cluster 1 A100 (VLEN=1024)".into(),
        },
        SandboxProfileSummary {
            profile_name: "HypervisorSandbox::cd-it-gate".into(),
            backend: "KVM(/dev/kvm)+virtio-vsock".into(),
            max_pids: 256,
            max_slots: 1,
            thread_budget: 2,
            hardware_target: "node-a / node-b (VT-x / KVM)".into(),
        },
    ]
}

fn default_registry() -> RegistryView {
    RegistryView {
        packages: vec![
            RegistryPackage {
                ecosystem: PackageEcosystem::Cargo,
                name: "muisolation".into(),
                latest_version: "0.4.2".into(),
                versions_count: 3,
                sha256_prefix: "4a8b91e0c21f".into(),
                deps_count: 4,
                yanked: false,
                tainted: false,
                taint_reason: None,
                versions: vec!["0.4.2".into(), "0.4.1".into(), "0.4.0".into()],
            },
            RegistryPackage {
                ecosystem: PackageEcosystem::Cargo,
                name: "actionrunner-ipc".into(),
                latest_version: "0.3.1".into(),
                versions_count: 2,
                sha256_prefix: "7d31f09aa812".into(),
                deps_count: 3,
                yanked: false,
                tainted: false,
                taint_reason: None,
                versions: vec!["0.3.1".into(), "0.3.0".into()],
            },
            RegistryPackage {
                ecosystem: PackageEcosystem::Cargo,
                name: "muconde-ipc".into(),
                latest_version: "0.3.0".into(),
                versions_count: 2,
                sha256_prefix: "9c20e41b7734".into(),
                deps_count: 5,
                yanked: false,
                tainted: false,
                taint_reason: None,
                versions: vec!["0.3.0".into(), "0.2.9".into()],
            },
            RegistryPackage {
                ecosystem: PackageEcosystem::Cargo,
                name: "k3-kernels-rvv".into(),
                latest_version: "0.2.4".into(),
                versions_count: 3,
                sha256_prefix: "e510ab8819c4".into(),
                deps_count: 2,
                yanked: false,
                tainted: true,
                taint_reason: Some("0.2.3-tainted rolled back on CD gate".into()),
                versions: vec!["0.2.4".into(), "0.2.3-tainted".into(), "0.2.2".into()],
            },
            RegistryPackage {
                ecosystem: PackageEcosystem::NuGet,
                name: "JeroMu.Telemetry.Bridge".into(),
                latest_version: "1.2.0".into(),
                versions_count: 2,
                sha256_prefix: "b8120f44901a".into(),
                deps_count: 6,
                yanked: false,
                tainted: false,
                taint_reason: None,
                versions: vec!["1.2.0".into(), "1.1.0".into()],
            },
            RegistryPackage {
                ecosystem: PackageEcosystem::Maven,
                name: "io.jeromu:muobserve-otlp-exporter".into(),
                latest_version: "0.9.1".into(),
                versions_count: 2,
                sha256_prefix: "c1093e77a12b".into(),
                deps_count: 8,
                yanked: false,
                tainted: false,
                taint_reason: None,
                versions: vec!["0.9.1".into(), "0.9.0".into()],
            },
        ],
        canaries: vec![
            CanaryBundle {
                bundle_id: "cny-042".into(),
                repo: RepoId::new("LMA1980", "MuConDe-agent"),
                service: "muconde-agent".into(),
                artifact_digest: "sha256:9f82c01a334e".into(),
                state: CanaryBundleState::Promoted,
                taint_reason: None,
                deployment_id: "dep-042".into(),
                trace_id: "tr-cd-0042".into(),
            },
            CanaryBundle {
                bundle_id: "cny-041".into(),
                repo: RepoId::new("LMA1980", "MuRegist"),
                service: "muregist".into(),
                artifact_digest: "sha256:deadbeef9012".into(),
                state: CanaryBundleState::Tainted,
                taint_reason: Some("Critical IT regression in it_smoke_cas_verify".into()),
                deployment_id: "dep-041".into(),
                trace_id: "tr-reg-taint-01".into(),
            },
            CanaryBundle {
                bundle_id: "cny-043".into(),
                repo: RepoId::new("LMA1980", "MuConsole"),
                service: "muconsole".into(),
                artifact_digest: "sha256:71c4a08823f1".into(),
                state: CanaryBundleState::Candidate,
                taint_reason: None,
                deployment_id: "dep-043".into(),
                trace_id: "tr-ci-1234".into(),
            },
        ],
        cas: CasHealth {
            blob_count: 14_820,
            dedup_bytes: 3_420_000_000,
            raw_bytes: 8_420_000_000,
            dedup_ratio_bp: 246,
            gc_watermark_pct: 72,
            last_scrub_epoch_ms: 1_700_000_500,
            corrupt_blobs: 0,
        },
    }
}

#[allow(clippy::too_many_lines)]
fn default_observe() -> ObserveView {
    ObserveView {
        smartscape_nodes: vec![
            SmartscapeNode {
                id: "svc:actionrunner-controller".into(),
                label: "actionrunner-controller".into(),
                layer: SmartscapeLayer::Service,
                req_per_sec_bp: 4_250,
                error_rate_bp: 0,
                p95_ms: 18,
                healthy: true,
            },
            SmartscapeNode {
                id: "svc:muregist".into(),
                label: "muregist".into(),
                layer: SmartscapeLayer::Service,
                req_per_sec_bp: 8_900,
                error_rate_bp: 120,
                p95_ms: 11,
                healthy: true,
            },
            SmartscapeNode {
                id: "svc:muconde-controller".into(),
                label: "muconde-controller".into(),
                layer: SmartscapeLayer::Service,
                req_per_sec_bp: 1_850,
                error_rate_bp: 0,
                p95_ms: 14,
                healthy: true,
            },
            SmartscapeNode {
                id: "svc:muobserve".into(),
                label: "muobserve".into(),
                layer: SmartscapeLayer::Service,
                req_per_sec_bp: 12_400,
                error_rate_bp: 0,
                p95_ms: 24,
                healthy: true,
            },
            SmartscapeNode {
                id: "proc:actionrunner-rs@worker-riscv64".into(),
                label: "actionrunner-rs (K3)".into(),
                layer: SmartscapeLayer::Process,
                req_per_sec_bp: 2_100,
                error_rate_bp: 0,
                p95_ms: 22,
                healthy: true,
            },
            SmartscapeNode {
                id: "proc:muconde-agent@worker-riscv64".into(),
                label: "muconde-agent (K3)".into(),
                layer: SmartscapeLayer::Process,
                req_per_sec_bp: 950,
                error_rate_bp: 0,
                p95_ms: 9,
                healthy: true,
            },
            SmartscapeNode {
                id: "proc:muregist-daemon@node-a".into(),
                label: "muregist-daemon".into(),
                layer: SmartscapeLayer::Process,
                req_per_sec_bp: 8_900,
                error_rate_bp: 120,
                p95_ms: 11,
                healthy: true,
            },
            SmartscapeNode {
                id: "host:node-a".into(),
                label: "node-a (192.0.2.101)".into(),
                layer: SmartscapeLayer::Host,
                req_per_sec_bp: 9_400,
                error_rate_bp: 0,
                p95_ms: 6,
                healthy: true,
            },
            SmartscapeNode {
                id: "host:node-b".into(),
                label: "node-b (192.0.2.102)".into(),
                layer: SmartscapeLayer::Host,
                req_per_sec_bp: 6_200,
                error_rate_bp: 0,
                p95_ms: 7,
                healthy: true,
            },
            SmartscapeNode {
                id: "host:worker-riscv64".into(),
                label: "worker-riscv64 (192.0.2.117)".into(),
                layer: SmartscapeLayer::Host,
                req_per_sec_bp: 3_050,
                error_rate_bp: 0,
                p95_ms: 8,
                healthy: true,
            },
        ],
        smartscape_edges: vec![
            SmartscapeEdge {
                from_id: "svc:actionrunner-controller".into(),
                to_id: "proc:actionrunner-rs@worker-riscv64".into(),
                protocol: "mTLS/gRPC".into(),
                call_rate_rps: 42,
                error_rate_bp: 0,
                p95_ms: 18,
            },
            SmartscapeEdge {
                from_id: "svc:muregist".into(),
                to_id: "proc:muregist-daemon@node-a".into(),
                protocol: "mTLS/HTTPS".into(),
                call_rate_rps: 89,
                error_rate_bp: 120,
                p95_ms: 11,
            },
            SmartscapeEdge {
                from_id: "svc:muconde-controller".into(),
                to_id: "proc:muconde-agent@worker-riscv64".into(),
                protocol: "mTLS/Lease".into(),
                call_rate_rps: 18,
                error_rate_bp: 0,
                p95_ms: 14,
            },
            SmartscapeEdge {
                from_id: "proc:actionrunner-rs@worker-riscv64".into(),
                to_id: "host:worker-riscv64".into(),
                protocol: "KernelSandbox".into(),
                call_rate_rps: 21,
                error_rate_bp: 0,
                p95_ms: 4,
            },
            SmartscapeEdge {
                from_id: "proc:muconde-agent@worker-riscv64".into(),
                to_id: "host:worker-riscv64".into(),
                protocol: "systemd-slot".into(),
                call_rate_rps: 10,
                error_rate_bp: 0,
                p95_ms: 3,
            },
            SmartscapeEdge {
                from_id: "proc:muregist-daemon@node-a".into(),
                to_id: "host:node-a".into(),
                protocol: "CAS-fs".into(),
                call_rate_rps: 89,
                error_rate_bp: 0,
                p95_ms: 5,
            },
        ],
        traces: vec![
            PurePathTrace {
                trace_id: "tr-ci-1234".into(),
                root_service: "actionrunner-controller".into(),
                root_operation: "ci.pipeline.verify (job #1234)".into(),
                domain: "CI".into(),
                duration_ms: 4_820,
                error: false,
                slow_p99: false,
                started_epoch_ms: 1_700_000_100,
                spans: vec![
                    TraceSpan {
                        span_id: "sp-ci-01".into(),
                        parent_span_id: None,
                        service: "actionrunner-controller".into(),
                        operation: "webhook.dispatch".into(),
                        start_offset_us: 0,
                        duration_us: 120_000,
                        self_time_us: 45_000,
                        critical_path: true,
                        error: false,
                        hardware_class: "node-a (x86_64)".into(),
                    },
                    TraceSpan {
                        span_id: "sp-ci-02".into(),
                        parent_span_id: Some("sp-ci-01".into()),
                        service: "actionrunner-rs".into(),
                        operation: "muisolation.sandbox.exec (cargo test + miri)".into(),
                        start_offset_us: 120_000,
                        duration_us: 4_410_000,
                        self_time_us: 4_120_000,
                        critical_path: true,
                        error: false,
                        hardware_class: "worker-riscv64 (K3 X100)".into(),
                    },
                    TraceSpan {
                        span_id: "sp-ci-03".into(),
                        parent_span_id: Some("sp-ci-02".into()),
                        service: "muregist".into(),
                        operation: "cas.upload_canary_bundle".into(),
                        start_offset_us: 4_530_000,
                        duration_us: 290_000,
                        self_time_us: 290_000,
                        critical_path: true,
                        error: false,
                        hardware_class: "node-a (CAS)".into(),
                    },
                ],
            },
            PurePathTrace {
                trace_id: "tr-reg-taint-01".into(),
                root_service: "muconde-controller".into(),
                root_operation: "cd.gate.verify_canary (dep-041)".into(),
                domain: "REGISTRY".into(),
                duration_ms: 3_150,
                error: true,
                slow_p99: true,
                started_epoch_ms: 1_700_000_200,
                spans: vec![
                    TraceSpan {
                        span_id: "sp-taint-01".into(),
                        parent_span_id: None,
                        service: "muconde-controller".into(),
                        operation: "slot.stage_b (dep-041)".into(),
                        start_offset_us: 0,
                        duration_us: 310_000,
                        self_time_us: 110_000,
                        critical_path: true,
                        error: false,
                        hardware_class: "node-a (x86_64)".into(),
                    },
                    TraceSpan {
                        span_id: "sp-taint-02".into(),
                        parent_span_id: Some("sp-taint-01".into()),
                        service: "muconde-agent".into(),
                        operation: "it.run_critical (it_smoke_cas_verify)".into(),
                        start_offset_us: 310_000,
                        duration_us: 2_420_000,
                        self_time_us: 2_420_000,
                        critical_path: true,
                        error: true,
                        hardware_class: "worker-riscv64 (K3 X100)".into(),
                    },
                    TraceSpan {
                        span_id: "sp-taint-03".into(),
                        parent_span_id: Some("sp-taint-01".into()),
                        service: "muregist".into(),
                        operation: "canary.mark_tainted (cny-041)".into(),
                        start_offset_us: 2_730_000,
                        duration_us: 420_000,
                        self_time_us: 420_000,
                        critical_path: true,
                        error: true,
                        hardware_class: "node-a (CAS)".into(),
                    },
                ],
            },
            PurePathTrace {
                trace_id: "tr-cd-0042".into(),
                root_service: "muconde-controller".into(),
                root_operation: "cd.promote_slot_b (dep-042)".into(),
                domain: "CD".into(),
                duration_ms: 1_940,
                error: false,
                slow_p99: false,
                started_epoch_ms: 1_700_000_300,
                spans: vec![
                    TraceSpan {
                        span_id: "sp-cd-01".into(),
                        parent_span_id: None,
                        service: "muconde-controller".into(),
                        operation: "lease.acquire (lse-042)".into(),
                        start_offset_us: 0,
                        duration_us: 180_000,
                        self_time_us: 180_000,
                        critical_path: true,
                        error: false,
                        hardware_class: "worker-riscv64 (192.0.2.117)".into(),
                    },
                    TraceSpan {
                        span_id: "sp-cd-02".into(),
                        parent_span_id: Some("sp-cd-01".into()),
                        service: "muconde-agent".into(),
                        operation: "it.suite.all_critical".into(),
                        start_offset_us: 180_000,
                        duration_us: 1_760_000,
                        self_time_us: 1_760_000,
                        critical_path: true,
                        error: false,
                        hardware_class: "worker-riscv64 (K3 A100)".into(),
                    },
                ],
            },
            PurePathTrace {
                trace_id: "tr-obs-p99-07".into(),
                root_service: "muobserve".into(),
                root_operation: "bench.k3.cluster_stratified".into(),
                domain: "CI".into(),
                duration_ms: 6_410,
                error: false,
                slow_p99: true,
                started_epoch_ms: 1_700_000_400,
                spans: vec![
                    TraceSpan {
                        span_id: "sp-obs-01".into(),
                        parent_span_id: None,
                        service: "muobserve".into(),
                        operation: "k3.x100.scalar_rvv256_probe".into(),
                        start_offset_us: 0,
                        duration_us: 2_110_000,
                        self_time_us: 2_110_000,
                        critical_path: true,
                        error: false,
                        hardware_class: "Cluster 0 X100 (0x00FF) VLEN=256".into(),
                    },
                    TraceSpan {
                        span_id: "sp-obs-02".into(),
                        parent_span_id: Some("sp-obs-01".into()),
                        service: "muobserve".into(),
                        operation: "k3.a100.xsmtvdotii_matrix_probe".into(),
                        start_offset_us: 2_110_000,
                        duration_us: 4_300_000,
                        self_time_us: 4_300_000,
                        critical_path: true,
                        error: false,
                        hardware_class: "Cluster 1 A100 (0xFF00) VLEN=1024 smt.vmadot".into(),
                    },
                ],
            },
        ],
        problems: vec![
            SloProblem {
                problem_id: "PRB-104".into(),
                title: "Canary Taint & Automatic Slot Rollback on muregist".into(),
                category: ProblemCategory::CanaryTaint,
                severity: "ERROR".into(),
                burn_rate_bp: 420,
                impacted_entity: "svc:muregist (cny-041 / dep-041)".into(),
                root_cause_trace_id: "tr-reg-taint-01".into(),
                active: true,
            },
            SloProblem {
                problem_id: "PRB-101".into(),
                title: "SpacemiT K3 Cluster 0 vs Cluster 1 Matmul Tail Variance".into(),
                category: ProblemCategory::LatencyRegression,
                severity: "WARN".into(),
                burn_rate_bp: 185,
                impacted_entity: "k3-kernels-rvv (X100 VLEN=256 vs A100 VLEN=1024)".into(),
                root_cause_trace_id: "tr-obs-p99-07".into(),
                active: true,
            },
        ],
        logs: vec![
            OtelLogEntry {
                timestamp_ms: 1_700_000_510,
                severity: LogSeverity::Error,
                service: "muconde-agent".into(),
                span_id: Some("sp-taint-02".into()),
                trace_id: "tr-reg-taint-01".into(),
                message: sanitize_public_log(
                    "IT gate failure on 192.0.2.117 (/var/lib/muconde/slots/b/verify.rs): digest mismatch -> taint cny-041",
                ),
            },
            OtelLogEntry {
                timestamp_ms: 1_700_000_520,
                severity: LogSeverity::Warn,
                service: "muobserve".into(),
                span_id: Some("sp-obs-02".into()),
                trace_id: "tr-obs-p99-07".into(),
                message: sanitize_public_log(
                    "K3 benchmark delta on worker-riscv64 (192.0.2.117): X100 VLEN=256 p99=2110ms vs A100 VLEN=1024",
                ),
            },
            OtelLogEntry {
                timestamp_ms: 1_700_000_530,
                severity: LogSeverity::Info,
                service: "actionrunner-rs".into(),
                span_id: Some("sp-ci-02".into()),
                trace_id: "tr-ci-1234".into(),
                message: sanitize_public_log(
                    "Completed 7/7 verification stages in /var/lib/action-runner/work/MuConsole on worker-riscv64",
                ),
            },
            OtelLogEntry {
                timestamp_ms: 1_700_000_540,
                severity: LogSeverity::Info,
                service: "muconde-controller".into(),
                span_id: Some("sp-cd-02".into()),
                trace_id: "tr-cd-0042".into(),
                message: sanitize_public_log(
                    "Promoted deployment dep-042 to active slot B on 192.0.2.117",
                ),
            },
        ],
        metrics: vec![
            HardwareMetricSeries {
                service: "k3-kernels-rvv".into(),
                hardware_class: "Cluster 1 A100 (cores 8-15, VLEN=1024, XSMTVDotII)".into(),
                rps: 118,
                error_rate_bp: 0,
                p50_ms: 11,
                p95_ms: 14,
                p99_ms: 17,
                exemplar_trace_id: "tr-obs-p99-07".into(),
                samples: vec![1140, 1158, 1172, 1165, 1180, 1184, 1179, 1188],
            },
            HardwareMetricSeries {
                service: "k3-kernels-rvv".into(),
                hardware_class: "Cluster 0 X100 (cores 0-7, VLEN=256, Out-of-Order)".into(),
                rps: 94,
                error_rate_bp: 0,
                p50_ms: 19,
                p95_ms: 23,
                p99_ms: 28,
                exemplar_trace_id: "tr-obs-p99-07".into(),
                samples: vec![138, 141, 140, 143, 142, 144, 141, 142],
            },
            HardwareMetricSeries {
                service: "actionrunner-rs".into(),
                hardware_class: "Fabric CI Stage Latency (max_slots=1, threads=6)".into(),
                rps: 42,
                error_rate_bp: 0,
                p50_ms: 46,
                p95_ms: 48,
                p99_ms: 49,
                exemplar_trace_id: "tr-ci-1234".into(),
                samples: vec![462, 451, 489, 472, 482, 468, 459, 471],
            },
        ],
        store: DataStoreHealth {
            hot_duckdb_rows: 1_482_900,
            hot_duckdb_bytes: 312_400_000,
            cold_parquet_partitions: 428,
            cold_parquet_rows: 48_920_000,
            cold_parquet_bytes: 4_890_000_000,
            zstd_compression_bp: 385,
            retention_days: 90,
            oldest_watermark_iso: "2026-08-05T00:00:00Z".into(),
        },
    }
}

impl Store {
    #[must_use]
    pub fn new(source: DataSource) -> Self {
        let auth = match &source {
            DataSource::Scenario(_) => AuthState::Operator {
                github_login: "operator".into(),
                role: Some("operator".into()),
            },
            DataSource::Live | DataSource::OfflineCache => AuthState::Anonymous,
        };
        Self {
            source,
            auth,
            dirty: true,
            ..Self::default()
        }
    }

    /// Whether the projected view may have changed since [`Self::take_dirty`].
    #[must_use]
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Read and clear the dirty flag.
    pub fn take_dirty(&mut self) -> bool {
        std::mem::take(&mut self.dirty)
    }

    /// Whether live (or scenario) data has arrived.
    #[must_use]
    pub fn has_live_data(&self) -> bool {
        self.loaded
    }

    #[must_use]
    pub fn selection(&self) -> Option<&Selection> {
        self.selection.as_ref()
    }

    /// Current operator authentication state.
    #[must_use]
    pub fn auth(&self) -> &AuthState {
        &self.auth
    }

    /// Repository whose topology the selection shows (submodule repo when a
    /// submodule is selected).
    #[must_use]
    pub fn topology_repo(&self) -> Option<RepoId> {
        let sel = self.selection.as_ref()?;
        match &sel.submodule {
            None => Some(sel.repo.clone()),
            Some(sub) => self
                .repos
                .get(&sel.repo)?
                .submodules
                .iter()
                .find(|s| s.path == sub.path)
                .map(|s| s.repo.clone()),
        }
    }

    /// Latest deployment id of a repository, if known.
    #[must_use]
    pub fn latest_deployment(&self, repo: &RepoId) -> Option<&str> {
        self.latest.get(repo).map(String::as_str)
    }

    /// Whether the gate of a deployment is loaded.
    #[must_use]
    pub fn has_gate(&self, id: &str) -> bool {
        self.gates.contains_key(id)
    }

    /// Whether a topology is loaded for a repository.
    #[must_use]
    pub fn has_topology(&self, repo: &RepoId) -> bool {
        self.topologies.contains_key(repo)
    }

    /// Latest known `job_id` for `repo` (from `/api/repos`, `/summary`, or `/topology`).
    #[must_use]
    pub fn repo_latest_job(&self, repo: &RepoId) -> Option<u64> {
        self.repos
            .get(repo)
            .and_then(|r| r.latest_job_id)
            .or_else(|| {
                self.topologies
                    .get(repo)
                    .and_then(|t| t.t.trains.first().map(|tr| tr.job_id))
            })
    }

    /// Ordered repository ids.
    pub fn repo_ids(&self) -> impl Iterator<Item = &RepoId> {
        self.repos.keys()
    }

    /// Change the data source label.
    pub fn set_source(&mut self, source: DataSource) {
        if self.source != source {
            self.source = source;
            self.dirty = true;
        }
    }

    /// Resolve a `u64` `job_id` back to its canonical string identifier
    /// (`"job-{ts}-{sha8}"` when known, or decimal fallback).
    #[must_use]
    pub fn resolve_job_id_str(&self, job_id: u64) -> String {
        self.job_id_strings
            .get(&job_id)
            .cloned()
            .unwrap_or_else(|| job_id.to_string())
    }

    fn record_job_id_str(&mut self, job_id: u64, raw_id: &str, commit_sha: &str) {
        if job_id == 0 {
            return;
        }
        if !raw_id.is_empty() {
            self.job_id_strings.insert(job_id, raw_id.to_owned());
        } else if (job_id >> 24) >= 1_000_000_000 && commit_sha.len() >= 8 {
            let ts = job_id >> 24;
            let sha8: String = commit_sha.chars().take(8).collect();
            self.job_id_strings
                .entry(job_id)
                .or_insert_with(|| format!("job-{ts}-{sha8}"));
        }
    }

    fn ensure_aux_defaults(&mut self) {
        if self.sandboxes.is_empty() {
            self.sandboxes = default_sandboxes();
        }
        if matches!(self.source, DataSource::Scenario(_)) {
            if self.leases.is_empty() {
                self.leases = default_leases();
            }
            if self.registry.packages.is_empty() {
                self.registry = default_registry();
            }
            if self.observe.smartscape_nodes.is_empty() {
                self.observe = default_observe();
            }
        }
    }

    /// Apply one input. Returns whether anything changed.
    #[allow(clippy::too_many_lines)]
    pub fn apply(&mut self, input: Input, now_ms: u64) -> bool {
        let changed = match input {
            Input::Repos(list) => self.repos_loaded(list),
            Input::ClusterNodes(list) => {
                self.loaded = true;
                self.ensure_aux_defaults();
                for n in list {
                    let clean_id = sanitize_public_log(&n.node_id);
                    let cpu_load_bp = n.cpu_load_bp();
                    let arch = if n.arch.is_empty() {
                        if clean_id.contains("riscv64") {
                            "riscv64".into()
                        } else {
                            "x86_64".into()
                        }
                    } else {
                        sanitize_public_log(&n.arch)
                    };
                    let tags = n
                        .tags
                        .into_iter()
                        .map(|t| sanitize_public_log(&t))
                        .collect();
                    let toolchains = n
                        .toolchains
                        .into_iter()
                        .map(|t| sanitize_public_log(&t))
                        .collect();
                    self.nodes.insert(
                        clean_id.clone(),
                        FabricNode {
                            id: clean_id.clone(),
                            online: n.is_online,
                            arch: arch.clone(),
                            active_slots: n.active_slots,
                            max_slots: n.max_slots.max(1),
                            cpu_load_bp,
                            ram_used_mb: n.ram_used_mb,
                            ram_total_mb: n.ram_total_mb,
                            btrfs_enabled: n.btrfs_enabled,
                            exclusive_locked: n.exclusive_locked,
                            last_seen_secs_ago: n.last_seen_secs_ago,
                            tags,
                            toolchains,
                        },
                    );
                    let host_id = format!("host:{clean_id}");
                    let host_label = format!("{clean_id} ({arch})");
                    if let Some(sn) = self
                        .observe
                        .smartscape_nodes
                        .iter_mut()
                        .find(|s| s.id == host_id)
                    {
                        sn.label = host_label;
                        sn.healthy = n.is_online;
                    } else {
                        self.observe.smartscape_nodes.push(SmartscapeNode {
                            id: host_id.clone(),
                            label: host_label,
                            layer: SmartscapeLayer::Host,
                            req_per_sec_bp: cpu_load_bp,
                            error_rate_bp: 0,
                            p95_ms: 6,
                            healthy: n.is_online,
                        });
                    }
                    let proc_id = format!("proc:action-runner@{clean_id}");
                    let proc_label = format!(
                        "action-runner ({clean_id}, {}/{} slots)",
                        n.active_slots,
                        n.max_slots.max(1)
                    );
                    if let Some(pn) = self
                        .observe
                        .smartscape_nodes
                        .iter_mut()
                        .find(|s| s.id == proc_id)
                    {
                        pn.label = proc_label;
                        pn.req_per_sec_bp = cpu_load_bp.max(100);
                        pn.healthy = n.is_online;
                    } else {
                        self.observe.smartscape_nodes.push(SmartscapeNode {
                            id: proc_id.clone(),
                            label: proc_label,
                            layer: SmartscapeLayer::Process,
                            req_per_sec_bp: cpu_load_bp.max(100),
                            error_rate_bp: 0,
                            p95_ms: 12,
                            healthy: n.is_online,
                        });
                    }
                    let svc_id = "svc:action-runner-controller";
                    if !self
                        .observe
                        .smartscape_edges
                        .iter()
                        .any(|e| e.from_id == svc_id && e.to_id == proc_id)
                    {
                        self.observe.smartscape_edges.push(SmartscapeEdge {
                            from_id: svc_id.into(),
                            to_id: proc_id.clone(),
                            protocol: "HTTPS/mTLS".into(),
                            call_rate_rps: 4,
                            error_rate_bp: 0,
                            p95_ms: 8,
                        });
                    }
                    if !self
                        .observe
                        .smartscape_edges
                        .iter()
                        .any(|e| e.from_id == proc_id && e.to_id == host_id)
                    {
                        self.observe.smartscape_edges.push(SmartscapeEdge {
                            from_id: proc_id,
                            to_id: host_id,
                            protocol: "cgroupv2/MuIsolation".into(),
                            call_rate_rps: 4,
                            error_rate_bp: 0,
                            p95_ms: 2,
                        });
                    }
                }
                if !self
                    .observe
                    .smartscape_nodes
                    .iter()
                    .any(|s| s.layer == SmartscapeLayer::Service)
                {
                    for (id, label, rps_bp, p95_ms) in [
                        (
                            "svc:action-runner-controller",
                            "ActionRunner Controller (CI)",
                            420,
                            8,
                        ),
                        ("svc:muconde-controller", "MuConDe Controller (CD)", 120, 6),
                        ("svc:muregist", "MuRegist Artifact CAS (REG)", 180, 5),
                        (
                            "svc:muobserve-collector",
                            "MuObserve OTel Collector (OBS)",
                            310,
                            4,
                        ),
                    ] {
                        self.observe.smartscape_nodes.push(SmartscapeNode {
                            id: id.into(),
                            label: label.into(),
                            layer: SmartscapeLayer::Service,
                            req_per_sec_bp: rps_bp,
                            error_rate_bp: 0,
                            p95_ms,
                            healthy: true,
                        });
                    }
                }
                true
            }
            Input::CiQueue(dto) => self.apply_ci_queue(dto),
            Input::Summary(s) => self.summary(&s),
            Input::Topology(t) => self.topology(t),
            Input::Deployments { repo, list } => self.deployments(&repo, &list),
            Input::Gate(g) => self.gate(g),
            Input::Leases(list) => {
                self.loaded = true;
                self.ensure_aux_defaults();
                if self.source == DataSource::Live || !list.is_empty() {
                    self.leases = list
                        .into_iter()
                        .map(|mut l| {
                            l.target_node = sanitize_public_log(&l.target_node);
                            l
                        })
                        .collect();
                }
                true
            }
            Input::Sandboxes(list) => {
                self.loaded = true;
                self.ensure_aux_defaults();
                if !list.is_empty() {
                    self.sandboxes = list;
                }
                true
            }
            Input::RegPackages(list) => {
                self.loaded = true;
                self.ensure_aux_defaults();
                if self.source == DataSource::Live || !list.is_empty() {
                    self.registry.packages = list
                        .into_iter()
                        .map(|d| {
                            let sha256_prefix = d.effective_sha256_prefix();
                            let versions = if d.versions.is_empty() && !d.latest_version.is_empty()
                            {
                                vec![d.latest_version.clone()]
                            } else {
                                d.versions
                            };
                            let versions_count = d
                                .versions_count
                                .max(u32::try_from(versions.len()).unwrap_or(0).max(1));
                            RegistryPackage {
                                ecosystem: d.ecosystem,
                                name: d.name,
                                latest_version: d.latest_version,
                                versions_count,
                                sha256_prefix,
                                deps_count: d.deps_count,
                                yanked: d.yanked,
                                tainted: d.tainted,
                                taint_reason: d.taint_reason.map(|r| sanitize_public_log(&r)),
                                versions,
                            }
                        })
                        .collect();
                }
                true
            }
            Input::RegCanaries(list) => {
                self.loaded = true;
                self.ensure_aux_defaults();
                if self.source == DataSource::Live || !list.is_empty() {
                    self.registry.canaries = list
                        .into_iter()
                        .map(|d| {
                            let owner = if d.owner.is_empty() {
                                "LMA1980"
                            } else {
                                d.owner.as_str()
                            };
                            let repo_name = if d.repo.is_empty() {
                                d.service.as_str()
                            } else {
                                d.repo.as_str()
                            };
                            CanaryBundle {
                                bundle_id: d.bundle_id,
                                repo: RepoId::new(owner, repo_name),
                                service: d.service,
                                artifact_digest: d.artifact_digest,
                                state: d.state,
                                taint_reason: d.taint_reason.map(|r| sanitize_public_log(&r)),
                                deployment_id: d.deployment_id,
                                trace_id: d.trace_id,
                            }
                        })
                        .collect();
                }
                true
            }
            Input::RegCasStatus(d) => {
                self.loaded = true;
                self.ensure_aux_defaults();
                let raw_bytes = d.effective_raw_bytes();
                self.registry.cas = CasHealth {
                    blob_count: d.blob_count,
                    dedup_bytes: d.dedup_bytes,
                    raw_bytes,
                    dedup_ratio_bp: d.dedup_ratio_bp,
                    gc_watermark_pct: d.gc_watermark_pct,
                    last_scrub_epoch_ms: d.last_scrub_epoch_ms,
                    corrupt_blobs: d.corrupt_blobs,
                };
                true
            }
            Input::ObsSmartscape(d) => {
                self.loaded = true;
                self.ensure_aux_defaults();
                let (nodes, edges) = d.into_nodes_and_edges();
                if !nodes.is_empty() {
                    self.observe.smartscape_nodes = nodes
                        .into_iter()
                        .map(|n| {
                            let req_per_sec_bp = n.effective_req_per_sec_bp();
                            let error_rate_bp = n.effective_error_rate_bp();
                            let p95_ms = n.effective_p95_ms();
                            let healthy = n.effective_healthy();
                            let label = if n.label.is_empty() {
                                sanitize_public_log(&n.id)
                            } else {
                                sanitize_public_log(&n.label)
                            };
                            SmartscapeNode {
                                id: sanitize_public_log(&n.id),
                                label,
                                layer: n.layer,
                                req_per_sec_bp,
                                error_rate_bp,
                                p95_ms,
                                healthy,
                            }
                        })
                        .collect();
                }
                if !edges.is_empty() {
                    self.observe.smartscape_edges = edges
                        .into_iter()
                        .map(|e| {
                            let call_rate_rps = e.effective_call_rate_rps();
                            let error_rate_bp = e.effective_error_rate_bp();
                            let p95_ms = e.effective_p95_ms();
                            SmartscapeEdge {
                                from_id: sanitize_public_log(&e.from_id),
                                to_id: sanitize_public_log(&e.to_id),
                                protocol: e.protocol,
                                call_rate_rps,
                                error_rate_bp,
                                p95_ms,
                            }
                        })
                        .collect();
                }
                true
            }
            Input::ObsProblems(list) => {
                self.loaded = true;
                self.ensure_aux_defaults();
                if self.source == DataSource::Live || !list.is_empty() {
                    self.observe.problems = list
                        .into_iter()
                        .map(|p| {
                            let active = p.effective_active();
                            SloProblem {
                                problem_id: p.problem_id,
                                title: sanitize_public_log(&p.title),
                                category: p.category,
                                severity: p.severity,
                                burn_rate_bp: p.burn_rate_bp,
                                impacted_entity: sanitize_public_log(&p.impacted_entity),
                                root_cause_trace_id: p.root_cause_trace_id,
                                active,
                            }
                        })
                        .collect();
                }
                true
            }
            Input::ObsTraces(list) => {
                self.loaded = true;
                self.ensure_aux_defaults();
                if !list.is_empty() {
                    self.observe.traces = list.into_iter().map(trace_from_dto).collect();
                }
                true
            }
            Input::ObsTraceDetail(mut d) => {
                self.loaded = true;
                self.ensure_aux_defaults();
                let correlated = std::mem::take(&mut d.correlated_logs);
                let trace = trace_from_dto(d);
                if let Some(slot) = self
                    .observe
                    .traces
                    .iter_mut()
                    .find(|t| t.trace_id == trace.trace_id)
                {
                    *slot = trace;
                } else {
                    self.observe.traces.push(trace);
                }
                for l in correlated {
                    let clean_msg = sanitize_public_log(&l.message);
                    let exists = self.observe.logs.iter().any(|existing| {
                        existing.trace_id == l.trace_id
                            && existing.timestamp_ms == l.timestamp_ms
                            && existing.message == clean_msg
                    });
                    if !exists {
                        self.observe.logs.push(OtelLogEntry {
                            timestamp_ms: l.timestamp_ms,
                            severity: l.severity,
                            service: l.service,
                            span_id: l.span_id,
                            trace_id: l.trace_id,
                            message: clean_msg,
                        });
                    }
                }
                true
            }
            Input::ObsLogs(list) => {
                self.loaded = true;
                self.ensure_aux_defaults();
                if !list.is_empty() {
                    self.observe.logs = list
                        .into_iter()
                        .map(|l| OtelLogEntry {
                            timestamp_ms: l.timestamp_ms,
                            severity: l.severity,
                            service: l.service,
                            span_id: l.span_id,
                            trace_id: l.trace_id,
                            message: sanitize_public_log(&l.message),
                        })
                        .collect();
                }
                true
            }
            Input::ObsMetrics(list) => {
                self.loaded = true;
                self.ensure_aux_defaults();
                if self.source == DataSource::Live || !list.is_empty() {
                    self.observe.metrics = list
                        .into_iter()
                        .map(|m| HardwareMetricSeries {
                            service: m.service,
                            hardware_class: sanitize_public_log(&m.hardware_class),
                            rps: m.rps,
                            error_rate_bp: m.error_rate_bp,
                            p50_ms: m.p50_ms,
                            p95_ms: m.p95_ms,
                            p99_ms: m.p99_ms,
                            exemplar_trace_id: m.exemplar_trace_id,
                            samples: m.samples,
                        })
                        .collect();
                }
                true
            }
            Input::ObsStoreStatus(d) => {
                self.loaded = true;
                self.ensure_aux_defaults();
                let hot_duckdb_rows = d.effective_hot_rows();
                let cold_parquet_rows = d.effective_cold_rows();
                let zstd_compression_bp = d.effective_zstd_compression_bp();
                self.observe.store = DataStoreHealth {
                    hot_duckdb_rows,
                    hot_duckdb_bytes: d.hot_duckdb_bytes,
                    cold_parquet_partitions: d.cold_parquet_partitions,
                    cold_parquet_rows,
                    cold_parquet_bytes: d.cold_parquet_bytes,
                    zstd_compression_bp,
                    retention_days: d.retention_days,
                    oldest_watermark_iso: d.oldest_watermark_iso,
                };
                true
            }
            Input::BranchCreated(e) => self.branch_created(&e),
            Input::BranchDeleted(e) => self.branch_deleted(&e, now_ms),
            Input::PrStateChanged(e) => self.pr_state(&e, now_ms),
            Input::JobStageChanged(e) => self.job_stage(&e),
            Input::NodeMembership(e) => self.node_membership(&e),
            Input::ItProgress(e) => self.it_progress(&e),
            Input::Promoted(e) => self.with_gate(&e.deployment_id, |g| {
                g.outcome = GateOutcome::Promoted;
                g.restore_slot = e.slot.other();
            }),
            Input::RolledBack(e) => self.with_gate(&e.deployment_id, |g| {
                g.outcome = GateOutcome::RolledBack;
                g.rollback_reason = Some(e.reason);
                g.restore_slot = e.restore_slot;
            }),
            Input::Tainted(e) => {
                let gate_changed = self.with_gate(&e.deployment_id, |g| {
                    g.outcome = GateOutcome::Tainted;
                    g.tainted = true;
                });
                if let Some(c) = self
                    .registry
                    .canaries
                    .iter_mut()
                    .find(|c| c.deployment_id == e.deployment_id)
                {
                    c.state = CanaryBundleState::Tainted;
                    c.taint_reason = Some(sanitize_public_log(&e.reason));
                }
                gate_changed
            }
            Input::LeaseExpired(e) => self.with_gate(&e.deployment_id, |g| {
                if !g.outcome.is_final() {
                    g.outcome = GateOutcome::RolledBack;
                    g.rollback_reason = Some(RollbackReason::LeaseExpired);
                }
            }),
            Input::Select(sel) => {
                let changed = self.selection.as_ref() != Some(&sel);
                self.selection = Some(sel);
                changed
            }
            Input::AuthSession(dto) => {
                let next = AuthState::from_session(&dto);
                let changed = self.auth != next;
                self.auth = next;
                changed
            }
            Input::JobRestarted(job_id) | Input::JobResumed(job_id) => {
                let mut any = false;
                for topo in self.topologies.values_mut() {
                    let mut tr_changed = false;
                    for tr in &mut topo.t.trains {
                        if tr.job_id == job_id {
                            for sig in &mut tr.stage_states {
                                if *sig == StageState::Failed {
                                    *sig = StageState::Running;
                                    tr_changed = true;
                                }
                            }
                        }
                    }
                    if tr_changed {
                        topo.t.fabric_rev += 1;
                        any = true;
                    }
                }
                for r in self.repos.values_mut() {
                    if r.latest_job_id == Some(job_id) && r.status == RepoStatus::Failing {
                        r.status = RepoStatus::Running;
                        any = true;
                    }
                }
                if let Some(j) = self.ci_jobs.iter_mut().find(|j| j.job_id == job_id) {
                    j.queue_state = "Active".into();
                    for st in &mut j.stages {
                        if st.state == StageState::Failed {
                            st.state = StageState::Running;
                        }
                    }
                    any = true;
                }
                any
            }
            Input::JobDetail(rec) => {
                self.loaded = true;
                let rec = rec.into_unwrapped();
                let trace = self.build_ci_trace_and_log(&rec, "Completed", 0);
                if let Some(slot) = self
                    .observe
                    .traces
                    .iter_mut()
                    .find(|t| t.trace_id == trace.trace_id)
                {
                    *slot = trace;
                } else {
                    self.observe.traces.insert(0, trace);
                }
                let Some(summary) = self.ci_job_from_record(rec, None) else {
                    return false;
                };
                if let Some(existing) = self.ci_jobs.iter_mut().find(|j| j.job_id == summary.job_id)
                {
                    if !summary.stages.is_empty() {
                        existing.stages = summary.stages;
                    }
                    existing.commit_sha = summary.commit_sha;
                    existing.job_id_str = summary.job_id_str;
                    if summary.elapsed_secs > 0 {
                        existing.elapsed_secs = summary.elapsed_secs;
                    }
                    if !summary.benchmark_summary.is_empty() {
                        existing.benchmark_summary = summary.benchmark_summary;
                    }
                    if summary.quality_score > 0 || summary.tests_total > 0 {
                        existing.quality_score = summary.quality_score;
                        existing.coverage_bp = summary.coverage_bp;
                        existing.tests_passed = summary.tests_passed;
                        existing.tests_total = summary.tests_total;
                    }
                    if existing.queue_state != "Active" && existing.queue_state != "Queued" {
                        existing.queue_state = summary.queue_state;
                    }
                } else {
                    self.ci_jobs.insert(0, summary);
                }
                true
            }
            Input::JobLog { job_id, lines } => {
                self.loaded = true;
                self.job_logs.insert(job_id, lines.clone());
                if let Some(j) = self.ci_jobs.iter_mut().find(|j| j.job_id == job_id) {
                    j.raw_log_lines = lines;
                }
                true
            }
            Input::Restore {
                saved_epoch_ms,
                view,
            } => {
                if self.loaded {
                    false
                } else {
                    if self.selection.is_none() {
                        self.selection.clone_from(&view.selection);
                    }
                    self.offline = Some((saved_epoch_ms, view));
                    true
                }
            }
        };
        self.dirty |= changed;
        changed
    }

    /// Advance time: remove sidings whose fade-out finished.
    pub fn tick(&mut self, now_ms: u64) -> bool {
        let mut changed = false;
        for topo in self.topologies.values_mut() {
            let t = &mut topo.t;
            let expired: Vec<String> = t
                .branches
                .iter()
                .filter(|b| {
                    matches!(b.phase, SidingPhase::Fading { since_epoch_ms, .. }
                        if now_ms >= since_epoch_ms.saturating_add(FADE_MS))
                })
                .map(|b| b.ref_name.clone())
                .collect();
            if expired.is_empty() {
                continue;
            }
            t.branches.retain(|b| !expired.contains(&b.ref_name));
            t.trains.retain(|tr| !expired.contains(&tr.ref_name));
            t.fabric_rev += 1;
            changed = true;
        }
        self.dirty |= changed;
        changed
    }

    fn repos_loaded(&mut self, list: Vec<RepoDto>) -> bool {
        self.loaded = true;
        self.offline = None;
        self.ensure_aux_defaults();
        let mut next = BTreeMap::new();
        for d in list {
            let id = RepoId::new(&d.owner, &d.repo);
            if let Some(job_id) = d.latest_job_id {
                self.record_job_id_str(job_id, "", &d.commit_sha);
            }
            let prev = self.repos.get(&id);
            let cd = prev.and_then(|r| r.cd.clone());
            let submodules: Vec<SubmoduleRef> = if d.submodules.is_empty() {
                prev.map(|r| r.submodules.clone()).unwrap_or_default()
            } else {
                d.submodules
                    .into_iter()
                    .map(|s| SubmoduleRef {
                        path: s.path,
                        repo: RepoId::new(&s.owner, &s.repo),
                        pinned_sha: s.pinned_sha,
                    })
                    .collect()
            };
            let parents: Vec<ParentRef> = if d.parents.is_empty() {
                prev.map(|r| r.parents.clone()).unwrap_or_default()
            } else {
                d.parents
                    .into_iter()
                    .map(|p| ParentRef {
                        repo: RepoId::new(&p.owner, &p.repo),
                        path: p.path,
                    })
                    .collect()
            };
            let score = RepoScore {
                id: id.clone(),
                visibility: d.visibility,
                default_branch: d.default_branch,
                status: d.status,
                score: d.score.min(100),
                coverage_bp: pct_to_bp(d.coverage),
                bench_delta_bp: signed_pct_to_bp(d.bench_delta),
                latest_job_id: d.latest_job_id,
                submodules,
                parents,
                cd,
            };
            next.insert(id, score);
        }
        self.repos = next;
        true
    }

    fn ci_job_from_record(
        &mut self,
        rec: CiQueueJobRecordDto,
        queue_state_hint: Option<&str>,
    ) -> Option<CiJobSummary> {
        let rec = rec.into_unwrapped();
        let job_id = parse_job_id_str(&rec.job.id);
        if job_id == 0 {
            return None;
        }
        self.record_job_id_str(job_id, &rec.job.id, &rec.job.commit_sha);
        let job_id_str = self.resolve_job_id_str(job_id);
        let repo = if let Some((owner, name)) = rec.job.repo_name.split_once('/') {
            RepoId::new(owner, name)
        } else if rec.job.repo_name.is_empty() {
            RepoId::new("LMA1980", "unknown")
        } else {
            RepoId::new("LMA1980", &rec.job.repo_name)
        };
        let ref_name = rec
            .job
            .ref_name
            .trim_start_matches("refs/heads/")
            .to_owned();
        let stages: Vec<CiJobStage> = rec
            .stages
            .iter()
            .map(|st| {
                let state =
                    StageState::from_status_str(&st.status.state, st.status.details.exit_code);
                CiJobStage {
                    id: st.id.clone(),
                    name: if st.name.is_empty() {
                        st.id.clone()
                    } else {
                        st.name.clone()
                    },
                    assigned_node: st.assigned_node.as_deref().map(sanitize_public_log),
                    threads: st.threads,
                    state,
                    duration_secs: st.status.details.duration_secs,
                    exit_code: st.status.details.exit_code,
                }
            })
            .collect();
        let any_failed = stages.iter().any(|s| s.state == StageState::Failed);
        let any_running = stages.iter().any(|s| s.state == StageState::Running);
        let all_passed = !stages.is_empty() && stages.iter().all(|s| s.state == StageState::Passed);
        let queue_state = match queue_state_hint {
            Some("Active") => "Active".into(),
            Some("Queued") => "Queued".into(),
            _ if any_failed => "Failed".into(),
            _ if any_running => "Active".into(),
            _ if all_passed => "Passed".into(),
            Some(other) => other.to_owned(),
            None => "Passed".into(),
        };
        let stage_dur_sum: u64 = stages.iter().map(|s| s.duration_secs).sum();
        let elapsed_secs = rec.elapsed_secs.max(stage_dur_sum);
        let (quality_score, coverage_bp, tests_passed, tests_total, benchmark_summary) = rec
            .metrics
            .as_ref()
            .map_or((0, 0, 0, 0, String::new()), |m| {
                (
                    m.quality_score.min(100),
                    pct_to_bp(m.coverage_pct),
                    m.tests_passed,
                    m.tests_total,
                    sanitize_public_log(&m.benchmark_summary),
                )
            });
        let raw_log_lines = self.job_logs.get(&job_id).cloned().unwrap_or_default();
        Some(CiJobSummary {
            job_id,
            job_id_str,
            repo,
            ref_name,
            commit_sha: rec.job.commit_sha,
            queue_state,
            elapsed_secs,
            wait_secs: rec.wait_secs,
            quality_score,
            coverage_bp,
            tests_passed,
            tests_total,
            benchmark_summary,
            stages,
            raw_log_lines,
        })
    }

    fn build_ci_trace_and_log(
        &mut self,
        rec: &CiQueueJobRecordDto,
        q_hint: &str,
        job_idx: usize,
    ) -> PurePathTrace {
        let short_job: String = if rec.job.commit_sha.len() >= 6 {
            rec.job.commit_sha.chars().take(6).collect()
        } else if !rec.job.id.is_empty() {
            rec.job.id.chars().take(6).collect()
        } else {
            format!("{:04}", job_idx + 1)
        };
        let trace_id = format!("tr-ci-{short_job}");
        let ref_clean = rec.job.ref_name.trim_start_matches("refs/heads/");
        let repo_label = if rec.job.repo_name.contains('/') {
            rec.job.repo_name.clone()
        } else {
            format!("LMA1980/{}", rec.job.repo_name)
        };
        let root_op = sanitize_public_log(&format!("ci.pipeline ({repo_label}) @{ref_clean}"));
        let default_node = rec
            .stages
            .iter()
            .find_map(|s| s.assigned_node.as_deref())
            .unwrap_or("fabric-worker");
        let node_hw = sanitize_public_log(default_node);
        let mut offset_us = 0_u64;
        let mut spans = Vec::with_capacity(rec.stages.len().max(1));
        for (st_idx, st) in rec.stages.iter().enumerate() {
            let dur_us = st
                .status
                .details
                .duration_secs
                .saturating_mul(1_000_000)
                .max(50_000);
            let span_id = format!("sp-{short_job}-{}", st_idx + 1);
            let parent_span_id = (st_idx > 0).then(|| format!("sp-{short_job}-{st_idx}"));
            let st_err =
                st.status.state.eq_ignore_ascii_case("failed") || st.status.details.exit_code != 0;
            let st_hw = st
                .assigned_node
                .as_deref()
                .map_or_else(|| node_hw.clone(), sanitize_public_log);
            spans.push(TraceSpan {
                span_id,
                parent_span_id,
                service: "actionrunner-rs".into(),
                operation: sanitize_public_log(&format!(
                    "stage.{}",
                    if st.name.is_empty() { &st.id } else { &st.name }
                )),
                start_offset_us: offset_us,
                duration_us: dur_us,
                self_time_us: dur_us,
                critical_path: true,
                error: st_err,
                hardware_class: st_hw,
            });
            offset_us = offset_us.saturating_add(dur_us);
        }
        if spans.is_empty() {
            spans.push(TraceSpan {
                span_id: format!("sp-{short_job}-1"),
                parent_span_id: None,
                service: "actionrunner-controller".into(),
                operation: "queue.dispatch".into(),
                start_offset_us: 0,
                duration_us: 100_000,
                self_time_us: 100_000,
                critical_path: true,
                error: false,
                hardware_class: node_hw.clone(),
            });
            offset_us = 100_000;
        }
        let duration_ms = u32::try_from((offset_us / 1_000).max(1)).unwrap_or(u32::MAX);
        let is_err = spans.iter().any(|s| s.error);
        let (cov_str, passed_t, total_t) = rec.metrics.as_ref().map_or_else(
            || ("--".into(), 0, 0),
            |m| {
                (
                    format!("{:.1}%", m.coverage_pct),
                    m.tests_passed,
                    m.tests_total,
                )
            },
        );
        let status_label = if is_err {
            "FAILED"
        } else if q_hint == "Active" {
            "RUNNING"
        } else if q_hint == "Queued" {
            "QUEUED"
        } else {
            "PASSED"
        };
        let log_msg = sanitize_public_log(&format!(
            "{repo_label} @{ref_clean} [{status_label}] stages={} tests={passed_t}/{total_t} cov={cov_str} on {node_hw}",
            rec.stages.len(),
        ));
        if !self
            .observe
            .logs
            .iter()
            .any(|l| l.trace_id == trace_id && l.message == log_msg)
        {
            self.observe.logs.push(OtelLogEntry {
                timestamp_ms: 1_700_000_900_u64.saturating_sub(u64::try_from(job_idx).unwrap_or(0)),
                severity: if is_err {
                    LogSeverity::Error
                } else {
                    LogSeverity::Info
                },
                service: "actionrunner-rs".into(),
                span_id: Some(format!("sp-{short_job}-1")),
                trace_id: trace_id.clone(),
                message: log_msg,
            });
        }
        PurePathTrace {
            trace_id,
            root_service: "actionrunner-controller".into(),
            root_operation: root_op,
            domain: "CI".into(),
            duration_ms,
            error: is_err,
            slow_p99: duration_ms >= 30_000,
            started_epoch_ms: 1_700_000_900_000_u64
                .saturating_sub(u64::try_from(job_idx).unwrap_or(0) * 1_000),
            spans,
        }
    }

    #[allow(clippy::too_many_lines)]
    fn apply_ci_queue(&mut self, dto: CiQueueDto) -> bool {
        self.loaded = true;
        self.ensure_aux_defaults();
        let tagged_jobs: Vec<(&str, CiQueueJobRecordDto)> = dto
            .active_jobs
            .into_iter()
            .map(|r| ("Active", r.into_unwrapped()))
            .chain(
                dto.queued_jobs
                    .into_iter()
                    .map(|r| ("Queued", r.into_unwrapped())),
            )
            .chain(
                dto.recent_jobs
                    .into_iter()
                    .map(|r| ("Completed", r.into_unwrapped())),
            )
            .take(24)
            .collect();
        if tagged_jobs.is_empty() {
            return false;
        }
        let prev_jobs = std::mem::take(&mut self.ci_jobs);
        let mut next_jobs = Vec::with_capacity(tagged_jobs.len());
        let mut live_traces = Vec::with_capacity(tagged_jobs.len());
        for (job_idx, (q_hint, rec)) in tagged_jobs.into_iter().enumerate() {
            if let Some(mut summary) = self.ci_job_from_record(rec.clone(), Some(q_hint)) {
                if let Some(prev) = prev_jobs.iter().find(|p| p.job_id == summary.job_id) {
                    if summary.stages.is_empty() && !prev.stages.is_empty() {
                        summary.stages.clone_from(&prev.stages);
                    }
                    if summary.raw_log_lines.is_empty() && !prev.raw_log_lines.is_empty() {
                        summary.raw_log_lines.clone_from(&prev.raw_log_lines);
                    }
                }
                if !next_jobs
                    .iter()
                    .any(|j: &CiJobSummary| j.job_id == summary.job_id)
                {
                    next_jobs.push(summary);
                }
            }
            live_traces.push(self.build_ci_trace_and_log(&rec, q_hint, job_idx));
        }
        self.ci_jobs = next_jobs;
        for existing in std::mem::take(&mut self.observe.traces) {
            if !live_traces.iter().any(|t| t.trace_id == existing.trace_id) {
                live_traces.push(existing);
            }
        }
        self.observe.traces = live_traces;
        true
    }

    fn summary(&mut self, s: &RepoSummaryDto) -> bool {
        let repo_id = RepoId::new(&s.owner, &s.repo);
        if let Some(job_id) = s.latest_job_id {
            self.record_job_id_str(job_id, "", &s.commit_sha);
        }
        for h in &s.history {
            self.record_job_id_str(h.job_id, "", &h.commit_sha);
        }
        let subs: Vec<SubmoduleRef> = s
            .submodules
            .iter()
            .map(|sub| SubmoduleRef {
                path: sub.path.clone(),
                repo: RepoId::new(&sub.owner, &sub.repo),
                pinned_sha: sub.pinned_sha.clone(),
            })
            .collect();
        let parents: Vec<ParentRef> = s
            .parents
            .iter()
            .map(|p| ParentRef {
                repo: RepoId::new(&p.owner, &p.repo),
                path: p.path.clone(),
            })
            .collect();
        let Some(r) = self.repos.get_mut(&repo_id) else {
            return false;
        };
        r.status = s.status;
        r.score = s.score.min(100);
        r.coverage_bp = pct_to_bp(s.coverage);
        r.bench_delta_bp = signed_pct_to_bp(s.bench_delta);
        r.latest_job_id = s.latest_job_id.or(r.latest_job_id);
        if !subs.is_empty() {
            r.submodules.clone_from(&subs);
        }
        if !parents.is_empty() {
            r.parents = parents;
        }
        if let Some(topo) = self.topologies.get_mut(&repo_id) {
            if !subs.is_empty() {
                topo.t.submodules.clone_from(&subs);
            }
        }
        // Populate reverse parent pointers on child submodule repos so C5/C3 show parent links.
        for sub in subs {
            if let Some(child_repo) = self.repos.get_mut(&sub.repo) {
                let pref = ParentRef {
                    repo: repo_id.clone(),
                    path: sub.path,
                };
                if !child_repo.parents.contains(&pref) {
                    child_repo.parents.push(pref);
                }
            }
        }
        true
    }

    fn topology(&mut self, d: TopologyDto) -> bool {
        self.loaded = true;
        self.ensure_aux_defaults();
        let repo = RepoId::new(&d.owner, &d.repo);
        let stations: Vec<Station> = d
            .stations
            .into_iter()
            .map(|s| Station {
                label: compact_station_label(&s.id, &s.label),
                id: s.id,
            })
            .collect();
        let n = stations.len();
        let mut branches: Vec<Branch> = d
            .branches
            .into_iter()
            .filter(|b| b.ref_name != d.default_branch)
            .map(|b| Branch {
                fork_stage: station_index(&stations, &b.fork_stage),
                ref_name: b.ref_name,
                base_ref: b.base_ref,
                pr_state: b.pr_state,
                last_job: b.last_job,
                phase: SidingPhase::Active,
            })
            .collect();
        branches.sort_by(|a, b| a.ref_name.cmp(&b.ref_name));
        branches.dedup_by(|a, b| a.ref_name == b.ref_name);
        let mut trains: Vec<Train> = Vec::with_capacity(d.trains.len());
        for t in d.trains {
            self.record_job_id_str(t.job_id, "", &t.commit_sha);
            let mut states = t.stage_states;
            states.resize(n, StageState::Pending);
            let clean_node = t.node_id.map(|id| sanitize_public_log(&id));
            let tr = Train {
                job_id: t.job_id,
                stage: station_index(&stations, &t.stage),
                node_lost: self.node_offline(clean_node.as_deref()),
                ref_name: t.ref_name,
                stage_states: states,
                node_id: clean_node,
            };
            if tr.job_id > 0 && !self.ci_jobs.iter().any(|j| j.job_id == tr.job_id) {
                let job_id_str = if self.job_id_strings.contains_key(&tr.job_id) {
                    self.resolve_job_id_str(tr.job_id)
                } else {
                    format!("job-{}", format_job_id(tr.job_id))
                };
                let repo_score = self.repos.get(&repo);
                let stages: Vec<CiJobStage> = stations
                    .iter()
                    .enumerate()
                    .map(|(idx, st)| {
                        let state = tr
                            .stage_states
                            .get(idx)
                            .copied()
                            .unwrap_or(StageState::Pending);
                        CiJobStage {
                            id: st.id.clone(),
                            name: st.label.clone(),
                            assigned_node: tr.node_id.clone(),
                            threads: 6,
                            state,
                            duration_secs: if state == StageState::Passed { 12 } else { 0 },
                            exit_code: i32::from(state == StageState::Failed),
                        }
                    })
                    .collect();
                let queue_state = if tr.failed() {
                    "Failed".into()
                } else if stages.iter().any(|s| s.state == StageState::Running) {
                    "Active".into()
                } else {
                    "Passed".into()
                };
                let elapsed_secs: u64 = stages.iter().map(|s| s.duration_secs).sum();
                self.ci_jobs.push(CiJobSummary {
                    job_id: tr.job_id,
                    job_id_str,
                    repo: repo.clone(),
                    ref_name: tr.ref_name.clone(),
                    commit_sha: t.commit_sha,
                    queue_state,
                    elapsed_secs,
                    wait_secs: 0,
                    quality_score: repo_score.map_or(95, |r| r.score),
                    coverage_bp: repo_score.map_or(9_000, |r| r.coverage_bp),
                    tests_passed: u32::try_from(
                        stages
                            .iter()
                            .filter(|s| s.state == StageState::Passed)
                            .count()
                            * 10,
                    )
                    .unwrap_or(0),
                    tests_total: u32::try_from(stages.len().max(1) * 10).unwrap_or(10),
                    benchmark_summary: String::new(),
                    stages,
                    raw_log_lines: self.job_logs.get(&tr.job_id).cloned().unwrap_or_default(),
                });
            }
            trains.push(tr);
        }
        trains.sort_by_key(|t| t.job_id);
        trains.dedup_by_key(|t| t.job_id);
        let prev_rev = self.topologies.get(&repo).map_or(0, |t| t.t.fabric_rev);
        let submodules = self
            .repos
            .get(&repo)
            .map(|r| r.submodules.clone())
            .unwrap_or_default();
        let topo = RepoTopology {
            repo: repo.clone(),
            submodule: None,
            default_branch: d.default_branch,
            stations,
            branches,
            trains,
            submodules,
            fabric_rev: d.fabric_rev.max(prev_rev),
            submodule_bump_pending: false,
        };
        self.topologies.insert(
            repo,
            Topo {
                t: topo,
                head_sha: d.head_sha,
            },
        );
        true
    }

    fn node_offline(&self, node: Option<&str>) -> bool {
        node.and_then(|n| self.nodes.get(n))
            .is_some_and(|n| !n.online)
    }

    fn topo_mut(&mut self, owner: &str, repo: &str, server_rev: u64) -> Option<&mut RepoTopology> {
        let topo = &mut self.topologies.get_mut(&RepoId::new(owner, repo))?.t;
        topo.fabric_rev = server_rev.max(topo.fabric_rev + 1);
        Some(topo)
    }

    fn branch_created(&mut self, e: &BranchCreatedDto) -> bool {
        let Some(t) = self
            .topologies
            .get_mut(&RepoId::new(&e.owner, &e.repo))
            .map(|t| &mut t.t)
        else {
            return false;
        };
        if e.ref_name == t.default_branch || t.branches.iter().any(|b| b.ref_name == e.ref_name) {
            return false;
        }
        let fork_stage = station_index(&t.stations, &e.fork_stage);
        t.fabric_rev = e.fabric_rev.max(t.fabric_rev + 1);
        upsert_sorted(
            &mut t.branches,
            Branch {
                ref_name: e.ref_name.clone(),
                base_ref: e.base_ref.clone(),
                fork_stage,
                pr_state: PrState::None,
                last_job: None,
                phase: SidingPhase::UnderConstruction,
            },
            |b| b.ref_name.clone(),
        );
        true
    }

    fn start_fade(t: &mut RepoTopology, r: &str, reason: FadeReason, now_ms: u64) -> bool {
        let Some(b) = t.branches.iter_mut().find(|b| b.ref_name == r) else {
            return false;
        };
        if matches!(b.phase, SidingPhase::Fading { .. }) {
            return false;
        }
        b.phase = SidingPhase::Fading {
            reason,
            since_epoch_ms: now_ms,
        };
        true
    }

    fn branch_deleted(&mut self, e: &BranchDeletedDto, now_ms: u64) -> bool {
        let Some(t) = self
            .topologies
            .get_mut(&RepoId::new(&e.owner, &e.repo))
            .map(|t| &mut t.t)
        else {
            return false;
        };
        let changed = Self::start_fade(t, &e.ref_name, FadeReason::Deleted, now_ms);
        if changed {
            t.fabric_rev = e.fabric_rev.max(t.fabric_rev + 1);
        }
        changed
    }

    fn pr_state(&mut self, e: &PrStateChangedDto, now_ms: u64) -> bool {
        let Some(t) = self.topo_mut(&e.owner, &e.repo, e.fabric_rev) else {
            return false;
        };
        let Some(b) = t.branches.iter_mut().find(|b| b.ref_name == e.ref_name) else {
            return false;
        };
        b.pr_state = e.pr_state;
        if e.pr_state == PrState::Merged {
            Self::start_fade(t, &e.ref_name, FadeReason::Merged, now_ms);
        }
        true
    }

    fn job_stage(&mut self, e: &JobStageChangedDto) -> bool {
        let repo_id = RepoId::new(&e.owner, &e.repo);
        let clean_node = e.node_id.as_ref().map(|n| sanitize_public_log(n));
        let node_lost = self.node_offline(clean_node.as_deref());
        let mut changed = false;
        let mut default_train_status = None;
        if let Some(t) = self.topologies.get_mut(&repo_id).map(|t| &mut t.t) {
            if t.trains
                .iter()
                .any(|tr| tr.ref_name == e.ref_name && tr.job_id > e.job_id)
            {
                return false;
            }
            let n = t.stations.len();
            let stage = station_index(&t.stations, &e.stage);
            let mut states = t
                .trains
                .iter()
                .find(|tr| tr.job_id == e.job_id)
                .map_or_else(
                    || vec![StageState::Pending; n],
                    |tr| tr.stage_states.clone(),
                );
            if e.stage_states.is_empty() {
                if let Some(slot) = usize::try_from(stage).ok().and_then(|i| states.get_mut(i)) {
                    *slot = e.state;
                }
            } else {
                states.clone_from(&e.stage_states);
                states.resize(n, StageState::Pending);
            }
            t.trains
                .retain(|tr| tr.ref_name != e.ref_name || tr.job_id == e.job_id);
            let train = Train {
                job_id: e.job_id,
                ref_name: e.ref_name.clone(),
                stage,
                stage_states: states,
                node_id: clean_node.clone(),
                node_lost,
            };
            if e.ref_name == t.default_branch {
                default_train_status = Some(train_status(&train));
            } else if let Some(b) = t.branches.iter_mut().find(|b| b.ref_name == e.ref_name) {
                b.last_job = Some(e.job_id);
                if b.phase == SidingPhase::UnderConstruction && clean_node.is_some() {
                    b.phase = SidingPhase::Active;
                }
            } else {
                upsert_sorted(
                    &mut t.branches,
                    Branch {
                        ref_name: e.ref_name.clone(),
                        base_ref: t.default_branch.clone(),
                        fork_stage: 0,
                        pr_state: PrState::None,
                        last_job: Some(e.job_id),
                        phase: SidingPhase::Active,
                    },
                    |b| b.ref_name.clone(),
                );
            }
            upsert_sorted(&mut t.trains, train, |tr| tr.job_id);
            t.fabric_rev = e.fabric_rev.max(t.fabric_rev + 1);
            changed = true;
        }
        if let Some(r) = self.repos.get_mut(&repo_id) {
            if r.latest_job_id.is_none_or(|j| j <= e.job_id) {
                r.latest_job_id = Some(e.job_id);
            }
            if let Some(s) = default_train_status {
                r.status = s;
            }
            changed = true;
        }
        changed
    }

    fn node_membership(&mut self, e: &NodeMembershipChangedDto) -> bool {
        let clean_id = sanitize_public_log(&e.node_id);
        let node = if let Some(mut existing) = self.nodes.get(&clean_id).cloned() {
            existing.online = e.online;
            existing
        } else {
            FabricNode::new(clean_id.clone(), e.online)
        };
        let changed = self.nodes.get(&clean_id) != Some(&node);
        self.nodes.insert(clean_id.clone(), node);
        for topo in self.topologies.values_mut() {
            let mut touched = false;
            for tr in &mut topo.t.trains {
                if tr.node_id.as_deref() == Some(clean_id.as_str()) && tr.node_lost == e.online {
                    tr.node_lost = !e.online;
                    touched = true;
                }
            }
            if touched {
                topo.t.fabric_rev = e.fabric_rev.max(topo.t.fabric_rev + 1);
            }
        }
        changed
    }

    fn deployments(&mut self, repo: &RepoId, list: &[DeploymentDto]) -> bool {
        self.loaded = true;
        self.ensure_aux_defaults();
        let mut sorted: Vec<&DeploymentDto> = list.iter().collect();
        sorted.sort_by_key(|a| std::cmp::Reverse(a.started_epoch_ms));
        let history: Vec<DeploymentSummary> = sorted
            .iter()
            .map(|d| {
                self.gates.get(&d.deployment_id).map_or_else(
                    || DeploymentSummary {
                        deployment_id: d.deployment_id.clone(),
                        artifact_digest: d.artifact_digest.clone(),
                        it_passed: d.it_passed,
                        it_total: d.it_total,
                        outcome: d.outcome,
                    },
                    DeploymentGate::summary,
                )
            })
            .collect();
        if let Some(first) = sorted.first() {
            self.latest
                .insert(repo.clone(), first.deployment_id.clone());
            if let Some(r) = self.repos.get_mut(repo) {
                r.cd = Some(CdScore {
                    deployment_id: first.deployment_id.clone(),
                    active_slot: first.active_slot,
                    outcome: first.outcome,
                    it_passed: first.it_passed,
                    it_total: first.it_total,
                });
            }
        } else {
            self.latest.remove(repo);
            if let Some(r) = self.repos.get_mut(repo) {
                r.cd = None;
            }
        }
        self.history.insert(repo.clone(), history);
        let latest = self.latest.get(repo).cloned();
        if let Some(id) = latest {
            self.refresh_cd(&id);
        }
        true
    }

    fn gate(&mut self, d: GateDto) -> bool {
        self.loaded = true;
        self.ensure_aux_defaults();
        let id = d.deployment_id.clone();
        let gate = DeploymentGate {
            deployment_id: d.deployment_id,
            repo: RepoId::new(&d.owner, &d.repo),
            service: d.service,
            artifact_digest: d.artifact_digest,
            target_node: sanitize_public_log(&d.target_node),
            staged_slot: d.staged_slot,
            restore_slot: d.restore_slot,
            lease_expires_epoch_ms: d.lease_expires_epoch_ms,
            outcome: d.outcome,
            rollback_reason: d.rollback_reason,
            tainted: d.tainted,
            tests: d
                .tests
                .into_iter()
                .map(|t| GateTest {
                    name: t.name,
                    critical: t.critical,
                    state: t.state,
                    duration_ms: t.duration_ms,
                    crate_name: t.crate_name,
                    log_excerpt: t.log_excerpt.map(|l| sanitize_public_log(&l)),
                })
                .collect(),
        };
        self.gates.insert(id.clone(), gate);
        self.refresh_cd(&id);
        true
    }

    fn it_progress(&mut self, e: &ItProgressDto) -> bool {
        self.with_gate(&e.deployment_id, |g| {
            if let Some(t) = g.tests.iter_mut().find(|t| t.name == e.test_name) {
                t.critical = e.critical;
                t.state = e.state;
                t.duration_ms = e.duration_ms;
            } else {
                g.tests.push(GateTest {
                    name: e.test_name.clone(),
                    critical: e.critical,
                    state: e.state,
                    duration_ms: e.duration_ms,
                    crate_name: None,
                    log_excerpt: None,
                });
            }
        })
    }

    fn with_gate(&mut self, id: &str, f: impl FnOnce(&mut DeploymentGate)) -> bool {
        let Some(g) = self.gates.get_mut(id) else {
            return false;
        };
        let before = g.clone();
        f(g);
        let changed = *g != before;
        if changed {
            self.refresh_cd(id);
        }
        changed
    }

    /// Propagate a gate into its history entry and the repo's CD score.
    fn refresh_cd(&mut self, id: &str) {
        let Some(g) = self.gates.get(id) else {
            return;
        };
        let summary = g.summary();
        if let Some(h) = self.history.get_mut(&g.repo) {
            if let Some(e) = h.iter_mut().find(|e| e.deployment_id == id) {
                *e = summary.clone();
            }
        }
        if self.latest.get(&g.repo).map(String::as_str) == Some(id) {
            if let Some(r) = self.repos.get_mut(&g.repo) {
                let active_slot = match g.outcome {
                    GateOutcome::Promoted => g.staged_slot,
                    GateOutcome::RolledBack | GateOutcome::Tainted => g.restore_slot,
                    GateOutcome::Pending => r.cd.as_ref().map_or(g.restore_slot, |c| c.active_slot),
                };
                r.cd = Some(CdScore {
                    deployment_id: id.to_owned(),
                    active_slot,
                    outcome: summary.outcome,
                    it_passed: summary.it_passed,
                    it_total: summary.it_total,
                });
            }
        }
    }

    /// Alert counts per area.
    #[must_use]
    pub fn badges(&self) -> AreaBadges {
        if let Some((_, v)) = self.offline.as_ref() {
            return badges_of_view(v);
        }
        let ci = u32::try_from(
            self.repos
                .values()
                .filter(|r| {
                    r.status == RepoStatus::Failing
                        || self.topologies.get(&r.id).is_some_and(|t| t.t.stop())
                })
                .count(),
        )
        .unwrap_or(u32::MAX);
        let cd = u32::try_from(
            self.repos
                .values()
                .filter_map(|r| r.cd.as_ref())
                .filter(|c| matches!(c.outcome, GateOutcome::RolledBack | GateOutcome::Tainted))
                .count(),
        )
        .unwrap_or(u32::MAX);
        let registry = u32::try_from(
            self.registry
                .canaries
                .iter()
                .filter(|c| c.state == CanaryBundleState::Tainted)
                .count()
                + usize::from(self.registry.cas.corrupt_blobs > 0),
        )
        .unwrap_or(u32::MAX);
        let observe = u32::try_from(self.observe.problems.iter().filter(|p| p.active).count())
            .unwrap_or(u32::MAX);
        let fleet =
            u32::try_from(self.nodes.values().filter(|n| !n.online).count()).unwrap_or(u32::MAX);
        AreaBadges {
            ci,
            cd,
            registry,
            observe,
            fleet,
        }
    }

    /// Project the store into the view model for the current selection.
    #[must_use]
    pub fn view(&self) -> ViewModel {
        if let Some((saved, v)) = self.offline.as_ref() {
            let mut v = v.clone();
            v.source = DataSource::OfflineCache;
            v.stale_since_epoch_ms = Some(*saved);
            v.selection.clone_from(&self.selection);
            return v;
        }
        let selection = self.selection.clone();
        let topology = self.topology_repo().and_then(|repo| {
            let topo = self.topologies.get(&repo)?;
            let mut t = topo.t.clone();
            t.submodules = self
                .repos
                .get(&repo)
                .map(|r| r.submodules.clone())
                .unwrap_or_default();
            if let Some(sel) = selection.as_ref() {
                if let Some(sub) = sel.submodule.as_ref() {
                    t.submodule = Some(sub.clone());
                    let pinned = self.repos.get(&sel.repo).and_then(|p| {
                        p.submodules
                            .iter()
                            .find(|s| s.path == sub.path)
                            .map(|s| s.pinned_sha.clone())
                    });
                    t.submodule_bump_pending = pinned.is_some_and(|p| {
                        !p.is_empty() && !topo.head_sha.is_empty() && p != topo.head_sha
                    });
                }
            }
            Some(t)
        });
        let parent = selection.as_ref().map(|s| &s.repo);
        let gate = parent
            .and_then(|p| self.latest.get(p))
            .and_then(|id| self.gates.get(id))
            .cloned();
        let history = parent
            .and_then(|p| self.history.get(p))
            .cloned()
            .unwrap_or_default();
        ViewModel {
            source: self.source.clone(),
            repos: self.repos.values().cloned().collect(),
            selection,
            topology,
            gate,
            history,
            nodes: self.nodes.values().cloned().collect(),
            stale_since_epoch_ms: None,
            leases: self.leases.clone(),
            sandboxes: self.sandboxes.clone(),
            registry: self.registry.clone(),
            observe: self.observe.clone(),
            ci_jobs: self.ci_jobs.clone(),
            auth: self.auth.clone(),
        }
    }
}

fn compact_station_label(id: &str, label: &str) -> String {
    if !label.is_empty() && label.chars().count() <= 12 {
        return label.to_owned();
    }
    let clean_id = id
        .trim_end_matches("-check")
        .trim_end_matches("_check")
        .trim_end_matches("-gate")
        .trim_end_matches("_gate")
        .trim_end_matches("-build")
        .trim_end_matches("_build");
    let base = if clean_id.is_empty() { id } else { clean_id };
    match base {
        "fmt" | "rustfmt" => "FMT".into(),
        "doc-format" | "doc_format" | "docs" => "DOCS".into(),
        "clippy" => "CLIPPY".into(),
        "wasm32" | "wasm" => "WASM32".into(),
        "unit-tests" | "unit_tests" | "test" | "tests" => "TESTS".into(),
        "audit" | "cargo-audit" => "AUDIT".into(),
        "coverage" | "llvm-cov" | "cov" => "COV".into(),
        "miri" => "MIRI".into(),
        "bench" | "benchmarks" => "BENCH".into(),
        other if !other.is_empty() => other
            .replace(['-', '_'], " ")
            .chars()
            .take(10)
            .collect::<String>()
            .to_ascii_uppercase(),
        _ => label
            .chars()
            .take(10)
            .collect::<String>()
            .to_ascii_uppercase(),
    }
}

fn trace_from_dto(d: TraceDto) -> PurePathTrace {
    let duration_ms = d.effective_duration_ms();
    let error = d.effective_error();
    let domain = if d.domain.is_empty() {
        if d.root_service.contains("actionrunner") || d.root_operation.contains("ci") {
            "CI".into()
        } else if d.root_service.contains("muconde") || d.root_operation.contains("cd") {
            "CD".into()
        } else if d.root_service.contains("muregist") || d.root_operation.contains("cas") {
            "REGISTRY".into()
        } else {
            "OBS".into()
        }
    } else {
        d.domain
    };
    PurePathTrace {
        trace_id: d.trace_id,
        root_service: d.root_service,
        root_operation: sanitize_public_log(&d.root_operation),
        domain,
        duration_ms,
        error,
        slow_p99: d.slow_p99 || duration_ms >= 2_500,
        started_epoch_ms: d.started_epoch_ms,
        spans: d
            .spans
            .into_iter()
            .map(|s| {
                let sp_err = s.effective_error();
                TraceSpan {
                    span_id: s.span_id,
                    parent_span_id: s.parent_span_id,
                    service: s.service,
                    operation: sanitize_public_log(&s.operation),
                    start_offset_us: s.start_offset_us,
                    duration_us: s.duration_us,
                    self_time_us: if s.self_time_us > 0 {
                        s.self_time_us
                    } else {
                        s.duration_us
                    },
                    critical_path: s.critical_path,
                    error: sp_err,
                    hardware_class: sanitize_public_log(&s.hardware_class),
                }
            })
            .collect(),
    }
}

fn train_status(t: &Train) -> RepoStatus {
    if t.failed() {
        RepoStatus::Failing
    } else if t
        .stage_states
        .iter()
        .any(|s| matches!(s, StageState::Running | StageState::Pending))
    {
        RepoStatus::Running
    } else {
        RepoStatus::Passing
    }
}

fn badges_of_view(v: &ViewModel) -> AreaBadges {
    let ci = v
        .repos
        .iter()
        .filter(|r| r.status == RepoStatus::Failing)
        .count();
    let cd = v
        .repos
        .iter()
        .filter_map(|r| r.cd.as_ref())
        .filter(|c| matches!(c.outcome, GateOutcome::RolledBack | GateOutcome::Tainted))
        .count();
    let registry = v
        .registry
        .canaries
        .iter()
        .filter(|c| c.state == CanaryBundleState::Tainted)
        .count()
        + usize::from(v.registry.cas.corrupt_blobs > 0);
    let observe = v.observe.problems.iter().filter(|p| p.active).count();
    let fleet = v.nodes.iter().filter(|n| !n.online).count();
    let c = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
    AreaBadges {
        ci: c(ci),
        cd: c(cd),
        registry: c(registry),
        observe: c(observe),
        fleet: c(fleet),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_conversions_clamp() {
        assert_eq!(pct_to_bp(83.456), 8_346);
        assert_eq!(pct_to_bp(-3.0), 0);
        assert_eq!(pct_to_bp(250.0), 10_000);
        assert_eq!(pct_to_bp(f64::NAN), 0);
        assert_eq!(signed_pct_to_bp(-1.25), -125);
        assert_eq!(signed_pct_to_bp(f64::NAN), 0);
    }

    #[test]
    fn events_for_unknown_targets_are_ignored() {
        let mut s = Store::new(DataSource::Live);
        s.take_dirty();
        assert!(!s.apply(
            Input::LeaseExpired(LeaseExpiredDto {
                deployment_id: "nope".into()
            }),
            0
        ));
        assert!(!s.apply(
            Input::BranchDeleted(BranchDeletedDto {
                owner: "o".into(),
                repo: "r".into(),
                ref_name: "feat/x".into(),
                fabric_rev: 0,
            }),
            0
        ));
        assert!(!s.is_dirty());
        assert_eq!(s.view(), ViewModel::default());
    }
}
