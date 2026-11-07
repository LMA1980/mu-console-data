// SPDX-License-Identifier: AGPL-3.0-only
//! REST and SSE payload decoding into store [`Input`]s.

use mu_console_protocol::dto::{
    AuthSessionDto, BranchCreatedDto, BranchDeletedDto, CanaryBundleDto, CasStatusDto,
    ClusterNodeDto, DeploymentDto, GateDto, ItProgressDto, JobStageChangedDto, LeaseDto,
    LeaseExpiredDto, MetricSeriesDto, NodeMembershipChangedDto, OtelLogDto, PackageDto,
    PrStateChangedDto, ProblemDto, PromotedDto, RepoDto, RepoListResponseDto, RepoSummaryDto,
    RolledBackDto, SmartscapeDto, StoreStatusDto, TaintedDigestDto, TaintedDto, TopologyDto,
    TraceDto,
};
use mu_console_protocol::{CanaryBundleState, CdLease, RepoId};
use serde::de::DeserializeOwned;
use serde::Deserialize;

use crate::store::Input;

/// Which REST resource a fetch targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchKind {
    Repos,
    ClusterNodes,
    Summary(RepoId),
    Topology(RepoId),
    Deployments(RepoId),
    Gate(String),
    Leases,
    RegPackages,
    RegCanaries,
    RegCasStatus,
    ObsSmartscape,
    ObsProblems,
    ObsTraces,
    ObsTraceDetail(String),
    ObsLogs,
    ObsMetrics,
    ObsStoreStatus,
    AuthSession,
    AuthRedeem(String),
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
}

impl StreamId {
    pub const ALL: [Self; 2] = [Self::Ci, Self::Cd];

    /// Index into per-stream arrays.
    #[must_use]
    pub fn index(self) -> usize {
        match self {
            Self::Ci => 0,
            Self::Cd => 1,
        }
    }
}

fn json<T: DeserializeOwned>(body: &str) -> Result<T, String> {
    serde_json::from_str(body).map_err(|e| e.to_string())
}

/// Decode a `/api/auth/session` or `/api/auth/redeem` JSON body.
///
/// # Errors
/// Returns the JSON error message when the payload is malformed.
pub fn parse_auth_session(bytes: &[u8]) -> Result<AuthSessionDto, String> {
    serde_json::from_slice(bytes).map_err(|e| e.to_string())
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
enum PackagesEnvelope {
    List(Vec<PackageDto>),
    Envelope {
        #[serde(default)]
        packages: Vec<PackageDto>,
    },
}

#[derive(Deserialize)]
#[serde(untagged)]
enum CanariesEnvelope {
    List(Vec<CanaryBundleDto>),
    Envelope {
        #[serde(default)]
        bundles: Vec<CanaryBundleDto>,
        #[serde(default)]
        canaries: Vec<CanaryBundleDto>,
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

#[derive(Deserialize)]
#[serde(untagged)]
enum LogsEnvelope {
    List(Vec<OtelLogDto>),
    Envelope {
        #[serde(default)]
        logs: Vec<OtelLogDto>,
    },
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
    List(Vec<MetricSeriesDto>),
    Envelope {
        #[serde(default)]
        series: Vec<MetricSeriesDto>,
        #[serde(default)]
        cluster_efficiency: Vec<ClusterEfficiencyDto>,
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
                CanariesEnvelope::List(v) => v,
                CanariesEnvelope::Envelope {
                    mut bundles,
                    canaries,
                    taints,
                } => {
                    if bundles.is_empty() {
                        bundles = canaries;
                    }
                    for t in taints {
                        if let Some(existing) =
                            bundles.iter_mut().find(|b| b.artifact_digest == t.digest)
                        {
                            existing.state = CanaryBundleState::Tainted;
                            if existing.taint_reason.is_none() && !t.reason.is_empty() {
                                existing.taint_reason = Some(t.reason);
                            }
                        } else {
                            bundles.push(CanaryBundleDto {
                                bundle_id: t.digest.chars().take(12).collect(),
                                owner: "LMA1980".into(),
                                repo: t.service.clone(),
                                service: t.service,
                                artifact_digest: t.digest,
                                state: CanaryBundleState::Tainted,
                                taint_reason: (!t.reason.is_empty()).then_some(t.reason),
                                deployment_id: String::new(),
                                trace_id: t.trace_id,
                            });
                        }
                    }
                    bundles
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
        FetchKind::ObsLogs => {
            let list = match json::<LogsEnvelope>(body)? {
                LogsEnvelope::List(v) => v,
                LogsEnvelope::Envelope { logs } => logs,
            };
            Input::ObsLogs(list)
        }
        FetchKind::ObsMetrics => {
            let list = match json::<MetricsEnvelope>(body)? {
                MetricsEnvelope::List(v) => v,
                MetricsEnvelope::Envelope {
                    mut series,
                    cluster_efficiency,
                } => {
                    for ce in cluster_efficiency {
                        series.push(MetricSeriesDto {
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
                            exemplar_trace_id: "tr-obs-p99-07".into(),
                            samples: vec![
                                ns_to_u32(ce.min_ns_per_iter),
                                ns_to_u32(ce.avg_ns_per_iter),
                                ns_to_u32(ce.max_ns_per_iter),
                            ],
                        });
                    }
                    series
                }
            };
            Input::ObsMetrics(list)
        }
        FetchKind::ObsStoreStatus => Input::ObsStoreStatus(json::<StoreStatusDto>(body)?),
        FetchKind::AuthSession | FetchKind::AuthRedeem(_) => {
            Input::AuthSession(parse_auth_session(body.as_bytes())?)
        }
    })
}

/// Decode one SSE event. `Ok(None)` for event kinds the console does not
/// use (the existing `queue` / `jobs` / `cluster` kinds, keep-alives).
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
        (StreamId::Cd, "it_progress") => Input::ItProgress(json::<ItProgressDto>(data)?),
        (StreamId::Cd, "promoted") => Input::Promoted(json::<PromotedDto>(data)?),
        (StreamId::Cd, "rolled_back") => Input::RolledBack(json::<RolledBackDto>(data)?),
        (StreamId::Cd, "tainted") => Input::Tainted(json::<TaintedDto>(data)?),
        (StreamId::Cd, "lease_expired") => Input::LeaseExpired(json::<LeaseExpiredDto>(data)?),
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
        // Existing kinds and cross-stream names are ignored.
        assert_eq!(parse_event(StreamId::Ci, "queue", "{}"), Ok(None));
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
              "bundle_id": "cny-042",
              "service_name": "muconde-agent",
              "binary_digest": "sha256:9f82c01a334e",
              "status": "promoted",
              "trace_id": "tr-cd-0042"
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
    }
}
