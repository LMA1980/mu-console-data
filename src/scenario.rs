// SPDX-License-Identifier: AGPL-3.0-only
//! Fixture scenario player (`?scenario=<name>`).
//!
//! Each scenario is a deterministic script of timed [`Input`]s that feeds
//! the same [`crate::store::Store`] → diff → coalescer path as live data,
//! so every UX state can be reached on any device without a backend. All
//! names are fictional (`fixture/*` repositories, `node-a` /
//! `worker-riscv64` nodes).

use mu_console_protocol::dto::{
    BranchCreatedDto, BranchDto, DeploymentDto, GateDto, GateTestDto, ItProgressDto,
    JobStageChangedDto, LeaseExpiredDto, NodeMembershipChangedDto, PrStateChangedDto, RepoDto,
    RolledBackDto, StationDto, SubmoduleDto, TaintedDto, TopologyDto, TrainDto,
};
use mu_console_protocol::{
    GateOutcome, PrState, RepoId, RepoStatus, RollbackReason, Selection, Slot, StageState,
    SubmoduleId, TestState, ViewModel, Visibility,
};

use crate::offline::OfflineSnapshot;
use crate::store::Input;

/// Fixture owner used by every scenario repository.
pub const OWNER: &str = "fixture";
/// Superproject with seven submodules.
pub const SUPERPROJECT: &str = "superproject";
/// Fixed epoch used by fixture timestamps (2026-11-01T00:00:00Z).
pub const FIXTURE_EPOCH_MS: u64 = 1_793_491_200_000;

/// Available scenarios.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scenario {
    /// Repository with 7 submodules; the engine submodule is selected and
    /// its gitlink bump is pending.
    Submodules,
    /// New branch: siding under construction with a queued train.
    NewBranch,
    /// PR merged: the siding fades and is removed after 2 s.
    PrMerged,
    /// Stage failure: train stops, `STOP` lit, CI badge.
    StageFailure,
    /// A node leaves the fabric: trains on it show `NODE LOST`.
    NodeLost,
    /// Critical integration test fails: rollback.
    ItCriticalFailure,
    /// Lease expires during the gate: rollback.
    LeaseExpiry,
    /// Artifact tainted after promotion.
    Tainted,
    /// 40 repositories for the rotary.
    Repos40,
    /// No repositories, no deployments.
    Empty,
    /// Offline mode: stale snapshot from CacheStorage, no upstream.
    Offline,
}

impl Scenario {
    pub const ALL: [Self; 11] = [
        Self::Submodules,
        Self::NewBranch,
        Self::PrMerged,
        Self::StageFailure,
        Self::NodeLost,
        Self::ItCriticalFailure,
        Self::LeaseExpiry,
        Self::Tainted,
        Self::Repos40,
        Self::Empty,
        Self::Offline,
    ];

    /// `?scenario=` name.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Submodules => "submodules",
            Self::NewBranch => "new-branch",
            Self::PrMerged => "pr-merged",
            Self::StageFailure => "stage-failure",
            Self::NodeLost => "node-lost",
            Self::ItCriticalFailure => "it-critical-failure",
            Self::LeaseExpiry => "lease-expiry",
            Self::Tainted => "tainted",
            Self::Repos40 => "repos-40",
            Self::Empty => "empty",
            Self::Offline => "offline",
        }
    }

    /// Look a scenario up by name (supports both hyphenated and snake_case aliases).
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        if let Some(s) = Self::ALL.into_iter().find(|s| s.name() == name) {
            return Some(s);
        }
        match name {
            "submodule_interchange" => Some(Self::Submodules),
            "ci_happy_path" | "new_branch" => Some(Self::NewBranch),
            "ci_pr_lifecycle" | "pr_merged" => Some(Self::PrMerged),
            "stage_failure" => Some(Self::StageFailure),
            "node_loss" | "node_lost" => Some(Self::NodeLost),
            "cd_gate_rollback" | "it_critical_failure" => Some(Self::ItCriticalFailure),
            "lease_expiry" => Some(Self::LeaseExpiry),
            "cd_gate_promote" => Some(Self::Tainted),
            "repos_40" => Some(Self::Repos40),
            _ => None,
        }
    }

    /// Whether the scenario simulates a lost upstream.
    #[must_use]
    pub fn is_offline(self) -> bool {
        self == Self::Offline
    }

    /// The timed script (`at_ms` relative to scenario start, ascending).
    #[must_use]
    pub fn script(self) -> Vec<Step> {
        match self {
            Self::Submodules => submodules(),
            Self::NewBranch => new_branch(),
            Self::PrMerged => pr_merged(),
            Self::StageFailure => stage_failure(),
            Self::NodeLost => node_lost(),
            Self::ItCriticalFailure => it_critical_failure(),
            Self::LeaseExpiry => lease_expiry(),
            Self::Tainted => tainted(),
            Self::Repos40 => repos_40(),
            Self::Empty => empty(),
            Self::Offline => offline(),
        }
    }

    /// Time after which the script has fully played (incl. fades).
    #[must_use]
    pub fn duration_ms(self) -> u64 {
        self.script().last().map_or(0, |s| s.at_ms) + crate::store::FADE_MS + 500
    }
}

/// One scripted input.
#[derive(Debug, Clone, PartialEq)]
pub struct Step {
    pub at_ms: u64,
    pub input: Input,
}

/// Replays a script against wall-clock ticks.
#[derive(Debug)]
pub struct ScenarioPlayer {
    scenario: Scenario,
    steps: Vec<Step>,
    cursor: usize,
    start_ms: u64,
    /// Playback speed in percent (`100` = 1x, `200` = 2x, `0` = paused / manual step).
    speed_pct: u32,
}

impl ScenarioPlayer {
    #[must_use]
    pub fn new(scenario: Scenario, start_ms: u64) -> Self {
        Self {
            scenario,
            steps: scenario.script(),
            cursor: 0,
            start_ms,
            speed_pct: 100,
        }
    }

    #[must_use]
    pub fn scenario(&self) -> Scenario {
        self.scenario
    }

    /// Playback speed in percent (`100` = 1x, `0` = manual stepping).
    #[must_use]
    pub fn speed_pct(&self) -> u32 {
        self.speed_pct
    }

    /// Change playback speed (`100` = 1x, `200` = 2x, `0` = paused).
    pub fn set_speed(&mut self, speed_pct: u32) {
        self.speed_pct = speed_pct;
    }

    /// Advance one scripted step immediately regardless of wall clock.
    pub fn step(&mut self) -> Option<(u64, Input)> {
        let step = self.steps.get(self.cursor)?;
        let at = self.start_ms.saturating_add(step.at_ms);
        let out = (at, step.input.clone());
        self.cursor += 1;
        Some(out)
    }

    /// Restart from the first step.
    pub fn restart(&mut self, start_ms: u64) {
        self.cursor = 0;
        self.start_ms = start_ms;
    }

    /// Whether every step has been emitted.
    #[must_use]
    pub fn finished(&self) -> bool {
        self.cursor >= self.steps.len()
    }

    /// Inputs due at `now_ms`, with the absolute time each was due at.
    pub fn due(&mut self, now_ms: u64) -> Vec<(u64, Input)> {
        let mut out = Vec::new();
        if self.speed_pct == 0 {
            return out;
        }
        let elapsed = now_ms
            .saturating_sub(self.start_ms)
            .saturating_mul(u64::from(self.speed_pct))
            / 100;
        while let Some(step) = self.steps.get(self.cursor) {
            if step.at_ms > elapsed {
                break;
            }
            let at = self.start_ms.saturating_add(step.at_ms);
            out.push((at, step.input.clone()));
            self.cursor += 1;
        }
        out
    }
}

// ---------------------------------------------------------------- fixtures

fn step(at_ms: u64, input: Input) -> Step {
    Step { at_ms, input }
}

const STATIONS: [(&str, &str); 8] = [
    ("push", "PUSH"),
    ("fmt-check", "FMT"),
    ("clippy-check", "CLIPPY"),
    ("audit-check", "AUDIT"),
    ("coverage-test", "COV"),
    ("bench", "BENCH"),
    ("release", "RELEASE"),
    ("merge", "MERGE"),
];

const SUBMODULES: [&str; 7] = [
    "core",
    "engine",
    "tokenizer",
    "kv",
    "kernels-rvv",
    "arch-synthetic",
    "manager",
];

fn repo_dto(name: &str, status: RepoStatus, score: u32) -> RepoDto {
    RepoDto {
        owner: OWNER.into(),
        repo: name.into(),
        visibility: Visibility::Public,
        default_branch: "main".into(),
        latest_job_id: Some(1_000),
        commit_sha: String::new(),
        score,
        coverage: f64::from(score) - 7.5,
        bench_delta: 0.4,
        status,
        submodules: Vec::new(),
        parents: Vec::new(),
    }
}

fn superproject_dto() -> RepoDto {
    let mut r = repo_dto(SUPERPROJECT, RepoStatus::Passing, 92);
    r.submodules = SUBMODULES
        .iter()
        .map(|m| SubmoduleDto {
            path: format!("code/{m}"),
            owner: OWNER.into(),
            repo: (*m).into(),
            pinned_sha: format!("pin-{m}"),
        })
        .collect();
    r
}

/// Superproject, its 7 submodule repositories and two standalone repos.
fn fabric_repos() -> Vec<RepoDto> {
    let mut v = vec![
        superproject_dto(),
        repo_dto("registry", RepoStatus::Passing, 88),
        repo_dto("console", RepoStatus::Running, 81),
    ];
    for (i, m) in SUBMODULES.iter().enumerate() {
        let mut r = repo_dto(m, RepoStatus::Passing, 80 + u32::try_from(i).unwrap_or(0));
        r.parents = vec![mu_console_protocol::dto::ParentDto {
            owner: OWNER.into(),
            repo: SUPERPROJECT.into(),
            path: format!("code/{m}"),
        }];
        v.push(r);
    }
    v
}

fn states(passed: usize, current: StageState) -> Vec<StageState> {
    (0..STATIONS.len())
        .map(|i| match i.cmp(&passed) {
            std::cmp::Ordering::Less => StageState::Passed,
            std::cmp::Ordering::Equal => current,
            std::cmp::Ordering::Greater => StageState::Pending,
        })
        .collect()
}

fn train(job_id: u64, r: &str, stage: usize, current: StageState, node: Option<&str>) -> TrainDto {
    TrainDto {
        job_id,
        ref_name: r.into(),
        commit_sha: String::new(),
        stage: STATIONS[stage].0.into(),
        stage_states: states(stage, current),
        node_id: node.map(Into::into),
    }
}

fn branch(r: &str, fork: usize, pr: PrState, job: Option<u64>) -> BranchDto {
    BranchDto {
        ref_name: r.into(),
        base_ref: "main".into(),
        fork_stage: STATIONS[fork].0.into(),
        pr_state: pr,
        last_job: job,
    }
}

/// Superproject Trainway: main + two sidings, trains on both nodes.
fn topology(repo: &str, head_sha: &str) -> TopologyDto {
    TopologyDto {
        owner: OWNER.into(),
        repo: repo.into(),
        default_branch: "main".into(),
        head_sha: head_sha.into(),
        stations: STATIONS
            .iter()
            .map(|(id, label)| StationDto {
                id: (*id).into(),
                label: (*label).into(),
            })
            .collect(),
        branches: vec![
            branch("feat/a", 0, PrState::Open, Some(1_234)),
            branch("feat/b", 1, PrState::None, Some(1_233)),
        ],
        trains: vec![
            train(1_231, "main", 5, StageState::Running, Some("node-a")),
            train(
                1_233,
                "feat/b",
                1,
                StageState::Running,
                Some("worker-riscv64"),
            ),
            train(1_234, "feat/a", 3, StageState::Running, Some("node-a")),
        ],
        fabric_rev: 480,
    }
}

fn node(id: &str, online: bool) -> Input {
    Input::NodeMembership(NodeMembershipChangedDto {
        node_id: id.into(),
        online,
        fabric_rev: 0,
    })
}

fn select(repo: &str, submodule: Option<&str>) -> Input {
    Input::Select(Selection {
        repo: RepoId::new(OWNER, repo),
        submodule: submodule.map(|p| SubmoduleId { path: p.into() }),
    })
}

fn gate_test(name: &str, critical: bool, state: TestState, crate_name: &str) -> GateTestDto {
    GateTestDto {
        name: name.into(),
        critical,
        state,
        duration_ms: if state == TestState::Passed { 1_200 } else { 0 },
        crate_name: Some(crate_name.into()),
        log_excerpt: (state == TestState::Failed).then(|| "assertion failed".into()),
    }
}

const DEPLOYMENT: &str = "dep-0042";

fn gate(outcome: GateOutcome, tests: Vec<GateTestDto>) -> GateDto {
    GateDto {
        deployment_id: DEPLOYMENT.into(),
        owner: OWNER.into(),
        repo: SUPERPROJECT.into(),
        service: "model-service".into(),
        artifact_digest: "sha256:1f2e3d4c".into(),
        target_node: "worker-riscv64".into(),
        staged_slot: Slot::B,
        restore_slot: Slot::A,
        lease_expires_epoch_ms: FIXTURE_EPOCH_MS + 600_000,
        outcome,
        rollback_reason: None,
        tainted: false,
        tests,
    }
}

fn running_gate() -> GateDto {
    gate(
        GateOutcome::Pending,
        vec![
            gate_test("it_boot", true, TestState::Passed, "core"),
            gate_test("it_tokenize", false, TestState::Passed, "tokenizer"),
            gate_test("it_kv_cache", true, TestState::Running, "kv"),
            gate_test("it_infer_gemm", true, TestState::Pending, "engine"),
            gate_test("it_manager_api", false, TestState::Pending, "manager"),
        ],
    )
}

fn deployments(head: &GateDto) -> Input {
    let summary =
        |id: &str, digest: &str, outcome: GateOutcome, passed: u32, age: u64| DeploymentDto {
            deployment_id: id.into(),
            owner: OWNER.into(),
            repo: SUPERPROJECT.into(),
            service: "model-service".into(),
            artifact_digest: digest.into(),
            target_node: "worker-riscv64".into(),
            active_slot: Slot::A,
            staged_slot: Slot::B,
            outcome,
            it_passed: passed,
            it_total: 5,
            started_epoch_ms: FIXTURE_EPOCH_MS - age,
        };
    let mut current = summary(DEPLOYMENT, &head.artifact_digest, head.outcome, 2, 0);
    current.it_total = u32::try_from(head.tests.len()).unwrap_or(0);
    Input::Deployments {
        repo: RepoId::new(OWNER, SUPERPROJECT),
        list: vec![
            current,
            summary(
                "dep-0041",
                "sha256:0a0b0c0d",
                GateOutcome::RolledBack,
                3,
                3_600_000,
            ),
            summary(
                "dep-0040",
                "sha256:09080706",
                GateOutcome::Promoted,
                5,
                7_200_000,
            ),
        ],
    }
}

/// Common opening: nodes, repos, superproject selected with its Trainway
/// and a running gate.
fn base() -> Vec<Step> {
    let g = running_gate();
    vec![
        step(0, node("node-a", true)),
        step(0, node("worker-riscv64", true)),
        step(0, Input::Repos(fabric_repos())),
        step(0, Input::Topology(topology(SUPERPROJECT, "head-super"))),
        step(0, select(SUPERPROJECT, None)),
        step(0, deployments(&g)),
        step(0, Input::Gate(g)),
    ]
}

fn ci_job(job_id: u64, r: &str, stage: usize, state: StageState, node: Option<&str>) -> Input {
    Input::JobStageChanged(JobStageChangedDto {
        owner: OWNER.into(),
        repo: SUPERPROJECT.into(),
        job_id,
        ref_name: r.into(),
        stage: STATIONS[stage].0.into(),
        state,
        stage_states: Vec::new(),
        node_id: node.map(Into::into),
        fabric_rev: 0,
    })
}

fn it(test: &str, critical: bool, state: TestState, duration_ms: u64) -> Input {
    Input::ItProgress(ItProgressDto {
        deployment_id: DEPLOYMENT.into(),
        test_name: test.into(),
        critical,
        state,
        duration_ms,
        timestamp_epoch_ms: FIXTURE_EPOCH_MS,
    })
}

fn submodules() -> Vec<Step> {
    let mut s = base();
    s.push(step(
        0,
        Input::Topology(topology("engine", "head-engine-newer")),
    ));
    s.push(step(800, select(SUPERPROJECT, Some("code/engine"))));
    s
}

fn new_branch() -> Vec<Step> {
    let mut s = base();
    s.push(step(
        1_000,
        Input::BranchCreated(BranchCreatedDto {
            owner: OWNER.into(),
            repo: SUPERPROJECT.into(),
            ref_name: "feat/new-siding".into(),
            base_ref: "main".into(),
            fork_stage: "fmt-check".into(),
            fabric_rev: 0,
        }),
    ));
    s.push(step(
        1_400,
        ci_job(2_001, "feat/new-siding", 0, StageState::Pending, None),
    ));
    s
}

fn pr_merged() -> Vec<Step> {
    let mut s = base();
    s.push(step(
        600,
        ci_job(1_234, "feat/a", 7, StageState::Passed, Some("node-a")),
    ));
    s.push(step(
        1_000,
        Input::PrStateChanged(PrStateChangedDto {
            owner: OWNER.into(),
            repo: SUPERPROJECT.into(),
            ref_name: "feat/a".into(),
            pr_state: PrState::Merged,
            pr_number: Some(77),
            fabric_rev: 0,
        }),
    ));
    s
}

fn stage_failure() -> Vec<Step> {
    let mut s = base();
    s.push(step(
        800,
        ci_job(
            1_233,
            "feat/b",
            1,
            StageState::Passed,
            Some("worker-riscv64"),
        ),
    ));
    s.push(step(
        1_200,
        ci_job(
            1_233,
            "feat/b",
            2,
            StageState::Failed,
            Some("worker-riscv64"),
        ),
    ));
    s
}

fn node_lost() -> Vec<Step> {
    let mut s = base();
    s.push(step(1_000, node("worker-riscv64", false)));
    s
}

fn it_critical_failure() -> Vec<Step> {
    let mut s = base();
    s.push(step(500, it("it_kv_cache", true, TestState::Passed, 2_300)));
    s.push(step(900, it("it_infer_gemm", true, TestState::Running, 0)));
    s.push(step(
        1_600,
        it("it_infer_gemm", true, TestState::Failed, 4_100),
    ));
    s.push(step(
        2_000,
        Input::RolledBack(RolledBackDto {
            deployment_id: DEPLOYMENT.into(),
            restore_slot: Slot::A,
            reason: RollbackReason::CriticalTestFailed,
        }),
    ));
    s
}

fn lease_expiry() -> Vec<Step> {
    let mut s = base();
    s.push(step(700, it("it_kv_cache", true, TestState::Passed, 2_300)));
    s.push(step(
        1_000,
        it("it_infer_gemm", true, TestState::Running, 0),
    ));
    s.push(step(
        2_500,
        Input::LeaseExpired(LeaseExpiredDto {
            deployment_id: DEPLOYMENT.into(),
        }),
    ));
    s
}

fn tainted() -> Vec<Step> {
    let mut s = base();
    s.push(step(400, it("it_kv_cache", true, TestState::Passed, 2_300)));
    s.push(step(
        700,
        it("it_infer_gemm", true, TestState::Passed, 3_900),
    ));
    s.push(step(
        900,
        it("it_manager_api", false, TestState::Passed, 800),
    ));
    s.push(step(
        1_200,
        Input::Promoted(mu_console_protocol::dto::PromotedDto {
            deployment_id: DEPLOYMENT.into(),
            slot: Slot::B,
        }),
    ));
    s.push(step(
        2_200,
        Input::Tainted(TaintedDto {
            deployment_id: DEPLOYMENT.into(),
            artifact_digest: "sha256:1f2e3d4c".into(),
            reason: "advisory RUSTSEC-0000-0000 matched".into(),
        }),
    ));
    s
}

/// Names for the 40-repo rotary list (alphabetical spread for type-ahead).
fn repo_name(i: u32) -> String {
    const STEMS: [&str; 10] = [
        "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india",
        "juliett",
    ];
    let stem = STEMS[usize::try_from(i % 10).unwrap_or(0)];
    format!("{stem}-{:02}", i / 10)
}

fn repos_40() -> Vec<Step> {
    let repos = (0..40)
        .map(|i| {
            let status = match i % 7 {
                0 => RepoStatus::Failing,
                1 | 2 => RepoStatus::Running,
                _ => RepoStatus::Passing,
            };
            repo_dto(&repo_name(i), status, 60 + (i % 40))
        })
        .collect();
    vec![
        step(0, node("node-a", true)),
        step(0, Input::Repos(repos)),
        step(0, select(&repo_name(0), None)),
    ]
}

fn empty() -> Vec<Step> {
    vec![step(0, Input::Repos(Vec::new()))]
}

/// The snapshot the offline scenario restores: the base fabric as seen
/// ten minutes before the fixture epoch.
#[must_use]
pub fn offline_snapshot() -> OfflineSnapshot {
    let mut store =
        crate::store::Store::new(mu_console_protocol::DataSource::Scenario("offline".into()));
    for s in base() {
        store.apply(s.input, FIXTURE_EPOCH_MS);
    }
    store.set_source(mu_console_protocol::DataSource::Live);
    let view: ViewModel = store.view();
    OfflineSnapshot {
        saved_epoch_ms: FIXTURE_EPOCH_MS - 600_000,
        view,
    }
}

fn offline() -> Vec<Step> {
    let snap = offline_snapshot();
    vec![step(
        0,
        Input::Restore {
            saved_epoch_ms: snap.saved_epoch_ms,
            view: snap.view,
        },
    )]
}
