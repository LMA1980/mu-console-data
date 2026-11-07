// SPDX-License-Identifier: AGPL-3.0-only
//! End-to-end tests for [`crate::Engine`], [`crate::scenario::ScenarioPlayer`],
//! live fetch/SSE ingestion, <= 10 Hz coalescing, 350 ms rotary settle
//! debounce, generation-token stale-response rejection, hidden-tab pause /
//! resync, and offline cache watermark persistence.

use mu_console_protocol::{
    apply_all, encode, Area, CiSubView, ConnState, CrtFont, DataEvent, DataSource, FadeReason,
    GateOutcome, ObserveSubView, PanelId, PrState, RegistrySubView, RepoId, Route, Selection,
    SidingPhase, SubView, SubmoduleId, UiCommand, UiError, ViewModel, WorkerConfig,
    PROTOCOL_VERSION,
};

use crate::api::tests::{GATE, REPOS, TOPOLOGY};
use crate::api::{FetchKind, StreamId};
use crate::coalesce::{HEARTBEAT_MS, MIN_INTERVAL_MS};
use crate::engine::{Effect, Engine, HttpError, OFFLINE_AFTER_ATTEMPTS, SELECT_SETTLE_MS};
use crate::offline::{OfflineSnapshot, SAVE_INTERVAL_MS};
use crate::scenario::{offline_snapshot, Scenario, OWNER, SUPERPROJECT};
use crate::store::FADE_MS;

/// Feed `Effect::Post` events into a mirrored [`ViewModel`] and verify that
/// `apply_all(mirror, patch)` always matches the engine's projected store view.
fn drain_view_events(effects: &[Effect], mirror: &mut Option<ViewModel>) -> usize {
    let mut count = 0;
    for fx in effects {
        match fx {
            Effect::Post(DataEvent::Snapshot(v)) => {
                *mirror = Some(v.clone());
                count += 1;
            }
            Effect::Post(DataEvent::Patch(deltas)) => {
                let m = mirror.as_mut().expect("patch before snapshot");
                apply_all(m, deltas);
                count += 1;
            }
            _ => {}
        }
    }
    count
}

#[test]
fn live_fetch_and_sse_coalesce_at_most_ten_hz() {
    let mut eng = Engine::new(42);
    let mut mirror = None;

    let fx = eng.handle(UiCommand::Configure(WorkerConfig::default()), 0);
    assert!(fx.contains(&Effect::Post(DataEvent::Ready {
        protocol: PROTOCOL_VERSION,
        source: DataSource::Live,
    })));
    assert!(fx.contains(&Effect::Post(DataEvent::Connection(ConnState::Connecting))));
    assert!(fx.contains(&Effect::LoadOffline));

    // Both SSE streams open -> ConnState::Live.
    eng.on_stream_open(StreamId::Ci, 10);
    let fx = eng.on_stream_open(StreamId::Cd, 20);
    assert!(fx.contains(&Effect::Post(DataEvent::Connection(ConnState::Live))));

    // Initial /api/repos response auto-selects the first repository (LMA1980/engine)
    // and triggers Summary, Topology, and Deployments fetches.
    let fx = eng.on_fetch(&FetchKind::Repos, Ok(REPOS.into()), 30);
    assert!(fx.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::Topology(_),
            ..
        }
    )));

    // Switch selection to superproject and deliver its topology + gate.
    let super_id = RepoId::new("LMA1980", "superproject");
    eng.handle(
        UiCommand::SelectRepo {
            repo: super_id.clone(),
            submodule: None,
        },
        40,
    );
    eng.on_fetch(
        &FetchKind::Topology(super_id.clone()),
        Ok(TOPOLOGY.into()),
        50,
    );
    let dep_list = r#"[{
        "deployment_id": "dep-42", "owner": "LMA1980", "repo": "superproject",
        "service": "model-service", "artifact_digest": "sha256:1f2e3d",
        "target_node": "worker-riscv64", "active_slot": "a", "staged_slot": "b",
        "outcome": "pending", "it_passed": 1, "it_total": 2, "started_epoch_ms": 1000
    }]"#;
    let fx = eng.on_fetch(&FetchKind::Deployments(super_id), Ok(dep_list.into()), 60);
    assert!(fx.contains(&Effect::Fetch {
        kind: FetchKind::Gate("dep-42".into()),
        url: "/api/cd/deployments/dep-42/gate".into(),
    }));
    eng.on_fetch(&FetchKind::Gate("dep-42".into()), Ok(GATE.into()), 70);

    // First tick at t=100 emits Snapshot and saves offline snapshot.
    let fx = eng.tick(100);
    assert_eq!(drain_view_events(&fx, &mut mirror), 1);
    assert!(fx.iter().any(|e| matches!(e, Effect::SaveOffline(_))));

    // Burst 25 SSE events across 150 ms; verify <= 10 Hz view emission.
    let mut emissions = 0;
    for step in 0..25_u64 {
        let now = 105 + step * 6;
        let sse = format!(
            "event: job_stage_changed\ndata: {{\"owner\":\"LMA1980\",\"repo\":\"superproject\",\"job_id\":1234,\"ref\":\"feat/rvv-gemm\",\"stage\":\"clippy-check\",\"state\":\"running\",\"fabric_rev\":{}}}\n\n",
            500 + step
        );
        eng.on_stream_chunk(StreamId::Ci, sse.as_bytes(), now);
        let fx = eng.tick(now);
        emissions += drain_view_events(&fx, &mut mirror);
    }
    // Across a 150 ms window (105..=249 ms), at most one patch (at t >= 200 ms) may fire.
    assert_eq!(emissions, 1);

    // Final tick at t=350 syncs the mirror with the latest store projection.
    let fx = eng.tick(350);
    drain_view_events(&fx, &mut mirror);
    assert_eq!(mirror.as_ref(), Some(&eng.store().view()));
}

#[test]
fn rotary_settle_debounce_and_stale_generation_rejection() {
    let mut eng = Engine::new(7);
    eng.handle(UiCommand::Configure(WorkerConfig::default()), 0);
    eng.on_fetch(&FetchKind::Repos, Ok(REPOS.into()), 10);

    let initial_gen = eng.selection_gen();
    let repo_a = RepoId::new("LMA1980", "engine");
    let repo_b = RepoId::new("LMA1980", "superproject");

    // Rapid rotary detents before 350 ms do not commit or trigger fetches.
    eng.rotary_detent(
        Selection {
            repo: repo_a.clone(),
            submodule: None,
        },
        100,
    );
    eng.rotary_detent(
        Selection {
            repo: repo_b.clone(),
            submodule: Some(SubmoduleId {
                path: "code/engine".into(),
            }),
        },
        250,
    );

    // At t=500 (250 ms after the second detent, < 350 ms), selection has not settled yet.
    let fx = eng.tick(500);
    assert!(!fx.iter().any(|e| matches!(e, Effect::Fetch { .. })));
    assert_eq!(eng.selection_gen(), initial_gen);

    // At t=250 + SELECT_SETTLE_MS (600 ms), the settled selection commits and bumps generation.
    let fx = eng.tick(250 + SELECT_SETTLE_MS);
    let new_gen = eng.selection_gen();
    assert!(new_gen > initial_gen);
    assert_eq!(
        eng.store().selection(),
        Some(&Selection {
            repo: repo_b.clone(),
            submodule: Some(SubmoduleId {
                path: "code/engine".into()
            }),
        })
    );
    // Because code/engine submodule is selected, topology fetch targets LMA1980/engine!
    assert!(fx.contains(&Effect::Fetch {
        kind: FetchKind::Topology(repo_a),
        url: "/api/repos/LMA1980/engine/topology".into(),
    }));

    // A stale response carrying the old generation token is rejected without mutating the store.
    let stale_summary =
        r#"{"owner":"LMA1980","repo":"superproject","status":"failing","score":12}"#;
    let fx = eng.on_fetch_gen(
        initial_gen,
        &FetchKind::Summary(repo_b.clone()),
        Ok(stale_summary.into()),
        610,
    );
    assert!(fx.is_empty());
    let super_score = eng
        .store()
        .view()
        .repos
        .into_iter()
        .find(|r| r.id == repo_b)
        .expect("repo_b");
    assert_eq!(
        super_score.score, 92,
        "stale response must not overwrite score"
    );

    // Current-generation response is accepted.
    let fresh_summary =
        r#"{"owner":"LMA1980","repo":"superproject","status":"passing","score":99}"#;
    eng.on_fetch_gen(
        new_gen,
        &FetchKind::Summary(repo_b.clone()),
        Ok(fresh_summary.into()),
        620,
    );
    let super_score = eng
        .store()
        .view()
        .repos
        .into_iter()
        .find(|r| r.id == repo_b)
        .expect("repo_b");
    assert_eq!(super_score.score, 99);
}

#[test]
fn tab_hidden_throttles_to_heartbeats_and_resyncs_on_visible() {
    let mut eng = Engine::new(9);
    let mut mirror = None;
    eng.handle(UiCommand::Configure(WorkerConfig::default()), 0);
    eng.on_stream_open(StreamId::Ci, 10);
    eng.on_stream_open(StreamId::Cd, 10);
    eng.on_fetch(&FetchKind::Repos, Ok(REPOS.into()), 20);
    let fx = eng.tick(100);
    drain_view_events(&fx, &mut mirror);

    // Hide the tab -> ConnState::Paused.
    let fx = eng.handle(UiCommand::SetVisibility { hidden: true }, 200);
    assert!(eng.is_hidden());
    assert!(fx.contains(&Effect::Post(DataEvent::Connection(ConnState::Paused))));

    // SSE updates still mutate the store while hidden, but only Heartbeat events go to the UI.
    eng.on_stream_chunk(
        StreamId::Ci,
        b"event: node_membership_changed\ndata: {\"node_id\":\"node-a\",\"online\":false,\"fabric_rev\":9}\n\n",
        500,
    );
    for t in (300..=200 + HEARTBEAT_MS).step_by(usize::try_from(MIN_INTERVAL_MS).unwrap_or(100)) {
        let fx = eng.tick(t);
        for e in &fx {
            assert!(
                !matches!(
                    e,
                    Effect::Post(
                        DataEvent::Snapshot(_) | DataEvent::Patch(_) | DataEvent::AreaBadges(_)
                    )
                ),
                "unexpected UI update while hidden: {e:?}"
            );
        }
        if t == 200 + HEARTBEAT_MS {
            assert!(fx.contains(&Effect::Post(DataEvent::Heartbeat { seq: 1 })));
        }
    }

    // Unhide the tab -> ConnState::Live and next tick emits a full Snapshot + AreaBadges.
    let fx = eng.handle(UiCommand::SetVisibility { hidden: false }, 20_000);
    assert!(!eng.is_hidden());
    assert!(fx.contains(&Effect::Post(DataEvent::Connection(ConnState::Live))));

    let fx = eng.tick(20_100);
    assert!(fx
        .iter()
        .any(|e| matches!(e, Effect::Post(DataEvent::Snapshot(_)))));
    assert!(fx
        .iter()
        .any(|e| matches!(e, Effect::Post(DataEvent::AreaBadges(b)) if b.fleet == 1)));
    drain_view_events(&fx, &mut mirror);
    assert_eq!(mirror.as_ref(), Some(&eng.store().view()));
}

#[test]
#[cfg_attr(miri, ignore)]
fn offline_snapshot_watermark_and_live_recovery() {
    let mut eng = Engine::new(100);
    eng.handle(UiCommand::Configure(WorkerConfig::default()), 0);

    // Restore an offline snapshot before any live data arrives.
    let snap = offline_snapshot();
    let bytes = snap.to_bytes().expect("encode offline snapshot");
    eng.on_offline_loaded(Some(&bytes), 50);

    let fx = eng.tick(100);
    let mut mirror = None;
    drain_view_events(&fx, &mut mirror);
    let view = mirror.expect("offline snapshot view");
    assert_eq!(view.source, DataSource::OfflineCache);
    assert_eq!(view.stale_since_epoch_ms, Some(snap.saved_epoch_ms));

    // Simulate repeated stream failures before live data -> transitions to ConnState::Offline.
    let mut t = 200;
    for attempt in 1..=OFFLINE_AFTER_ATTEMPTS {
        let fx = eng.on_stream_closed(StreamId::Ci, Some("net down".into()), t);
        if attempt < OFFLINE_AFTER_ATTEMPTS {
            assert!(fx.iter().any(|e| matches!(
                e,
                Effect::Post(DataEvent::Connection(ConnState::Reconnecting { .. }))
            )));
        } else {
            assert!(fx.contains(&Effect::Post(DataEvent::Connection(ConnState::Offline))));
        }
        t += 60_000;
        eng.tick(t);
    }

    // When live /api/repos finally arrives, the STALE watermark clears and source becomes Live.
    eng.on_fetch(&FetchKind::Repos, Ok(REPOS.into()), t + 10);
    let fx = eng.tick(t + 200);
    let mut live_mirror = Some(view);
    drain_view_events(&fx, &mut live_mirror);
    let live_view = live_mirror.expect("live view");
    assert_eq!(live_view.source, DataSource::Live);
    assert_eq!(live_view.stale_since_epoch_ms, None);

    // After SAVE_INTERVAL_MS, changed live view is persisted back to CacheStorage.
    eng.on_stream_chunk(
        StreamId::Ci,
        b"event: node_membership_changed\ndata: {\"node_id\":\"node-a\",\"online\":true,\"fabric_rev\":10}\n\n",
        t + SAVE_INTERVAL_MS + 300,
    );
    let fx = eng.tick(t + SAVE_INTERVAL_MS + 400);
    let saved = fx
        .into_iter()
        .find_map(|e| match e {
            Effect::SaveOffline(b) => Some(b),
            _ => None,
        })
        .expect("SaveOffline emitted");
    let decoded = OfflineSnapshot::from_bytes(&saved).expect("decode saved snapshot");
    assert_eq!(decoded.view.source, DataSource::Live);
}

#[test]
fn deterministic_scenario_player_aliases_stepping_and_speed_control() {
    // Verify all query-string scenario aliases resolve and replay deterministically.
    for (alias, expected) in [
        ("ci_happy_path", Scenario::NewBranch),
        ("ci_pr_lifecycle", Scenario::PrMerged),
        ("cd_gate_promote", Scenario::Tainted),
        ("cd_gate_rollback", Scenario::ItCriticalFailure),
        ("submodule_interchange", Scenario::Submodules),
        ("node_loss", Scenario::NodeLost),
    ] {
        assert_eq!(Scenario::from_name(alias), Some(expected), "alias {alias}");
    }

    // Replay every canonical scenario end-to-end and verify mirror consistency.
    for sc in Scenario::ALL {
        if cfg!(miri) && matches!(sc, Scenario::Repos40) {
            continue;
        }
        let mut eng = Engine::new(1);
        let mut mirror = None;
        let cfg = WorkerConfig {
            api_base: String::new(),
            scenario: Some(sc.name().into()),
        };
        let fx = eng.handle(UiCommand::Configure(cfg), 0);
        let expected_conn = if sc.is_offline() {
            ConnState::Offline
        } else {
            ConnState::Scenario
        };
        assert!(fx.contains(&Effect::Post(DataEvent::Connection(expected_conn))));

        let end = sc.duration_ms();
        let tick_step = if cfg!(miri) { 500 } else { MIN_INTERVAL_MS };
        let mut now = 0;
        while now <= end {
            let fx = eng.tick(now);
            drain_view_events(&fx, &mut mirror);
            now += tick_step;
        }
        let fx = eng.tick(end + MIN_INTERVAL_MS);
        drain_view_events(&fx, &mut mirror);
        assert_eq!(
            mirror.as_ref(),
            Some(&eng.store().view()),
            "scenario {}",
            sc.name()
        );
    }

    // Verify manual single-stepping (speed = 0 + step_scenario) on cd_gate_rollback.
    let mut eng = Engine::new(2);
    eng.handle(
        UiCommand::Configure(WorkerConfig {
            api_base: String::new(),
            scenario: Some("cd_gate_rollback".into()),
        }),
        0,
    );
    eng.set_scenario_speed(0);
    // Wall-clock advances without emitting further scripted steps while paused.
    eng.tick(5_000);
    assert_eq!(
        eng.store().view().gate.as_ref().map(|g| g.outcome),
        Some(GateOutcome::Pending)
    );
    // Step through remaining scripted inputs deterministically.
    let mut steps = 0;
    while eng.step_scenario() {
        steps += 1;
    }
    assert_eq!(steps, 4);
    assert_eq!(
        eng.store().view().gate.as_ref().map(|g| g.outcome),
        Some(GateOutcome::RolledBack)
    );

    // Verify 2x playback speed reaches PR merge fade in half the wall-clock time.
    let mut fast = Engine::new(3);
    fast.handle(
        UiCommand::Configure(WorkerConfig {
            api_base: String::new(),
            scenario: Some("ci_pr_lifecycle".into()),
        }),
        0,
    );
    fast.set_scenario_speed(200);
    // At 2x speed, the t=1000 ms PR merge step fires by t=500 ms.
    fast.tick(500);
    let topo = fast.store().view().topology.expect("topology");
    let feat_a = topo
        .branches
        .iter()
        .find(|b| b.ref_name == "feat/a")
        .expect("feat/a");
    assert_eq!(feat_a.pr_state, PrState::Merged);
    assert!(matches!(
        feat_a.phase,
        SidingPhase::Fading {
            reason: FadeReason::Merged,
            ..
        }
    ));
    // After FADE_MS, the merged siding is removed.
    fast.tick(1_000 + FADE_MS + 100);
    let topo = fast.store().view().topology.expect("topology");
    assert!(topo.branches.iter().all(|b| b.ref_name != "feat/a"));

    // Retry restarts scenario from the beginning.
    fast.handle(UiCommand::Retry, 5_000);
    let topo = fast.store().view().topology.expect("topology");
    assert!(topo.branches.iter().any(|b| b.ref_name == "feat/a"));
}

#[test]
fn engine_handles_unknown_scenarios_routes_and_wire_errors() {
    let mut eng = Engine::new(5);

    // Unknown scenario emits UiError::UnknownScenario and falls back to Live mode.
    let fx = eng.handle(
        UiCommand::Configure(WorkerConfig {
            api_base: "/proxy".into(),
            scenario: Some("no-such-scenario".into()),
        }),
        0,
    );
    assert!(
        fx.contains(&Effect::Post(DataEvent::Error(UiError::UnknownScenario(
            "no-such-scenario".into()
        ))))
    );
    assert!(fx.contains(&Effect::Post(DataEvent::Ready {
        protocol: PROTOCOL_VERSION,
        source: DataSource::Live,
    })));

    // Subscribe route selects repo + submodule; Page and SetCrtFont are no-ops on the worker.
    let fx = eng.handle(
        UiCommand::Subscribe(Route {
            area: Area::Ci,
            subview: SubView::Ci(CiSubView::Trainway),
            repo: Some(RepoId::new(OWNER, SUPERPROJECT)),
            submodule: Some(SubmoduleId {
                path: "code/engine".into(),
            }),
            branch: None,
            job: None,
            trace_id: None,
            filter: None,
        }),
        10,
    );
    assert!(!fx.is_empty());
    let reg_fx = eng.handle(
        UiCommand::SelectSubView(SubView::Registry(RegistrySubView::Packages)),
        15,
    );
    assert!(reg_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::RegPackages,
            ..
        }
    )));
    let obs_fx = eng.handle(
        UiCommand::SelectSubView(SubView::Observe(ObserveSubView::PurePath)),
        16,
    );
    assert!(obs_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::ObsTraces,
            ..
        }
    )));
    assert!(!eng.handle(UiCommand::ResetStream, 18).is_empty());
    assert!(eng
        .handle(
            UiCommand::Page {
                panel: PanelId::Trainway,
                cursor: 1
            },
            20
        )
        .is_empty());
    assert!(eng
        .handle(UiCommand::SetCrtFont(CrtFont::OpenDyslexic), 30)
        .is_empty());

    // 404 on Deployments is ignored ("no CD for this repo"), whereas 500 surfaces UiError::Http.
    let repo = RepoId::new(OWNER, SUPERPROJECT);
    assert!(eng
        .on_fetch(
            &FetchKind::Deployments(repo.clone()),
            Err(HttpError {
                status: 404,
                message: "Not Found".into(),
            }),
            40,
        )
        .is_empty());
    let fx = eng.on_fetch(
        &FetchKind::Summary(repo),
        Err(HttpError {
            status: 500,
            message: "Internal Server Error".into(),
        }),
        50,
    );
    assert!(fx.contains(&Effect::Post(DataEvent::Error(UiError::Http {
        status: 500,
        message: "Internal Server Error".into(),
    }))));

    // Version mismatch and corrupt wire frames surface UiError without panicking.
    let mut bad_ver = postcard::to_allocvec(&(PROTOCOL_VERSION + 1)).expect("ver");
    bad_ver.extend_from_slice(&[0]);
    assert_eq!(
        eng.handle_frame(&bad_ver, 60),
        vec![Effect::Post(DataEvent::Error(UiError::VersionMismatch {
            expected: PROTOCOL_VERSION,
            found: PROTOCOL_VERSION + 1,
        }))]
    );
    let good_frame = encode(&UiCommand::Retry).expect("encode");
    assert!(!eng.handle_frame(&good_frame, 70).is_empty());
}

#[test]
fn auth_session_probe_and_invite_redemption_emit_auth_delta_and_refresh_repos() {
    use mu_console_protocol::dto::AuthSessionDto;
    use mu_console_protocol::{AuthState, Delta};

    let mut eng = Engine::new(11);
    let mut mirror = None;

    let fx = eng.handle(UiCommand::Configure(WorkerConfig::default()), 0);
    assert!(fx.contains(&Effect::Fetch {
        kind: FetchKind::AuthSession,
        url: "/api/auth/session".into(),
    }));
    eng.on_fetch(&FetchKind::Repos, Ok(REPOS.into()), 10);
    let fx = eng.tick(100);
    drain_view_events(&fx, &mut mirror);
    assert_eq!(
        mirror.as_ref().map(|v| &v.auth),
        Some(&AuthState::Anonymous)
    );

    // Uninvited GitHub user session transitions view.auth to InviteRequired.
    let uninvited_json =
        r#"{"authenticated":false,"github_login":"guest-user","invite_bound":false,"role":null}"#;
    eng.on_fetch(&FetchKind::AuthSession, Ok(uninvited_json.into()), 110);
    let fx = eng.tick(200);
    assert!(fx.iter().any(|e| matches!(
        e,
        Effect::Post(DataEvent::Patch(deltas))
            if deltas.contains(&Delta::Auth(AuthState::InviteRequired {
                github_login: "guest-user".into()
            }))
    )));
    drain_view_events(&fx, &mut mirror);

    // Redeeming a valid invite token issues FetchKind::AuthRedeem, transitions to Operator,
    // and refreshes /api/repos so private repos become visible.
    let fx = eng.handle(
        UiCommand::RedeemInvite {
            token: "inv_019a4f8c_secret".into(),
        },
        210,
    );
    assert!(fx.contains(&Effect::Fetch {
        kind: FetchKind::AuthRedeem("inv_019a4f8c_secret".into()),
        url: "/api/auth/redeem".into(),
    }));

    let redeemed_json = r#"{"authenticated":true,"github_login":"guest-user","invite_bound":true,"role":"operator"}"#;
    let fx = eng.on_fetch(
        &FetchKind::AuthRedeem("inv_019a4f8c_secret".into()),
        Ok(redeemed_json.into()),
        220,
    );
    assert!(fx.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::Repos,
            ..
        }
    )));
    let fx = eng.tick(350);
    drain_view_events(&fx, &mut mirror);
    assert_eq!(
        mirror.as_ref().map(|v| &v.auth),
        Some(&AuthState::Operator {
            github_login: "guest-user".into(),
            role: Some("operator".into()),
        })
    );

    // Direct SetAuthSession command also updates Store.auth.
    eng.handle(UiCommand::SetAuthSession(AuthSessionDto::default()), 360);
    assert_eq!(eng.store().auth(), &AuthState::Anonymous);
}

#[test]
fn live_cluster_nodes_ci_queue_and_non_empty_aux_views_regression() {
    let mut eng = Engine::new(77);
    let fx = eng.handle(UiCommand::Configure(WorkerConfig::default()), 0);
    assert!(fx.contains(&Effect::Fetch {
        kind: FetchKind::CiQueue,
        url: "/api/queue".into(),
    }));

    // Capture gen = 0 before /api/repos auto-selects the first repository (which increments selection_gen).
    let gen0 = eng.selection_gen();
    eng.on_fetch(&FetchKind::Repos, Ok(REPOS.into()), 10);
    assert!(eng.selection_gen() > gen0);

    // Global fetches initiated at gen0 (ClusterNodes, CiQueue, RegPackages, Leases, ObsProblems)
    // must NOT be dropped by on_fetch_gen after auto-selection bumped selection_gen!
    let nodes_json = r#"[{
        "node_id": "worker-riscv64",
        "is_online": true,
        "arch": "riscv64",
        "active_slots": 1,
        "max_slots": 1,
        "cpu_load_pct": 12.5,
        "ram_used_mb": 1720,
        "ram_total_mb": 32145,
        "btrfs_enabled": true,
        "exclusive_locked": true,
        "last_seen_secs_ago": 2,
        "tags": ["riscv64", "spacemit-k3"],
        "toolchains": ["rust", "miri", "wasm32"]
    }]"#;
    eng.on_fetch_gen(gen0, &FetchKind::ClusterNodes, Ok(nodes_json.into()), 20);

    let queue_json = r#"{
        "queue_depth": 0,
        "concurrency": 1,
        "active_jobs": [{
            "elapsed_secs": 18,
            "wait_secs": 2,
            "position": 0,
            "record": {
                "job": {
                    "id": "job-1794054805-5cec9056",
                    "repo_name": "LMA1980/mu-console",
                    "ref_name": "refs/heads/feat/live-workflow-parity",
                    "commit_sha": "5cec90561234",
                    "event_type": "push"
                },
                "stages": [
                    {
                        "id": "fmt-check",
                        "name": "fmt-check",
                        "assigned_node": "worker-riscv64",
                        "threads": 6,
                        "status": { "state": "Running", "details": { "duration_secs": 4, "exit_code": 0 } }
                    }
                ]
            }
        }],
        "queued_jobs": [],
        "recent_jobs": [{
            "job": {
                "id": "job-1794054497-af7344e0",
                "repo_name": "mu-console",
                "ref_name": "refs/heads/main",
                "commit_sha": "af7344e01234",
                "event_type": "push",
                "queued_at": "2026-11-07T05:00:00Z"
            },
            "metrics": {
                "quality_score": 99,
                "letter_grade": "A+",
                "coverage_pct": 94.8,
                "tests_passed": 71,
                "tests_total": 71
            },
            "stages": [
                {
                    "id": "fmt",
                    "name": "fmt-check",
                    "assigned_node": "worker-riscv64",
                    "threads": 6,
                    "status": { "state": "Completed", "details": { "duration_secs": 3, "exit_code": 0 } }
                },
                {
                    "id": "clippy",
                    "name": "clippy-check",
                    "assigned_node": "worker-riscv64",
                    "threads": 6,
                    "status": { "state": "Completed", "details": { "duration_secs": 8, "exit_code": 0 } }
                }
            ]
        }]
    }"#;
    eng.on_fetch_gen(gen0, &FetchKind::CiQueue, Ok(queue_json.into()), 25);

    // Hydrate submodules from /api/repos/{owner}/{repo}/summary when /api/repos had none.
    let summary_json = r#"{
        "owner": "LMA1980",
        "repo": "engine",
        "status": "passing",
        "score": 96,
        "coverage": 91.5,
        "bench_delta": 0.2,
        "latest_job_id": 29612437286333911,
        "commit_sha": "62add75b8019",
        "submodules": [
            { "path": "code/core", "owner": "LMA1980", "repo": "core", "pinned_sha": "a1b2c3d4" }
        ]
    }"#;
    let repo_a = RepoId::new("LMA1980", "engine");
    let sum_fx = eng.on_fetch_gen(
        eng.selection_gen(),
        &FetchKind::Summary(repo_a.clone()),
        Ok(summary_json.into()),
        28,
    );
    assert!(
        sum_fx.iter().any(|e| matches!(
            e,
            Effect::Fetch {
                kind: FetchKind::JobDetail(_),
                ..
            }
        )),
        "Summary hydration must automatically fetch JobDetail for the repo's latest_job_id"
    );

    // Empty arrays from RegPackages, RegCanaries, Leases, ObsProblems, and Deployments
    // in Live mode must produce explicit empty-state vectors rather than synthetic fixtures.
    eng.on_fetch_gen(gen0, &FetchKind::RegPackages, Ok("[]".into()), 30);
    eng.on_fetch_gen(gen0, &FetchKind::RegCanaries, Ok("[]".into()), 31);
    eng.on_fetch_gen(gen0, &FetchKind::Leases, Ok("[]".into()), 32);
    eng.on_fetch_gen(gen0, &FetchKind::ObsProblems, Ok("[]".into()), 33);
    eng.on_fetch_gen(
        gen0,
        &FetchKind::ObsLogs,
        Ok(r#"{"severity":"all","total":1,"logs":[{"timestamp_ms":1793858300000,"trace_id":"0102030405060708090a0b0c0d0e0f12","span_id":"010203040506070a","severity_text":"INFO","service":"muobserve-collector","body":"Edge collector mTLS forwarding verified from worker-riscv64"}]}"#.into()),
        34,
    );
    eng.on_fetch_gen(
        gen0,
        &FetchKind::ObsMetrics,
        Ok(r#"{"metric":"all","window":"1h","series":[],"cluster_efficiency":[]}"#.into()),
        34,
    );
    eng.on_fetch(&FetchKind::Deployments(repo_a.clone()), Ok("[]".into()), 35);

    let v = eng.store().view();
    let k3 = v
        .nodes
        .iter()
        .find(|n| n.id == "worker-riscv64")
        .expect("worker-riscv64 node");
    assert_eq!(k3.arch, "riscv64");
    assert_eq!(k3.active_slots, 1);
    assert_eq!(k3.cpu_load_bp, 1_250);
    assert_eq!(k3.ram_total_mb, 32_145);
    assert!(k3.btrfs_enabled);
    assert!(k3.exclusive_locked);
    assert_eq!(k3.tags, vec!["riscv64", "spacemit-k3"]);

    assert_eq!(v.ci_jobs.len(), 2);
    assert_eq!(v.ci_jobs[0].job_id_str, "job-1794054805-5cec9056");
    assert_eq!(v.ci_jobs[0].queue_state, "Active");
    assert_eq!(v.ci_jobs[0].elapsed_secs, 18);
    assert_eq!(v.ci_jobs[1].job_id_str, "job-1794054497-af7344e0");
    assert_eq!(v.ci_jobs[1].queue_state, "Passed");

    // Verify SelectJob + JobLog hydration and string job_id resolution for RestartJob / ResumeJob.
    let active_u64 = v.ci_jobs[0].job_id;
    let sel_fx = eng.handle(UiCommand::SelectJob { job_id: active_u64 }, 36);
    assert!(sel_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch { kind: FetchKind::JobDetail(id), url }
        if *id == active_u64 && url == "/api/jobs/job-1794054805-5cec9056"
    )));
    assert!(sel_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch { kind: FetchKind::JobLog(id), url }
        if *id == active_u64 && url == "/api/jobs/job-1794054805-5cec9056/log"
    )));
    eng.on_fetch(
        &FetchKind::JobLog(active_u64),
        Ok("\u{1b}[32mCompiling\u{1b}[0m mu-console (/var/lib/action-runner/work/mu-console)\nFinished release".into()),
        37,
    );
    let v_after_log = eng.store().view();
    assert_eq!(v_after_log.ci_jobs[0].raw_log_lines.len(), 2);
    assert!(v_after_log.ci_jobs[0].raw_log_lines[0].contains(".../work/mu-console"));

    let engine_repo = v_after_log
        .repos
        .iter()
        .find(|r| r.id == repo_a)
        .expect("LMA1980/engine repo");
    assert_eq!(engine_repo.submodules.len(), 1);
    assert_eq!(engine_repo.submodules[0].path, "code/core");

    assert!(v_after_log
        .observe
        .traces
        .iter()
        .any(|t| t.trace_id == "tr-ci-af7344"));
    assert!(v_after_log
        .observe
        .smartscape_nodes
        .iter()
        .any(|n| n.id == "svc:action-runner-controller"));
    assert!(v_after_log
        .observe
        .smartscape_nodes
        .iter()
        .any(|n| n.id == "proc:action-runner@worker-riscv64"));
    assert!(v_after_log
        .observe
        .smartscape_edges
        .iter()
        .any(|e| e.from_id == "svc:action-runner-controller"
            && e.to_id == "proc:action-runner@worker-riscv64"));
    assert!(v_after_log
        .observe
        .logs
        .iter()
        .any(|l| l.service == "actionrunner-rs" && l.trace_id == "tr-ci-af7344"));
    assert!(v_after_log
        .observe
        .logs
        .iter()
        .any(|l| l.service == "muobserve-collector"));
    assert!(!v_after_log.observe.metrics.is_empty());
    assert!(v_after_log.registry.packages.is_empty());
    assert!(v_after_log.registry.canaries.is_empty());
    assert!(v_after_log.leases.is_empty());
    assert!(v_after_log.observe.problems.is_empty());
    assert!(
        v_after_log.gate.is_none(),
        "Live mode must show explicit empty state when deployments list is empty"
    );
}

#[test]
fn operator_restart_job_dispatches_post_and_transitions_failed_stages() {
    use mu_console_protocol::{ConsoleSkin, StageState, UiError};

    let mut eng = Engine::new(99);
    let _ = eng.handle(UiCommand::Configure(WorkerConfig::default()), 0);

    // SetSkin is a UI-local preference and must be a clean no-op in the data worker.
    assert!(eng
        .handle(UiCommand::SetSkin(ConsoleSkin::Avionics), 5)
        .is_empty());

    // Anonymous RestartJob in Live mode must be rejected with 403 and emit no HTTP requests.
    let anon_eff = eng.handle(UiCommand::RestartJob { job_id: 1_233 }, 10);
    assert!(
        !anon_eff.iter().any(|e| matches!(
            e,
            Effect::Fetch {
                kind: FetchKind::RestartJob(_),
                ..
            }
        )),
        "anonymous caller must not dispatch RestartJob POST"
    );
    assert!(
        anon_eff.iter().any(|e| matches!(
            e,
            Effect::Post(DataEvent::Error(UiError::Http { status: 403, .. }))
        )),
        "anonymous caller must receive 403 error"
    );

    // Promote Live session to Operator via AuthSession fetch response.
    let _ = eng.on_fetch(
        &FetchKind::AuthSession,
        Ok(
            r#"{"authenticated":true,"invite_bound":true,"github_login":"LMA1980","role":"operator"}"#
                .into(),
        ),
        15,
    );
    assert!(eng.store().auth().is_operator());

    // Operator RestartJob in Live mode must dispatch POST /api/jobs/1233/restart.
    let op_eff = eng.handle(UiCommand::RestartJob { job_id: 1_233 }, 20);
    assert!(
        op_eff.iter().any(|e| matches!(
            e,
            Effect::Fetch {
                kind: FetchKind::RestartJob(1_233),
                url,
            } if url == "/api/jobs/1233/restart"
        )),
        "operator RestartJob must dispatch POST /api/jobs/1233/restart"
    );

    // Verify optimistic stage state transition (Failed -> Running) on stage-failure scenario.
    let mut sc_eng = Engine::new(100);
    let _ = sc_eng.handle(
        UiCommand::Configure(WorkerConfig {
            api_base: String::new(),
            scenario: Some("stage-failure".into()),
        }),
        0,
    );
    while sc_eng.step_scenario() {}
    let before_topo = sc_eng.store().view().topology.expect("topology");
    let failed_job_id = before_topo
        .trains
        .iter()
        .find(|t| t.stage_states.contains(&StageState::Failed))
        .map(|t| t.job_id)
        .expect("stage-failure train with Failed stage");
    let _ = sc_eng.handle(
        UiCommand::RestartJob {
            job_id: failed_job_id,
        },
        30,
    );
    let after_topo = sc_eng
        .store()
        .view()
        .topology
        .expect("topology after restart");
    let train_after = after_topo
        .trains
        .iter()
        .find(|t| t.job_id == failed_job_id)
        .expect("restarted train");
    assert!(
        !train_after.stage_states.contains(&StageState::Failed),
        "restarted train must transition Failed stages to Running"
    );
    assert!(train_after.stage_states.contains(&StageState::Running));
}
