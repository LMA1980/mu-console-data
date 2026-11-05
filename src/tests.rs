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
