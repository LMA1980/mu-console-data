// SPDX-License-Identifier: AGPL-3.0-only
//! End-to-end tests for [`crate::Engine`], [`crate::scenario::ScenarioPlayer`],
//! live fetch/SSE ingestion, <= 10 Hz coalescing, 350 ms rotary settle
//! debounce, generation-token stale-response rejection, hidden-tab pause /
//! resync, and offline cache watermark persistence.

use mu_console_protocol::{
    apply_all, encode, Area, AuthReasonCode, AuthStatus, CiSubView, ConnState, CrtFont, DataEvent,
    DataSource, FadeReason, GateOutcome, ObservabilitySubView, PanelId, PrState, RepoId,
    RepositorySubView, Route, Selection, SidingPhase, SubView, SubmoduleId, UiCommand, UiError,
    ViewModel, WorkerConfig, PROTOCOL_VERSION,
};

use crate::api::tests::{GATE, REPOS, TOPOLOGY};
use crate::api::{FetchKind, StreamId};
use crate::coalesce::{HEARTBEAT_MS, MIN_INTERVAL_MS};
use crate::engine::{
    Effect, Engine, HttpError, MIN_STABLE_STREAM_MS, OFFLINE_AFTER_ATTEMPTS, SELECT_SETTLE_MS,
};
use crate::offline::{OfflineSnapshot, SAVE_INTERVAL_MS};
use crate::scenario::{offline_snapshot, Scenario, OWNER, SUPERPROJECT};
use crate::store::FADE_MS;

const OPERATOR_SESSION_JSON: &str = r#"{
    "authenticated": true,
    "github_login": "operator",
    "invite_bound": true,
    "passkey_count": 1,
    "passkey_enrollment_required": false,
    "baseline_role": "operator",
    "bound_roles": ["operator"],
    "active_policies": [
        "system:status.read", "system:dashboard.read",
        "ci:queue.read", "ci:repos.public.read", "ci:repos.private.read",
        "ci:jobs.read", "ci:jobs.logs.read", "ci:nodes.read", "ci:sandboxes.read",
        "ci:ha.read", "ci:jobs.restart", "ci:jobs.resume",
        "cd:runs.read", "cd:steps.read",
        "ab:slots.read", "ab:gate.logs.read", "ab:rollback",
        "reg:packages.read", "reg:canaries.read", "reg:taints.read", "reg:cas.read",
        "obs:logs.read", "obs:smartscape.read", "obs:traces.read",
        "obs:problems.read", "obs:metrics.read", "obs:store.read", "obs:ingress.read",
        "mr:models.read", "mr:queue.read", "mr:openai_api.read", "mr:wireguard_vpn.read",
        "platform:maintenance.read", "platform:maintenance.write",
        "platform:users.read", "platform:users.write",
        "platform:invites.read", "platform:invites.write",
        "platform:roles.read", "platform:roles.write",
        "platform:folios.read", "platform:folios.write",
        "platform:activity.read"
    ]
}"#;

fn resolve_operator_session(eng: &mut Engine, now_ms: u64) -> Vec<Effect> {
    eng.on_fetch(
        &FetchKind::AuthSession,
        Ok(OPERATOR_SESSION_JSON.into()),
        now_ms,
    )
}

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
    // Fail-closed cold boot (t = 0): LoadOffline and non-auth fetches wait for AuthSession.
    assert!(!fx.contains(&Effect::LoadOffline));
    let auth_fx = resolve_operator_session(&mut eng, 5);
    assert!(auth_fx.contains(&Effect::LoadOffline));

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
    resolve_operator_session(&mut eng, 5);
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
    resolve_operator_session(&mut eng, 5);
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
        .any(|e| matches!(e, Effect::Post(DataEvent::AreaBadges(b)) if b.ci == 1)));
    drain_view_events(&fx, &mut mirror);
    assert_eq!(mirror.as_ref(), Some(&eng.store().view()));
}

#[test]
#[cfg_attr(miri, ignore)]
fn offline_snapshot_watermark_and_live_recovery() {
    let mut eng = Engine::new(100);
    eng.handle(UiCommand::Configure(WorkerConfig::default()), 0);
    resolve_operator_session(&mut eng, 5);

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

    // Replay every canonical scenario end-to-end (representative subset under Miri) and verify mirror consistency.
    let scenarios: &[Scenario] = if cfg!(miri) {
        &[
            Scenario::PrMerged,
            Scenario::ItCriticalFailure,
            Scenario::Offline,
        ]
    } else {
        &Scenario::ALL
    };
    for &sc in scenarios {
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
        let tick_step = if cfg!(miri) { 2_000 } else { MIN_INTERVAL_MS };
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
    resolve_operator_session(&mut eng, 5);

    // Subscribe route selects repo + submodule; Page and SetCrtFont emit no upstream effects.
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
        UiCommand::SelectSubView(SubView::Repository(RepositorySubView::Packages)),
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
        UiCommand::SelectSubView(SubView::Observability(ObservabilitySubView::PurePath)),
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
    let fx = eng.tick(0);
    drain_view_events(&fx, &mut mirror);
    assert_eq!(
        mirror.as_ref().map(|v| &v.auth),
        Some(&AuthState::unresolved())
    );

    // Non-lockdown anonymous session allows public read access without authentication.
    let anon_public_json = r#"{
        "authenticated":false,"github_login":null,"invite_bound":false,"anonymous_lockdown":false,
        "active_policies":["system:status.read","ci:repos.public.read","ci:queue.read"]
    }"#;
    eng.on_fetch(&FetchKind::AuthSession, Ok(anon_public_json.into()), 80);
    let fx = eng.tick(110);
    assert!(fx.iter().any(|e| matches!(
        e,
        Effect::Post(DataEvent::Patch(deltas))
            if deltas.iter().any(|d| matches!(
                d,
                Delta::Auth(a) if a.status == AuthStatus::Anonymous && !a.anonymous_lockdown
            ))
    )));
    drain_view_events(&fx, &mut mirror);
    assert_eq!(
        mirror.as_ref().map(|v| v.auth.status),
        Some(AuthStatus::Anonymous)
    );

    // Uninvited GitHub user session transitions view.auth to AuthorizationDenied and forces a clean Snapshot.
    let uninvited_json =
        r#"{"authenticated":false,"github_login":"guest-user","invite_bound":false,"role":null}"#;
    eng.on_fetch(&FetchKind::AuthSession, Ok(uninvited_json.into()), 120);
    let fx = eng.tick(220);
    assert!(fx.iter().any(|e| matches!(
        e,
        Effect::Post(DataEvent::Snapshot(v))
            if v.auth.status == AuthStatus::AuthorizationDenied
                && v.auth.github_login.as_deref() == Some("guest-user")
                && v.auth.reason_code == Some(AuthReasonCode::AuthorizationDenied)
    )));
    drain_view_events(&fx, &mut mirror);

    // Redeeming a valid invite token issues FetchKind::AuthRedeem, transitions to Active operator,
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

    let redeemed_json = r#"{
        "authenticated":true,"github_login":"guest-user","invite_bound":true,"passkey_count":1,
        "baseline_role":"operator","bound_roles":["operator"],
        "active_policies":["system:status.read","ci:queue.read","ci:repos.public.read","ci:repos.private.read"]
    }"#;
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
    let auth = mirror.as_ref().map(|v| &v.auth).expect("auth");
    assert_eq!(auth.status, AuthStatus::Active);
    assert_eq!(auth.github_login.as_deref(), Some("guest-user"));
    assert_eq!(auth.baseline_role.as_deref(), Some("operator"));

    // Direct SetAuthSession command resets cleanly to fail-closed Anonymous lockdown.
    eng.handle(UiCommand::SetAuthSession(AuthSessionDto::default()), 360);
    assert_eq!(eng.store().auth().status, AuthStatus::Anonymous);
    assert!(eng.store().auth().anonymous_lockdown);
}

#[test]
fn live_cluster_nodes_ci_queue_and_non_empty_aux_views_regression() {
    let mut eng = Engine::new(77);
    let fx = eng.handle(UiCommand::Configure(WorkerConfig::default()), 0);
    assert!(!fx.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::CiQueue,
            ..
        }
    )));
    let auth_fx = resolve_operator_session(&mut eng, 5);
    assert!(auth_fx.contains(&Effect::Fetch {
        kind: FetchKind::CiQueue,
        url: "/api/queue".into(),
    }));
    assert!(auth_fx.contains(&Effect::Fetch {
        kind: FetchKind::ObsSubsystemStatus,
        url: "/api/obs/v1/status/subsystems".into(),
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
        &FetchKind::ObsTraces,
        Ok(r#"{"domain":"all","total":1,"traces":[{"trace_id":"tr-ci-af7344","root_service":"actionrunner-controller","root_operation":"queue.dispatch","domain":"CI","duration_ms":120,"error":false,"slow_p99":false,"started_epoch_ms":1793858200000,"spans":[]}]}"#.into()),
        33,
    );
    eng.on_fetch_gen(
        gen0,
        &FetchKind::ObsLogs,
        Ok(r#"{"severity":"all","total":2,"logs":[{"timestamp_ms":1793858300000,"trace_id":"0102030405060708090a0b0c0d0e0f12","span_id":"010203040506070a","severity_text":"INFO","service":"muobserve-collector","body":"Edge collector mTLS forwarding verified from worker-riscv64"},{"timestamp_ms":1793858200000,"trace_id":"tr-ci-af7344","span_id":"010203040506070b","severity_text":"INFO","service":"actionrunner-rs","body":"Build step finished"}]}"#.into()),
        34,
    );
    eng.on_fetch_gen(
        gen0,
        &FetchKind::ObsMetrics,
        Ok(r#"{"metric":"all","window":"1h","series":[{"service":"node:worker-riscv64","hardware_class":"riscv64","rps":10,"error_rate_bp":0,"p50_ms":5,"p95_ms":15,"p99_ms":20,"exemplar_trace_id":"","samples":[5,10,15]}],"cluster_efficiency":[]}"#.into()),
        34,
    );
    eng.on_fetch_gen(
        gen0,
        &FetchKind::ObsSmartscape,
        Ok(r#"{
            "window_secs": 300,
            "services": [{"id":"svc:action-runner-controller","name":"action-runner-controller","request_rate_rps":8.9,"error_rate_pct":0.0,"p95_latency_ms":12.0,"health_state":"healthy"}],
            "processes": [
                {"id":"proc:action-runner@worker-riscv64","name":"action-runner@worker-riscv64","health_state":"healthy"},
                {"id":"proc:mu-observable","name":"mu-observable","health_state":"healthy"},
                {"id":"proc:duckdb-hot-store","name":"duckdb-hot-store","health_state":"healthy"}
            ],
            "hosts": [],
            "edges": [{"source":"svc:action-runner-controller","target":"proc:action-runner@worker-riscv64","relation":"calls","request_rate_rps":8.9,"error_rate_pct":0.0,"p95_latency_ms":12.0}]
        }"#.into()),
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

    // Verify anonymous 401 on /api/jobs/{id}/log automatically falls back to /api/obs/v1/jobs/{id}/log.
    let second_u64 = v_after_log.ci_jobs[1].job_id;
    let fb_fx = eng.on_fetch(
        &FetchKind::JobLog(second_u64),
        Err(HttpError {
            status: 401,
            message: "Unauthorized".into(),
        }),
        38,
    );
    assert!(fb_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch { kind: FetchKind::JobLog(id), url }
        if *id == second_u64 && url == "/api/obs/v1/jobs/job-1794054497-af7344e0/log"
    )));

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
    assert_eq!(
        v_after_log.observe.logs[0].service, "muobserve-collector",
        "Live MuObserve OTel logs must be prioritized ahead of synthetic CI job logs"
    );
    assert!(v_after_log
        .observe
        .logs
        .iter()
        .any(|l| l.service == "actionrunner-rs" && l.trace_id == "tr-ci-af7344"));
    assert!(v_after_log
        .observe
        .smartscape_nodes
        .iter()
        .any(|n| n.id == "proc:mu-observable"));
    assert!(v_after_log
        .observe
        .smartscape_nodes
        .iter()
        .any(|n| n.id == "proc:duckdb-hot-store"));

    // Verify subsequent CiQueue updates preserve live_obs_logs at the top of observe.logs.
    eng.on_fetch_gen(gen0, &FetchKind::CiQueue, Ok(queue_json.into()), 39);
    let v_after_requeue = eng.store().view();
    assert_eq!(
        v_after_requeue.observe.logs[0].service,
        "muobserve-collector"
    );
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
        .handle(UiCommand::SetSkin(ConsoleSkin::Wireframe), 5)
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
            r#"{
                "authenticated":true,"invite_bound":true,"github_login":"LMA1980","role":"operator",
                "passkey_count":1,"baseline_role":"operator","bound_roles":["operator"],
                "active_policies":["ci:jobs.restart","ci:jobs.resume","ci:queue.read","ci:repos.public.read","system:status.read"]
            }"#
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

#[test]
fn live_sse_push_and_active_job_log_tailing() {
    use mu_console_protocol::StageState;

    let mut eng = Engine::new(42);
    let _ = eng.handle(UiCommand::Configure(WorkerConfig::default()), 0);
    // Authenticated observer holding ci:queue.read + ci:jobs.read + obs:logs.read (no ci:jobs.logs.read)
    // tails build logs via the sanitized MuObserve fallback endpoint.
    let _ = eng.on_fetch(
        &FetchKind::AuthSession,
        Ok(
            r#"{
                "authenticated":true,"invite_bound":true,"github_login":"viewer","passkey_count":1,
                "baseline_role":"viewer","bound_roles":["viewer"],
                "active_policies":["system:status.read","ci:queue.read","ci:repos.public.read","ci:jobs.read","obs:logs.read"]
            }"#
            .into(),
        ),
        2,
    );
    let _ = eng.on_stream_open(StreamId::Ci, 5);

    // 1. SSE event: queue populates active job in Store.ci_jobs.
    let sse_queue = concat!(
        "event: queue\n",
        "data: {\"queue_depth\":0,\"concurrency\":1,\"active_jobs\":[{\"elapsed_secs\":5,\"wait_secs\":1,\"position\":0,\"record\":{\"job\":{\"id\":\"job-1794054805-5cec9056\",\"repo_name\":\"LMA1980/mu-console\",\"ref_name\":\"refs/heads/main\",\"commit_sha\":\"5cec90561234\",\"event_type\":\"push\"},\"status\":{\"state\":\"Running\"},\"stages\":[{\"id\":\"fmt-check\",\"name\":\"fmt-check\",\"assigned_node\":\"worker-riscv64\",\"threads\":6,\"status\":{\"state\":\"Running\",\"details\":{\"duration_secs\":2,\"exit_code\":0}}}]}}],\"queued_jobs\":[],\"recent_jobs\":[]}\n\n"
    );
    let _ = eng.on_stream_chunk(StreamId::Ci, sse_queue.as_bytes(), 10);
    let v = eng.store().view();
    assert_eq!(v.ci_jobs.len(), 1);
    assert_eq!(v.ci_jobs[0].queue_state, "Active");
    let job_id = v.ci_jobs[0].job_id;

    // 2. Engine::tick at >= 2_000ms polls JobDetail + JobLog for the active job.
    let tick_fx = eng.tick(2_010);
    assert!(tick_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch { kind: FetchKind::JobDetail(id), url }
        if *id == job_id && url == "/api/jobs/job-1794054805-5cec9056"
    )));
    assert!(tick_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch { kind: FetchKind::JobLog(id), url }
        if *id == job_id && url == "/api/obs/v1/jobs/job-1794054805-5cec9056/log"
    )));

    // 3. SSE event: job_stage_changed updates Store.ci_jobs stage state and triggers refresh fetches.
    let sse_stage = concat!(
        "event: job_stage_changed\n",
        "data: {\"owner\":\"LMA1980\",\"repo\":\"mu-console\",\"job_id\":\"job-1794054805-5cec9056\",\"ref\":\"main\",\"stage\":\"fmt-check\",\"state\":\"passed\",\"fabric_rev\":10}\n\n"
    );
    let stage_fx = eng.on_stream_chunk(StreamId::Ci, sse_stage.as_bytes(), 2_100);
    assert!(stage_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::CiQueue,
            ..
        }
    )));
    let v_after = eng.store().view();
    assert_eq!(v_after.ci_jobs[0].stages[0].state, StageState::Passed);
    assert_eq!(v_after.ci_jobs[0].queue_state, "Passed");

    // 4. Switching to OBS > Logs polls ObsLogs + CiQueue on live tick even when no CI job is running.
    let _ = eng.handle(
        UiCommand::SelectSubView(SubView::Observability(ObservabilitySubView::Logs)),
        2_200,
    );
    let obs_tick_fx = eng.tick(4_020);
    assert!(obs_tick_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::ObsLogs,
            ..
        }
    )));
    assert!(obs_tick_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::CiQueue,
            ..
        }
    )));

    // 5. Switching to CI > Queue & Logs polls CiQueue + ObsLogs and hydrates missing job logs on tick.
    let _ = eng.handle(
        UiCommand::SelectSubView(SubView::Ci(CiSubView::QueueLogs)),
        4_100,
    );
    let ci_tick_fx = eng.tick(6_030);
    assert!(ci_tick_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::CiQueue,
            ..
        }
    )));
    assert!(ci_tick_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::JobLog(id),
            url,
        } if *id == job_id && url == "/api/obs/v1/jobs/job-1794054805-5cec9056/log"
    )));
}

#[test]
#[cfg_attr(miri, ignore)]
fn cold_boot_fails_closed_until_session_resolves() {
    use mu_console_protocol::AreaBadges;

    let mut eng = Engine::new(301);
    let fx = eng.handle(UiCommand::Configure(WorkerConfig::default()), 0);

    // At t = 0: ONLY AuthSession + Ready + Connecting; zero LoadOffline, SSE, or non-auth REST.
    assert!(fx.contains(&Effect::Fetch {
        kind: FetchKind::AuthSession,
        url: "/api/auth/session".into(),
    }));
    assert!(!fx.contains(&Effect::LoadOffline));
    assert!(!fx.iter().any(|e| matches!(e, Effect::OpenStream { .. })));
    assert!(!fx.iter().any(|e| matches!(
        e,
        Effect::Fetch { kind, .. } if !matches!(kind, FetchKind::AuthSession)
    )));
    assert_eq!(eng.store().auth().status, AuthStatus::Unresolved);
    assert_eq!(eng.store().view(), ViewModel::default());
    assert_eq!(eng.store().badges(), AreaBadges::default());

    // Navigating subviews before session resolution emits zero operational fetches.
    assert!(eng
        .handle(
            UiCommand::SelectSubView(SubView::Observability(ObservabilitySubView::Logs)),
            10,
        )
        .is_empty());

    // Even if offline bytes arrive pre-session, Store::view stays fail-closed empty.
    let bytes = offline_snapshot().to_bytes().expect("encode offline");
    eng.on_offline_loaded(Some(&bytes), 20);
    assert_eq!(eng.store().view(), ViewModel::default());
}

#[test]
#[cfg_attr(miri, ignore)]
fn anonymous_lockdown_and_zero_passkey_gate_suppress_non_auth_fetches() {
    use mu_console_protocol::{AreaBadges, DialogModel};

    // 1. Anonymous lockdown mode withholds LoadOffline, SSE, and all non-auth REST calls.
    let mut eng = Engine::new(302);
    eng.handle(UiCommand::Configure(WorkerConfig::default()), 0);
    let lockdown_fx = eng.on_fetch(
        &FetchKind::AuthSession,
        Ok(r#"{"authenticated":false,"anonymous_lockdown":true,"active_policies":[]}"#.into()),
        10,
    );
    assert!(!lockdown_fx.contains(&Effect::LoadOffline));
    assert!(!lockdown_fx
        .iter()
        .any(|e| matches!(e, Effect::OpenStream { .. })));
    assert!(!lockdown_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch { kind, .. } if !matches!(kind, FetchKind::AuthSession)
    )));
    assert!(eng
        .handle(
            UiCommand::SelectSubView(SubView::Ci(CiSubView::QueueLogs)),
            20
        )
        .is_empty());
    assert_eq!(eng.store().badges(), AreaBadges::default());

    // 2a. Authenticated 0-Passkey session WITH anonymous_lockdown opens PasskeyEnrollmentGate,
    // suppresses LoadOffline/SSE/non-auth REST, yet allows dismiss and Passkey registration.
    let locked_zero_pk_json = r#"{
        "authenticated": true,
        "github_login": "alice",
        "invite_bound": true,
        "passkey_count": 0,
        "passkey_enrollment_required": true,
        "anonymous_lockdown": true,
        "baseline_role": "operator",
        "bound_roles": ["operator"],
        "active_policies": []
    }"#;
    let locked_gate_fx = eng.on_fetch(&FetchKind::AuthSession, Ok(locked_zero_pk_json.into()), 25);
    assert!(!locked_gate_fx.contains(&Effect::LoadOffline));
    assert!(!locked_gate_fx
        .iter()
        .any(|e| matches!(e, Effect::OpenStream { .. })));
    assert!(!locked_gate_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch { kind, .. }
            if !matches!(
                kind,
                FetchKind::AuthSession | FetchKind::AuthPasskeys
            )
    )));
    assert!(matches!(
        eng.store().view().active_dialog,
        Some(DialogModel::PasskeyEnrollmentGate(ref g)) if g.github_login == "alice" && g.passkey_count == 0
    ));

    // 2b. Authenticated 0-Passkey session WITHOUT anonymous_lockdown opens PasskeyEnrollmentGate
    // as a dismissible guiding modal, permits baseline public reads/streams, withholds LoadOffline
    // and operator/private endpoints, and unblocks full workspace on Passkey enrollment.
    let zero_pk_json = r#"{
        "authenticated": true,
        "github_login": "alice",
        "invite_bound": true,
        "passkey_count": 0,
        "passkey_enrollment_required": true,
        "anonymous_lockdown": false,
        "baseline_role": "operator",
        "bound_roles": ["operator"],
        "active_policies": []
    }"#;
    let gate_fx = eng.on_fetch(&FetchKind::AuthSession, Ok(zero_pk_json.into()), 30);
    assert!(!gate_fx.contains(&Effect::LoadOffline));
    assert!(gate_fx.iter().any(|e| matches!(
        e,
        Effect::OpenStream {
            stream: StreamId::Ci,
            ..
        }
    )));
    assert!(gate_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::Repos,
            ..
        }
    )));
    assert!(!gate_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::ClusterNodes
                | FetchKind::ObsLogs
                | FetchKind::RegPackages
                | FetchKind::AuthProfile,
            ..
        }
    )));

    let v_gate = eng.store().view();
    assert_eq!(v_gate.auth.status, AuthStatus::PasskeyEnrollmentRequired);
    assert!(matches!(
        v_gate.active_dialog,
        Some(DialogModel::PasskeyEnrollmentGate(ref g)) if g.github_login == "alice" && g.passkey_count == 0
    ));

    // CloseDialog dismisses PasskeyEnrollmentGate while operator-only subviews remain gated.
    eng.handle(UiCommand::CloseDialog, 40);
    assert!(eng.store().view().active_dialog.is_none());
    assert!(eng
        .handle(
            UiCommand::SelectSubView(SubView::Repository(RepositorySubView::Packages)),
            45,
        )
        .is_empty());

    // Opening UserProfile in 0-Passkey mode skips 403-gated AuthProfile while fetching AuthPasskeys.
    let profile_fx = eng.handle(
        UiCommand::OpenDialog(DialogModel::UserProfile(Default::default())),
        48,
    );
    assert!(profile_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::AuthPasskeys,
            ..
        }
    )));
    assert!(!profile_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::AuthProfile,
            ..
        }
    )));
    eng.handle(UiCommand::CloseDialog, 49);
    assert!(eng.store().view().active_dialog.is_none());

    // Passkey enrollment DOES dispatch in 0-Passkey state.
    let enroll_fx = eng.handle(
        UiCommand::EnrollPasskey {
            label: Some("YubiKey".into()),
            attestation_json: r#"{"id":"pk-1"}"#.into(),
        },
        50,
    );
    assert!(enroll_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::AuthPasskeyRegisterFinish { .. },
            url,
        } if url == "/api/auth/passkeys/register/finish"
    )));

    let finish_fx = eng.on_fetch(
        &FetchKind::AuthPasskeyRegisterFinish {
            label: Some("YubiKey".into()),
            attestation_json: r#"{"id":"pk-1"}"#.into(),
        },
        Ok(r#"{"credential_id":"pk-1","label":"YubiKey","created_at_ms":55}"#.into()),
        55,
    );
    assert!(finish_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::AuthSession,
            ..
        }
    )));
    assert!(finish_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::AuthPasskeys,
            ..
        }
    )));

    // Refreshing AuthSession with passkey_count == 1 closes PasskeyEnrollmentGate and unlocks workspace.
    let unlock_fx = resolve_operator_session(&mut eng, 60);
    assert!(unlock_fx.contains(&Effect::LoadOffline));
    assert!(unlock_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::ClusterNodes,
            ..
        }
    )));
    assert!(eng.store().view().active_dialog.is_none());
}

#[test]
fn auth_passkey_register_finish_with_session_envelope_bootstraps_streams_and_repos() {
    use mu_console_protocol::DialogModel;

    let mut eng = Engine::new(304);
    eng.handle(UiCommand::Configure(WorkerConfig::default()), 0);

    let zero_pk_json = r#"{
        "authenticated": true,
        "github_login": "alice",
        "invite_bound": true,
        "passkey_count": 0,
        "passkey_enrollment_required": true,
        "baseline_role": "operator",
        "bound_roles": ["operator"],
        "active_policies": []
    }"#;
    let gate_fx = eng.on_fetch(&FetchKind::AuthSession, Ok(zero_pk_json.into()), 10);
    assert!(!gate_fx.contains(&Effect::LoadOffline));
    assert!(!gate_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::ClusterNodes,
            ..
        }
    )));
    assert!(matches!(
        eng.store().view().active_dialog,
        Some(DialogModel::PasskeyEnrollmentGate(_))
    ));

    let enroll_finish_json = r#"{
        "enrolled": true,
        "credential_id": "pk-1",
        "passkey_count": 1,
        "passkey_enrollment_required": false,
        "session": {
            "authenticated": true,
            "github_login": "alice",
            "invite_bound": true,
            "passkey_count": 1,
            "passkey_enrollment_required": false,
            "baseline_role": "operator",
            "bound_roles": ["operator"],
            "active_roles": [{"id": "operator"}],
            "active_policies": ["system:status.read", "ci:repos.public.read", "ci:repos.private.read", "ci:queue.read", "ci:nodes.read"]
        }
    }"#;
    let finish_fx = eng.on_fetch(
        &FetchKind::AuthPasskeyRegisterFinish {
            label: Some("Security Key".into()),
            attestation_json: r#"{"challenge_id":"ch-1","credential":{"id":"pk-1"}}"#.into(),
        },
        Ok(enroll_finish_json.into()),
        20,
    );

    assert_eq!(eng.store().view().auth.status, AuthStatus::Active);
    assert!(eng.store().view().active_dialog.is_none());
    assert!(finish_fx.contains(&Effect::LoadOffline));
    assert!(finish_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::Repos,
            ..
        }
    )));
    assert!(finish_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::ClusterNodes,
            ..
        }
    )));
}

#[test]
fn anonymous_bounded_polling_eliminates_log_node_and_registry_leaks() {
    let mut eng = Engine::new(303);
    eng.handle(UiCommand::Configure(WorkerConfig::default()), 0);

    // Non-lockdown anonymous grants ONLY system:status.read, ci:queue.read, ci:repos.public.read.
    let anon_json = r#"{
        "authenticated": false,
        "github_login": null,
        "invite_bound": false,
        "anonymous_lockdown": false,
        "active_policies": ["system:status.read", "ci:queue.read", "ci:repos.public.read"]
    }"#;
    let boot_fx = eng.on_fetch(&FetchKind::AuthSession, Ok(anon_json.into()), 10);

    // Must fetch ONLY authorized public endpoints and open ONLY Ci + Obs streams.
    assert!(boot_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::ObsSubsystemStatus,
            url,
        } if url == "/api/obs/v1/status/subsystems"
    )));
    assert!(boot_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::Repos,
            ..
        }
    )));
    assert!(boot_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::CiQueue,
            ..
        }
    )));
    assert!(boot_fx.iter().any(|e| matches!(
        e,
        Effect::OpenStream {
            stream: StreamId::Ci,
            ..
        }
    )));
    assert!(boot_fx.iter().any(|e| matches!(
        e,
        Effect::OpenStream {
            stream: StreamId::Obs,
            ..
        }
    )));
    assert!(!boot_fx.iter().any(|e| matches!(
        e,
        Effect::OpenStream {
            stream: StreamId::Cd,
            ..
        }
    )));
    assert!(!boot_fx.contains(&Effect::LoadOffline));

    for forbidden in &boot_fx {
        assert!(
            !matches!(
                forbidden,
                Effect::Fetch {
                    kind: FetchKind::ClusterNodes
                        | FetchKind::ObsLogs
                        | FetchKind::ObsStoreStatus
                        | FetchKind::RegPackages
                        | FetchKind::RegCanaries
                        | FetchKind::RegCasStatus
                        | FetchKind::JobDetail(_)
                        | FetchKind::JobLog(_),
                    ..
                }
            ),
            "anonymous bootstrap leaked forbidden fetch: {forbidden:?}"
        );
    }

    // Deliver CiQueue, open QueueLogs, SelectJob, and tick past 2s poll interval:
    // ZERO raw /api/jobs/{id}/log or /api/obs/v1/jobs/{id}/log or /api/obs/v1/logs or /api/cluster/nodes!
    let queue_json = r#"{
        "queue_depth": 0,
        "concurrency": 1,
        "active_jobs": [{
            "elapsed_secs": 8, "wait_secs": 0, "position": 0,
            "record": {
                "job": { "id": "job-1794054805-5cec9056", "repo_name": "LMA1980/mu-console", "ref_name": "main", "commit_sha": "5cec90561234", "event_type": "push" },
                "status": { "state": "Running" },
                "stages": [{ "id": "fmt-check", "name": "fmt-check", "threads": 6, "status": { "state": "Running", "details": { "duration_secs": 2, "exit_code": 0 } } }]
            }
        }],
        "queued_jobs": [],
        "recent_jobs": []
    }"#;
    let q_fx = eng.on_fetch(&FetchKind::CiQueue, Ok(queue_json.into()), 20);
    assert!(!q_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::JobLog(_) | FetchKind::JobDetail(_),
            ..
        }
    )));

    let job_id = eng.store().view().ci_jobs[0].job_id;
    let sub_fx = eng.handle(
        UiCommand::SelectSubView(SubView::Ci(CiSubView::QueueLogs)),
        30,
    );
    let sel_fx = eng.handle(UiCommand::SelectJob { job_id }, 40);
    let tick_fx = eng.tick(2_500);
    let nodes_fx = eng.handle(
        UiCommand::SelectSubView(SubView::Ci(CiSubView::WorkerNodes)),
        2_600,
    );
    let fb_fx = eng.on_fetch(
        &FetchKind::JobLog(job_id),
        Err(HttpError {
            status: 401,
            message: "Unauthorized".into(),
        }),
        2_700,
    );

    for fx_batch in [&sub_fx, &sel_fx, &tick_fx, &nodes_fx, &fb_fx] {
        for e in fx_batch {
            assert!(
                !matches!(
                    e,
                    Effect::Fetch {
                        kind: FetchKind::JobLog(_)
                            | FetchKind::JobDetail(_)
                            | FetchKind::ObsLogs
                            | FetchKind::ClusterNodes
                            | FetchKind::RegPackages
                            | FetchKind::RegCanaries
                            | FetchKind::RegCasStatus,
                        ..
                    }
                ),
                "anonymous polling leaked restricted endpoint: {e:?}"
            );
        }
    }
}

#[test]
fn independent_role_lease_countdown_activity_reset_and_single_role_expiry_scrubbing() {
    use mu_console_protocol::dto::{
        FolioOrigin, PolicyFolioDto, RoleActivationDto, RoleFolioIndexDto, RoleSpecDto,
    };

    let mut eng = Engine::new(304);
    eng.handle(UiCommand::Configure(WorkerConfig::default()), 0);
    let mut mirror = None;

    // Session at t = 1_000 ms has:
    // - baseline "viewer" (PinnedBaseline)
    // - elective "ci-operator" (Elective)
    // - timed "ab-responder" (hard 10s -> 11_000 ms, idle 5s -> 6_000 ms)
    // - timed "obs-investigator" (hard 30s -> 31_000 ms, idle 20s -> 21_000 ms)
    let session_json = r#"{
        "authenticated": true,
        "github_login": "responder",
        "invite_bound": true,
        "passkey_count": 1,
        "passkey_enrollment_required": false,
        "baseline_role": "viewer",
        "bound_roles": ["viewer", "ci-operator", "ab-responder", "obs-investigator"],
        "active_roles": [
            { "id": "viewer", "activation": { "kind": "pinned_baseline" } },
            { "id": "ci-operator", "activation": { "kind": "elective" } },
            { "id": "ab-responder", "activation": { "kind": "timed", "hard_ttl_secs": 10, "idle_ttl_secs": 5 } },
            { "id": "obs-investigator", "activation": { "kind": "timed", "hard_ttl_secs": 30, "idle_ttl_secs": 20 } }
        ],
        "leases": [
            {
                "role_id": "ab-responder",
                "activated_at_ms": 1000,
                "last_activity_at_ms": 1000,
                "hard_expires_at_ms": 11000,
                "idle_expires_at_ms": 6000,
                "hard_ttl_secs": 10,
                "idle_ttl_secs": 5,
                "seconds_remaining": 10,
                "idle_timer": 5
            },
            {
                "role_id": "obs-investigator",
                "activated_at_ms": 1000,
                "last_activity_at_ms": 1000,
                "hard_expires_at_ms": 31000,
                "idle_expires_at_ms": 21000,
                "hard_ttl_secs": 30,
                "idle_ttl_secs": 20,
                "seconds_remaining": 30,
                "idle_timer": 20
            }
        ],
        "active_folios": [
            "folio:baseline",
            "folio:ci-ops",
            "folio:ab-ops",
            "folio:obs-ops",
            "folio:plat-read"
        ],
        "active_policies": [
            "system:status.read", "ci:repos.public.read", "ci:queue.read",
            "ci:jobs.read", "ci:nodes.read",
            "ab:slots.read", "ab:rollback", "cd:runs.read",
            "obs:logs.read", "obs:traces.read",
            "platform:folios.read"
        ]
    }"#;
    let boot_fx = eng.on_fetch(&FetchKind::AuthSession, Ok(session_json.into()), 1_000);
    assert!(boot_fx.iter().any(|e| matches!(
        e,
        Effect::OpenStream {
            stream: StreamId::Cd,
            ..
        }
    )));
    eng.on_stream_open(StreamId::Ci, 1_005);
    eng.on_stream_open(StreamId::Cd, 1_005);
    eng.on_stream_open(StreamId::Obs, 1_005);

    // Load RoleCatalog, PolicyFolio catalog & RoleFolioIndex + operational slices for all 4 roles.
    let roles_dto = vec![
        RoleSpecDto {
            id: "viewer".into(),
            display_name: None,
            description: String::new(),
            activation: RoleActivationDto::pinned_baseline(),
            step_up: Default::default(),
        },
        RoleSpecDto {
            id: "ci-operator".into(),
            display_name: None,
            description: String::new(),
            activation: RoleActivationDto::elective(),
            step_up: Default::default(),
        },
        RoleSpecDto {
            id: "ab-responder".into(),
            display_name: None,
            description: String::new(),
            activation: RoleActivationDto::timed(10, 5),
            step_up: Default::default(),
        },
        RoleSpecDto {
            id: "obs-investigator".into(),
            display_name: None,
            description: String::new(),
            activation: RoleActivationDto::timed(30, 20),
            step_up: Default::default(),
        },
    ];
    let folios_json = serde_json::json!({
        "folios": [
            PolicyFolioDto {
                id: "folio:baseline".into(),
                display_name: "Baseline".into(),
                description: String::new(),
                origin: FolioOrigin::Operator,
                owner_subsystem: None,
                includes: Vec::new(),
                policies: vec!["system:status.read".into(), "ci:repos.public.read".into(), "ci:queue.read".into()],
            },
            PolicyFolioDto {
                id: "folio:ci-ops".into(),
                display_name: "CI Ops".into(),
                description: String::new(),
                origin: FolioOrigin::Operator,
                owner_subsystem: None,
                includes: Vec::new(),
                policies: vec!["ci:jobs.read".into(), "ci:nodes.read".into()],
            },
            PolicyFolioDto {
                id: "folio:ab-ops".into(),
                display_name: "AB Ops".into(),
                description: String::new(),
                origin: FolioOrigin::Operator,
                owner_subsystem: None,
                includes: Vec::new(),
                policies: vec!["ab:slots.read".into(), "ab:rollback".into(), "cd:runs.read".into()],
            },
            PolicyFolioDto {
                id: "folio:obs-ops".into(),
                display_name: "OBS Ops".into(),
                description: String::new(),
                origin: FolioOrigin::Operator,
                owner_subsystem: None,
                includes: Vec::new(),
                policies: vec!["obs:logs.read".into(), "obs:traces.read".into()],
            },
            PolicyFolioDto {
                id: "folio:plat-read".into(),
                display_name: "Plat".into(),
                description: String::new(),
                origin: FolioOrigin::Operator,
                owner_subsystem: None,
                includes: Vec::new(),
                policies: vec!["platform:folios.read".into()],
            }
        ],
        "policies": []
    });
    let mut role_folios = std::collections::BTreeMap::new();
    role_folios.insert(
        "viewer".into(),
        vec!["folio:baseline".into(), "folio:plat-read".into()],
    );
    role_folios.insert("ci-operator".into(), vec!["folio:ci-ops".into()]);
    role_folios.insert("ab-responder".into(), vec!["folio:ab-ops".into()]);
    role_folios.insert("obs-investigator".into(), vec!["folio:obs-ops".into()]);
    let rfi = RoleFolioIndexDto {
        anonymous: Vec::new(),
        role_folios,
    };

    eng.on_fetch(
        &FetchKind::AuthRoles,
        Ok(serde_json::to_string(&roles_dto).unwrap()),
        1_010,
    );
    eng.on_fetch(&FetchKind::AuthFolios, Ok(folios_json.to_string()), 1_010);
    eng.on_fetch(
        &FetchKind::AuthRoleFolioIndex,
        Ok(serde_json::to_string(&rfi).unwrap()),
        1_010,
    );

    eng.on_fetch(&FetchKind::Repos, Ok(REPOS.into()), 1_020);
    eng.on_fetch(
        &FetchKind::ClusterNodes,
        Ok(r#"[{"node_id":"worker-riscv64","is_online":true,"arch":"riscv64","active_slots":0,"max_slots":1,"cpu_load_pct":10.0,"ram_used_mb":1024,"ram_total_mb":32768,"btrfs_enabled":true,"exclusive_locked":false,"last_seen_secs_ago":1}]"#.into()),
        1_020,
    );
    eng.on_fetch(
        &FetchKind::Leases,
        Ok(r#"[{"deployment_id":"dep-42","service":"muconsole","target_node":"worker-riscv64","slot":"b","remaining_secs":120}]"#.into()),
        1_020,
    );
    eng.on_fetch(
        &FetchKind::CdRuns {
            repo: RepoId::new("LMA1980", "engine"),
            ecosystem: None,
            limit: 25,
        },
        Ok(r#"[{"run_id":"run-1","ecosystem":"cargo","repo":{"owner":"LMA1980","repo":"engine"},"state":"succeeded","started_epoch_ms":1000}]"#.into()),
        1_020,
    );
    eng.on_fetch(
        &FetchKind::ObsLogs,
        Ok(r#"[{"timestamp_ms":1000,"severity":"INFO","service":"obs","trace_id":"t1","message":"log stays"}]"#.into()),
        1_020,
    );
    let fx = eng.tick(1_100);
    drain_view_events(&fx, &mut mirror);

    // Passive ticks & telemetry polls at t = 3_000 ms MUST count down BOTH clocks independently
    // WITHOUT resetting idle_timer!
    eng.on_fetch(&FetchKind::ObsMetrics, Ok("[]".into()), 2_000);
    let _ = eng.tick(3_000);
    let v3 = eng.store().view();
    let ab3 = v3
        .auth
        .leases
        .iter()
        .find(|l| l.role_id == "ab-responder")
        .expect("ab lease");
    let obs3 = v3
        .auth
        .leases
        .iter()
        .find(|l| l.role_id == "obs-investigator")
        .expect("obs lease");
    assert_eq!((ab3.seconds_remaining, ab3.idle_timer), (8, 3));
    assert_eq!((obs3.seconds_remaining, obs3.idle_timer), (28, 18));

    // Explicit RecordUserActivity at t = 3_100 resets idle_timer cleanly while preserving fixed hard_expires_at_ms!
    let act_fx = eng.handle(UiCommand::RecordUserActivity, 3_100);
    assert!(act_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::AuthActivity,
            url,
        } if url == "/api/auth/activity"
    )));
    let v_act = eng.store().view();
    let ab_act = v_act
        .auth
        .leases
        .iter()
        .find(|l| l.role_id == "ab-responder")
        .expect("ab lease after activity");
    let obs_act = v_act
        .auth
        .leases
        .iter()
        .find(|l| l.role_id == "obs-investigator")
        .expect("obs lease after activity");
    assert_eq!(ab_act.hard_expires_at_ms, 11_000);
    assert_eq!(ab_act.idle_expires_at_ms, 8_100);
    assert_eq!(ab_act.seconds_remaining, 8);
    assert_eq!(ab_act.idle_timer, 5);
    assert_eq!(obs_act.idle_timer, 20);

    // Advance past ab-responder's idle deadline (8_100 ms) WITHOUT activity:
    // ONLY ab-responder expires; baseline + ci-operator + obs-investigator survive!
    let exp_fx = eng.tick(8_100);
    assert!(
        exp_fx
            .iter()
            .any(|e| matches!(e, Effect::Post(DataEvent::Snapshot(_)))),
        "single-role 00:00 expiration must force a full DataEvent::Snapshot"
    );
    assert!(exp_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::AuthSession,
            ..
        }
    )));
    assert!(exp_fx.contains(&Effect::CloseStream(StreamId::Cd)));

    let v_after = eng.store().view();
    assert_eq!(v_after.auth.status, AuthStatus::Active);
    let active_role_ids: Vec<&str> = v_after
        .auth
        .active_roles
        .iter()
        .map(|r| r.role_id.as_str())
        .collect();
    assert_eq!(
        active_role_ids,
        vec!["viewer", "ci-operator", "obs-investigator"]
    );
    assert!(!v_after.auth.has_policy("ab:slots.read"));
    assert!(!v_after.auth.has_policy("cd:runs.read"));
    assert!(v_after.auth.has_policy("ci:nodes.read"));
    assert!(v_after.auth.has_policy("obs:logs.read"));

    // Exclusively AB/CD slices are scrubbed while surviving CI/OBS slices remain intact!
    assert!(v_after.leases.is_empty());
    assert!(v_after.cd_runs.is_empty());
    assert!(v_after.gate.is_none());
    assert!(!v_after.repos.is_empty());
    assert!(!v_after.nodes.is_empty());
    assert!(!v_after.observe.logs.is_empty());
}

#[test]
fn m2_eight_area_subview_polling_commands_and_sse_round_trip() {
    use mu_console_protocol::{
        AbDeploySubView, CdRunState, CdSubView, DialogModel, MaintenanceMode, ModelRunnerSubView,
        PlatformSubView, SubsystemId, SubsystemStatus,
    };

    let mut eng = Engine::new(305);
    eng.handle(UiCommand::Configure(WorkerConfig::default()), 0);
    resolve_operator_session(&mut eng, 5);
    eng.on_stream_open(StreamId::Obs, 6);

    // 1. Subsystems SSE live update -> updates subsystem_health + AreaBadges::dashboard / platform.
    let sse_sub = concat!(
        "event: subsystem_status_changed\n",
        "data: {\"subsystem\":\"cd\",\"effective_status\":\"in-maintenance\",\"probe_status\":\"live\",\"mode\":\"manual\",\"summary\":\"Window\",\"updated_at_ms\":10}\n\n"
    );
    eng.on_stream_chunk(StreamId::Obs, sse_sub.as_bytes(), 10);
    assert_eq!(
        eng.store().view().subsystem_health.cd.status,
        SubsystemStatus::InMaintenance
    );
    assert_eq!(eng.store().badges().platform, 1);

    // 2. Maintenance override command + refresh.
    let maint_fx = eng.handle(
        UiCommand::SetSubsystemMaintenance {
            subsystem: SubsystemId::Repository,
            mode: MaintenanceMode::Manual(SubsystemStatus::Offline),
            reason: Some("CAS maintenance".into()),
            auto_clear_secs: Some(600),
        },
        20,
    );
    assert!(maint_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::SetSubsystemMaintenance {
                subsystem: SubsystemId::Repository,
                ..
            },
            url,
        } if url == "/api/obs/v1/status/subsystems/repository/maintenance"
    )));

    // 3. Area::Cd Runs polling -> badge increments on failed run.
    let repo = RepoId::new("LMA1980", "mu-console");
    eng.handle(
        UiCommand::SelectRepo {
            repo: repo.clone(),
            submodule: None,
        },
        30,
    );
    let cd_fx = eng.handle(UiCommand::SelectSubView(SubView::Cd(CdSubView::Runs)), 35);
    assert!(cd_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::CdRuns { .. },
            ..
        }
    )));
    eng.on_fetch(
        &FetchKind::CdRuns {
            repo,
            ecosystem: None,
            limit: 25,
        },
        Ok(r#"[{"run_id":"cd-1","ecosystem":"cargo","repo":{"owner":"LMA1980","repo":"mu-console"},"state":"failed","started_epoch_ms":35}]"#.into()),
        40,
    );
    assert_eq!(eng.store().view().cd_runs.len(), 1);
    assert_eq!(eng.store().view().cd_runs[0].state, CdRunState::Failed);
    assert_eq!(eng.store().badges().cd, 1);

    // 4. Area::AbDeploy emergency symmetric rollback command & gate update.
    eng.handle(
        UiCommand::SelectSubView(SubView::AbDeploy(AbDeploySubView::IntegrationGate)),
        45,
    );
    eng.on_fetch(&FetchKind::Gate("dep-42".into()), Ok(GATE.into()), 46);
    let rb_fx = eng.handle(
        UiCommand::TriggerAbRollback {
            deployment_id: "dep-42".into(),
            note: Some("regression".into()),
        },
        50,
    );
    assert!(rb_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::AbRollback { deployment_id, .. },
            url,
        } if deployment_id == "dep-42" && url == "/api/cd/deployments/dep-42/rollback"
    )));
    let rb_follow = eng.on_fetch(
        &FetchKind::AbRollback {
            deployment_id: "dep-42".into(),
            note: Some("regression".into()),
        },
        Ok(
            r#"{"deployment_id":"dep-42","restored_slot":"a","tainted_digest":"sha256:bad"}"#
                .into(),
        ),
        55,
    );
    assert!(rb_follow.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::Deployments(_),
            ..
        }
    )));

    // 5. Area::ModelRunner subviews -> populates ModelRunnerView & degraded WireGuard badge.
    let mr_q_fx = eng.handle(
        UiCommand::SelectSubView(SubView::ModelRunner(ModelRunnerSubView::RuntimeQueue)),
        60,
    );
    assert!(mr_q_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::MrStatus,
            url,
        } if url == "/api/mr/v1/status"
    )));
    let mr_c_fx = eng.handle(
        UiCommand::SelectSubView(SubView::ModelRunner(ModelRunnerSubView::ConnectionVpn)),
        61,
    );
    assert!(mr_c_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::MrConnection,
            url,
        } if url == "/api/mr/v1/connection"
    )));
    eng.on_fetch(
        &FetchKind::MrConnection,
        Ok(r#"{"openai_base_url":"https://192.0.2.1/v1","interface_state":"down"}"#.into()),
        65,
    );
    assert_eq!(eng.store().badges().model_runner, 1);

    // 6. Area::Platform -> UsersAndInvites, CreateInvite opens InviteCreatedOnce dialog cleanly.
    let p_fx = eng.handle(
        UiCommand::SelectSubView(SubView::Platform(PlatformSubView::UsersAndInvites)),
        70,
    );
    assert!(p_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::AuthUsers,
            ..
        }
    )));
    assert!(p_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::AuthInvites,
            ..
        }
    )));
    let rf_fx = eng.handle(
        UiCommand::SelectSubView(SubView::Platform(PlatformSubView::RolesAndFolios)),
        72,
    );
    assert!(rf_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::AuthRoles,
            ..
        }
    )));
    assert!(rf_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::AuthFolios,
            ..
        }
    )));
    assert!(rf_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::AuthRoleFolioIndex,
            ..
        }
    )));

    let inv_fx = eng.handle(
        UiCommand::CreateInvite {
            note: Some("oncall".into()),
            ttl_secs: Some(3600),
        },
        75,
    );
    assert!(inv_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::AuthCreateInvite { .. },
            url,
        } if url == "/api/auth/invites"
    )));
    let created_fx = eng.on_fetch(
        &FetchKind::AuthCreateInvite {
            note: Some("oncall".into()),
            ttl_secs: Some(3600),
        },
        Ok(r#"{
          "invite_id": "inv-01",
          "token": "secret-token",
          "url": "https://console.example.org/?invite=secret-token",
          "granted_role": "viewer",
          "expires_at_ms": 3600075,
          "note": "oncall"
        }"#
        .into()),
        80,
    );
    assert!(created_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::AuthInvites,
            ..
        }
    )));
    assert!(matches!(
        eng.store().view().active_dialog,
        Some(DialogModel::InviteCreatedOnce(ref dlg)) if dlg.invite_id == "inv-01" && dlg.granted_role == "viewer"
    ));
    eng.handle(UiCommand::CloseDialog, 85);
    assert!(eng.store().view().active_dialog.is_none());
}

#[test]
fn cold_boot_elevated_non_admin_expiry_preserves_baseline_and_blocks_maintenance_activity_leak() {
    use mu_console_protocol::dto::AuthSessionDto;
    use mu_console_protocol::{
        PlatformSubView, RoleActivationDto, RoleLeaseView, RoleSpecDto, StepUpRequirement,
    };

    let mut eng = Engine::new(306);
    eng.handle(UiCommand::Configure(WorkerConfig::default()), 0);

    // Non-admin user boots cold ALREADY holding an active Timed role (`ci-operator`) and an
    // Elective role (`cd-reader`), without `platform:folios.read` (no folios catalog fetched).
    let cold_elevated = AuthSessionDto {
        authenticated: true,
        github_login: Some("bob".into()),
        invite_bound: true,
        passkey_count: 1,
        passkey_enrollment_required: false,
        baseline_role: Some("viewer".into()),
        bound_roles: vec!["viewer".into(), "cd-reader".into(), "ci-operator".into()],
        active_roles: vec![
            RoleSpecDto {
                id: "viewer".into(),
                display_name: Some("Viewer".into()),
                description: "Baseline".into(),
                activation: RoleActivationDto::pinned_baseline(),
                step_up: StepUpRequirement::None,
            },
            RoleSpecDto {
                id: "cd-reader".into(),
                display_name: Some("CD Reader".into()),
                description: "Elective CD reads".into(),
                activation: RoleActivationDto::elective(),
                step_up: StepUpRequirement::None,
            },
            RoleSpecDto {
                id: "ci-operator".into(),
                display_name: Some("CI Operator".into()),
                description: "Timed CI ops".into(),
                activation: RoleActivationDto::timed(4, 4),
                step_up: StepUpRequirement::Passkey,
            },
        ],
        leases: vec![RoleLeaseView {
            role_id: "ci-operator".into(),
            display_name: Some("CI Operator".into()),
            activated_at_ms: 10,
            last_activity_at_ms: 10,
            hard_ttl_secs: 4,
            idle_ttl_secs: 4,
            seconds_remaining: 4,
            hard_expires_at_ms: 4_010,
            idle_timer: 4,
            idle_expires_at_ms: 4_010,
            ..RoleLeaseView::default()
        }],
        active_folios: vec![
            "folio:system:dashboard".into(),
            "folio:ci:anon-queue".into(),
            "folio:cd:read".into(),
            "folio:ci:operate".into(),
        ],
        active_policies: vec![
            "system:status.read".into(),
            "system:dashboard.read".into(),
            "ci:queue.read".into(),
            "ci:repos.public.read".into(),
            "cd:runs.read".into(),
            "cd:steps.read".into(),
            "ci:jobs.read".into(),
            "ci:jobs.restart".into(),
        ],
        ..AuthSessionDto::default()
    };

    eng.on_fetch(
        &FetchKind::AuthSession,
        Ok(serde_json::to_string(&cold_elevated).unwrap()),
        10,
    );
    eng.on_fetch(&FetchKind::Repos, Ok(REPOS.into()), 15);
    eng.on_fetch(
        &FetchKind::CdRuns {
            repo: RepoId::new(OWNER, SUPERPROJECT),
            ecosystem: None,
            limit: 25,
        },
        Ok(r#"[{"run_id":"cd-1","ecosystem":"cargo","repo":{"owner":"lma1980","repo":"lero"},"ref_name":"main","commit_sha":"deadbeef","state":"succeeded","started_epoch_ms":10,"steps":[]}]"#.into()),
        16,
    );

    // Navigating to Platform::Maintenance must NOT emit POST /api/auth/activity nor extend idle_timer.
    let maint_fx = eng.handle(
        UiCommand::SelectSubView(SubView::Platform(PlatformSubView::Maintenance)),
        1_010,
    );
    assert!(maint_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::ObsSubsystemStatus,
            ..
        }
    )));
    assert!(!maint_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::AuthActivity,
            ..
        }
    )));
    eng.tick(1_500);
    assert_eq!(eng.store().view().auth.leases[0].idle_timer, 3);

    // At 4_010 ms, `ci-operator` expires locally BEFORE `/api/auth/session` resolves (`folios` absent).
    let exp_fx = eng.tick(4_010);
    assert!(exp_fx
        .iter()
        .any(|e| matches!(e, Effect::Post(DataEvent::Snapshot(_)))));
    assert!(exp_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::AuthSession,
            ..
        }
    )));

    let v_after = eng.store().view();
    assert!(!v_after.auth.has_policy("ci:jobs.restart"));
    // Baseline + elective read policies remain preserved rather than wiping active_policies to [].
    assert!(v_after.auth.has_policy("system:status.read"));
    assert!(v_after.auth.has_policy("system:dashboard.read"));
    assert!(v_after.auth.has_policy("ci:queue.read"));
    assert!(v_after.auth.has_policy("ci:repos.public.read"));
    assert!(v_after.auth.has_policy("cd:runs.read"));
    assert!(v_after.auth.has_policy("cd:steps.read"));
    assert!(!v_after.repos.is_empty());
    assert!(!v_after.cd_runs.is_empty());

    // Mutating command requiring expired `ci:jobs.restart` is fail-closed denied (403).
    let restart_fx = eng.handle(UiCommand::RestartJob { job_id: 1 }, 4_020);
    assert!(restart_fx.iter().any(|e| matches!(
        e,
        Effect::Post(DataEvent::Error(UiError::Http { status: 403, .. }))
    )));
}

#[test]
fn timed_elevation_refreshes_active_subview_and_elective_toggle_prunes_non_timed() {
    use mu_console_protocol::dto::AuthSessionDto;
    use mu_console_protocol::{
        AbDeploySubView, RoleActivationDto, RoleLeaseView, RoleSpecDto, StepUpRequirement,
    };

    let mut eng = Engine::new(307);
    eng.handle(UiCommand::Configure(WorkerConfig::default()), 0);

    let baseline = RoleSpecDto {
        id: "viewer".into(),
        display_name: Some("Viewer".into()),
        description: "Baseline".into(),
        activation: RoleActivationDto::pinned_baseline(),
        step_up: StepUpRequirement::None,
    };
    let cd_reader = RoleSpecDto {
        id: "cd-reader".into(),
        display_name: Some("CD Reader".into()),
        description: "Elective CD".into(),
        activation: RoleActivationDto::elective(),
        step_up: StepUpRequirement::None,
    };
    let ab_responder = RoleSpecDto {
        id: "ab-responder".into(),
        display_name: Some("AB Responder".into()),
        description: "Timed AB".into(),
        activation: RoleActivationDto::timed(5, 5),
        step_up: StepUpRequirement::Passkey,
    };

    // 1. Start active with baseline + elective `cd-reader` while viewing AbDeploy::DeploymentsSlots.
    let s1 = AuthSessionDto {
        authenticated: true,
        github_login: Some("carol".into()),
        invite_bound: true,
        passkey_count: 1,
        baseline_role: Some("viewer".into()),
        bound_roles: vec!["viewer".into(), "cd-reader".into(), "ab-responder".into()],
        active_roles: vec![baseline.clone(), cd_reader.clone()],
        active_policies: vec![
            "system:status.read".into(),
            "ci:queue.read".into(),
            "ci:repos.public.read".into(),
            "cd:runs.read".into(),
        ],
        ..AuthSessionDto::default()
    };
    eng.on_fetch(
        &FetchKind::AuthSession,
        Ok(serde_json::to_string(&s1).unwrap()),
        10,
    );
    eng.on_fetch(&FetchKind::Repos, Ok(REPOS.into()), 15);
    eng.handle(
        UiCommand::SelectSubView(SubView::AbDeploy(AbDeploySubView::DeploymentsSlots)),
        20,
    );

    // 2. Elevate Timed `ab-responder` -> must immediately refresh active AbDeploy subview + selection!
    let s2 = AuthSessionDto {
        active_roles: vec![baseline.clone(), cd_reader, ab_responder.clone()],
        leases: vec![RoleLeaseView {
            role_id: "ab-responder".into(),
            display_name: Some("AB Responder".into()),
            activated_at_ms: 30,
            last_activity_at_ms: 30,
            hard_ttl_secs: 5,
            idle_ttl_secs: 5,
            seconds_remaining: 5,
            hard_expires_at_ms: 5_030,
            idle_timer: 5,
            idle_expires_at_ms: 5_030,
            ..RoleLeaseView::default()
        }],
        active_policies: vec![
            "system:status.read".into(),
            "ci:queue.read".into(),
            "ci:repos.public.read".into(),
            "cd:runs.read".into(),
            "ab:slots.read".into(),
            "ab:gate.logs.read".into(),
            "ab:rollback".into(),
        ],
        ..s1.clone()
    };
    let elev_fx = eng.on_fetch(
        &FetchKind::AuthElevateFinish {
            role_id: "ab-responder".into(),
            assertion_json: "{}".into(),
        },
        Ok(serde_json::to_string(&s2).unwrap()),
        30,
    );
    assert!(elev_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::Deployments(_),
            ..
        }
    )));
    // Wait until a Canary read policy is granted before RegCanaries fires.
    assert!(!elev_fx.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::RegCanaries,
            ..
        }
    )));

    // 3. Disable Elective `cd-reader` while Timed `ab-responder` remains active (folios unavailable).
    let s3 = AuthSessionDto {
        active_roles: vec![baseline, ab_responder],
        active_policies: vec![
            "system:status.read".into(),
            "ci:queue.read".into(),
            "ci:repos.public.read".into(),
            "ab:slots.read".into(),
            "ab:gate.logs.read".into(),
            "ab:rollback".into(),
        ],
        ..s2
    };
    eng.on_fetch(
        &FetchKind::AuthDisableRole("cd-reader".into()),
        Ok(serde_json::to_string(&s3).unwrap()),
        40,
    );

    // 4. When `ab-responder` later reaches 00:00 (no folios table), `cd:runs.read` was pruned from
    // non_timed_policies (`!is_empty` fix) while baseline policies remain active.
    eng.tick(5_030);
    let v_final = eng.store().view();
    assert!(!v_final.auth.has_policy("cd:runs.read"));
    assert!(!v_final.auth.has_policy("ab:rollback"));
    assert!(!v_final.auth.has_policy("ab:slots.read"));
    assert!(v_final.auth.has_policy("system:status.read"));
    assert!(v_final.auth.has_policy("ci:queue.read"));
    assert!(v_final.auth.has_policy("ci:repos.public.read"));
}

#[test]
fn auth_session_probe_http_failure_surfaces_error_and_stays_fail_closed() {
    let mut eng = Engine::new(308);
    let init_fx = eng.handle(UiCommand::Configure(WorkerConfig::default()), 0);
    assert!(init_fx.contains(&Effect::Fetch {
        kind: FetchKind::AuthSession,
        url: "/api/auth/session".into(),
    }));

    for (ts, status, raw_msg, expected_msg) in [
        (50_u64, 404_u32, "", "GET /api/auth/session"),
        (
            100_u64,
            503_u32,
            "Service Unavailable",
            "GET /api/auth/session: Service Unavailable",
        ),
        (
            150_u64,
            0_u32,
            "network timeout",
            "GET /api/auth/session: network timeout",
        ),
    ] {
        let err_fx = eng.on_fetch(
            &FetchKind::AuthSession,
            Err(HttpError {
                status,
                message: raw_msg.into(),
            }),
            ts,
        );
        assert!(
            err_fx.iter().any(|e| matches!(
                e,
                Effect::Post(DataEvent::Error(UiError::Http { status: s, message }))
                    if *s == status && message == expected_msg
            )),
            "expected DataEvent::Error(UiError::Http {{ status: {status}, message: {expected_msg:?} }}), got {err_fx:?}"
        );
        assert_eq!(eng.store().auth().status, AuthStatus::Unresolved);
        assert!(!eng.store().can_emit_operational_data());
        assert!(!err_fx.contains(&Effect::LoadOffline));
        assert!(!err_fx
            .iter()
            .any(|e| matches!(e, Effect::OpenStream { .. } | Effect::Fetch { .. })));
    }

    let retry_fx = eng.handle(UiCommand::Retry, 200);
    assert!(retry_fx.contains(&Effect::Fetch {
        kind: FetchKind::AuthSession,
        url: "/api/auth/session".into(),
    }));
    assert!(!retry_fx.iter().any(
        |e| matches!(e, Effect::OpenStream { .. } | Effect::LoadOffline)
            || matches!(e, Effect::Fetch { kind, .. } if !matches!(kind, FetchKind::AuthSession))
    ));

    let ok_fx = resolve_operator_session(&mut eng, 250);
    assert_eq!(eng.store().auth().status, AuthStatus::Active);
    assert!(ok_fx.contains(&Effect::LoadOffline));
}

#[test]
fn live_fetch_and_sse_short_lived_eof_backs_off_until_stable() {
    let mut eng = Engine::new(77);
    eng.handle(UiCommand::Configure(WorkerConfig::default()), 0);
    resolve_operator_session(&mut eng, 5);
    // Keep has_live_data() true so repeated closes report ConnState::Reconnecting.
    eng.on_fetch(&FetchKind::Repos, Ok(REPOS.into()), 6);

    let mut now_ms = 10;
    let mut prev_delay_ms = 0;

    for expected_attempt in 1..=4 {
        let open_fx = eng.on_stream_open(StreamId::Obs, now_ms);
        assert!(open_fx.contains(&Effect::Post(DataEvent::Connection(ConnState::Live))));

        // Immediate EOF after 10ms must preserve exponential backoff across reconnects.
        let close_ms = now_ms + 10;
        let close_fx = eng.on_stream_closed(StreamId::Obs, None, close_ms);
        let (attempt, retry_in_ms) = close_fx
            .iter()
            .find_map(|e| match e {
                Effect::Post(DataEvent::Connection(ConnState::Reconnecting {
                    attempt,
                    retry_in_ms,
                })) => Some((*attempt, *retry_in_ms)),
                _ => None,
            })
            .expect("ConnState::Reconnecting emitted");

        assert_eq!(attempt, expected_attempt);
        assert!(
            retry_in_ms > prev_delay_ms,
            "attempt {attempt} delay {retry_in_ms}ms should exceed prior {prev_delay_ms}ms"
        );
        if expected_attempt == 4 {
            assert!(
                retry_in_ms >= 3_200,
                "expected exponential growth by attempt 4, got {retry_in_ms}ms"
            );
        }
        prev_delay_ms = retry_in_ms;

        // Reconnect remains suppressed 1ms before due time and fires at `reconnect_at`.
        let before_due = close_ms + u64::from(retry_in_ms) - 1;
        let before_fx = eng.tick(before_due);
        assert!(!before_fx.iter().any(|e| matches!(
            e,
            Effect::OpenStream {
                stream: StreamId::Obs,
                ..
            }
        )));

        now_ms = close_ms + u64::from(retry_in_ms);
        let due_fx = eng.tick(now_ms);
        assert!(due_fx.iter().any(|e| matches!(
            e,
            Effect::OpenStream {
                stream: StreamId::Obs,
                ..
            }
        )));
    }

    // Holding open >= MIN_STABLE_STREAM_MS resets backoff on the subsequent close.
    eng.on_stream_open(StreamId::Obs, now_ms);
    let stable_close_ms = now_ms + MIN_STABLE_STREAM_MS + 100;
    eng.tick(now_ms + MIN_STABLE_STREAM_MS);
    let stable_close_fx = eng.on_stream_closed(StreamId::Obs, None, stable_close_ms);
    let (reset_attempt, reset_delay_ms) = stable_close_fx
        .iter()
        .find_map(|e| match e {
            Effect::Post(DataEvent::Connection(ConnState::Reconnecting {
                attempt,
                retry_in_ms,
            })) => Some((*attempt, *retry_in_ms)),
            _ => None,
        })
        .expect("ConnState::Reconnecting emitted after stable close");
    assert_eq!(reset_attempt, 1);
    assert!(
        (400..=600).contains(&reset_delay_ms),
        "expected reset base backoff in 400..=600ms, got {reset_delay_ms}ms"
    );
}

#[test]
fn local_skin_and_font_preferences_survive_auth_session_without_preferences() {
    use mu_console_protocol::ConsoleSkin;

    let mut eng = Engine::new(410);
    let _ = eng.handle(UiCommand::Configure(WorkerConfig::default()), 0);

    // Local preferences set before AuthSession resolves emit no effects and are preserved.
    assert!(eng
        .handle(UiCommand::SetCrtFont(CrtFont::OpenDyslexic), 10)
        .is_empty());
    assert!(eng
        .handle(UiCommand::SetSkin(ConsoleSkin::Wireframe), 15)
        .is_empty());

    // Resolve AuthSession without server `preferences` field.
    let _ = resolve_operator_session(&mut eng, 20);
    let tick_fx = eng.tick(20 + MIN_INTERVAL_MS);
    let view = tick_fx
        .iter()
        .find_map(|e| match e {
            Effect::Post(DataEvent::Snapshot(v)) => Some(v.clone()),
            Effect::Post(DataEvent::Patch(ops)) => {
                let mut v = ViewModel::default();
                apply_all(&mut v, ops);
                Some(v)
            }
            _ => None,
        })
        .unwrap_or_else(|| eng.store().view());
    let profile = view
        .user_profile
        .expect("authenticated session populates user_profile");
    assert_eq!(profile.preferences.font, CrtFont::OpenDyslexic);
    assert_eq!(profile.preferences.skin, ConsoleSkin::Wireframe);
}

#[test]
fn update_user_profile_optimistically_updates_store_and_treats_404_put_as_optional() {
    use mu_console_protocol::ConsoleSkin;

    let mut eng = Engine::new(411);
    let _ = eng.handle(UiCommand::Configure(WorkerConfig::default()), 0);
    let _ = resolve_operator_session(&mut eng, 10);

    let cmd = UiCommand::UpdateUserProfile {
        display_name: Some("Ops Lead".into()),
        preferred_skin: Some(ConsoleSkin::Wireframe),
        preferred_font: Some(CrtFont::OpenDyslexic),
    };
    let fx = eng.handle(cmd, 20);
    assert!(fx.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::AuthProfilePut { .. },
            ..
        }
    )));

    let tick_fx = eng.tick(20 + MIN_INTERVAL_MS);
    assert!(!tick_fx.is_empty());
    let profile = eng
        .store()
        .view()
        .user_profile
        .expect("optimistic user_profile updated");
    assert_eq!(profile.display_name.as_deref(), Some("Ops Lead"));
    assert_eq!(profile.preferences.skin, ConsoleSkin::Wireframe);
    assert_eq!(profile.preferences.font, CrtFont::OpenDyslexic);

    // Optional PUT /api/auth/profile returning 404 preserves local preferences without UiError.
    let kind = FetchKind::AuthProfilePut {
        display_name: Some("Ops Lead".into()),
        preferred_skin: Some(ConsoleSkin::Wireframe),
        preferred_font: Some(CrtFont::OpenDyslexic),
    };
    let fx_404 = eng.on_fetch(
        &kind,
        Err(HttpError {
            status: 404,
            message: "Not Found".into(),
        }),
        20 + MIN_INTERVAL_MS + 10,
    );
    assert!(
        !fx_404
            .iter()
            .any(|e| matches!(e, Effect::Post(DataEvent::Error(_)))),
        "404 on optional /api/auth/profile PUT must not emit DataEvent::Error"
    );
    let retained = eng.store().view().user_profile.expect("retained profile");
    assert_eq!(retained.preferences.skin, ConsoleSkin::Wireframe);
    assert_eq!(retained.preferences.font, CrtFont::OpenDyslexic);

    // 403 still surfaces UiError::Http.
    let fx_403 = eng.on_fetch(
        &kind,
        Err(HttpError {
            status: 403,
            message: "Forbidden".into(),
        }),
        20 + MIN_INTERVAL_MS + 20,
    );
    assert!(fx_403.iter().any(|e| matches!(
        e,
        Effect::Post(DataEvent::Error(UiError::Http { status: 403, .. }))
    )));
}

#[test]
fn super_operator_renewal_envelope_tick_transition_and_dialog_sync() {
    use crate::api::parse_auth_session;
    use mu_console_protocol::dto::AuthSessionDto;
    use mu_console_protocol::{
        DialogModel, RoleActivationDto, RoleLeaseView, RoleSpecDto, SessionRolesDialogModel,
        StepUpRequirement,
    };

    let mut eng = Engine::new(308);
    eng.handle(UiCommand::Configure(WorkerConfig::default()), 0);

    let super_spec = RoleSpecDto {
        id: "super-operator".into(),
        display_name: Some("Super Operator".into()),
        description: "All-access Passkey role".into(),
        activation: RoleActivationDto::super_operator(),
        step_up: StepUpRequirement::Passkey,
    };
    let mut s1 = AuthSessionDto {
        authenticated: true,
        github_login: Some("LMA1980".into()),
        invite_bound: true,
        passkey_count: 1,
        baseline_role: Some("operator".into()),
        bound_roles: vec!["operator".into(), "super-operator".into()],
        bound_role_specs: vec![super_spec.clone()],
        active_roles: vec![super_spec.clone()],
        leases: vec![RoleLeaseView {
            role_id: "super-operator".into(),
            display_name: Some("Super Operator".into()),
            activated_at_ms: 0,
            last_activity_at_ms: 775_000,
            hard_expires_at_ms: 900_000,
            idle_expires_at_ms: 895_000,
            hard_ttl_secs: 900,
            idle_ttl_secs: 120,
            renew_window_secs: 120,
            renew_extend_secs: 900,
            max_renewals: 1,
            renewals_used: 0,
            seconds_remaining: 125,
            idle_timer: 120,
            can_renew: false,
        }],
        active_policies: vec!["system:status.read".into(), "platform:roles.write".into()],
        ..AuthSessionDto::default()
    };
    eng.on_fetch(
        &FetchKind::AuthSession,
        Ok(serde_json::to_string(&s1).unwrap()),
        775_000,
    );

    // Open empty SessionRoles dialog -> Store populates bound_role_specs automatically.
    eng.handle(
        UiCommand::OpenDialog(DialogModel::SessionRoles(SessionRolesDialogModel {
            github_login: "LMA1980".into(),
            roles: Vec::new(),
            lock_all_enabled: true,
        })),
        775_000,
    );

    // At 779_000ms (121s remaining), can_renew stays false.
    let _ = eng.tick(779_000);
    assert!(!eng.store().view().auth.leases[0].can_renew);

    // At 780_000ms (120s remaining), can_renew transitions to true and updates both ViewModel and dialog.
    let fx_win = eng.tick(780_000);
    assert!(fx_win
        .iter()
        .any(|e| matches!(e, Effect::Post(DataEvent::Patch(_)))));
    assert!(eng.store().view().auth.leases[0].can_renew);
    if let Some(DialogModel::SessionRoles(sr)) = &eng.store().view().active_dialog {
        assert!(sr.roles.iter().any(
            |r| r.role_id == "super-operator" && r.lease.as_ref().is_some_and(|l| l.can_renew)
        ));
    } else {
        panic!("expected SessionRoles dialog to remain open");
    }

    // Dispatch RenewRoleWithPasskey -> emits FetchKind::AuthRenewRole for /api/auth/roles/super-operator/renew.
    let fx_cmd = eng.handle(
        UiCommand::RenewRoleWithPasskey {
            role_id: "super-operator".into(),
            assertion_json: r#"{"challenge_id":"c1","credential":{}}"#.into(),
        },
        780_000,
    );
    assert!(fx_cmd.iter().any(|e| matches!(
        e,
        Effect::Fetch {
            kind: FetchKind::AuthRenewRole { role_id, .. },
            url,
        } if role_id == "super-operator" && url.ends_with("/api/auth/roles/super-operator/renew")
    )));

    // parse_auth_session unwraps controller `{"elevated": true, "renewed": true, "session": ...}` envelope.
    s1.leases[0].hard_expires_at_ms = 1_800_000;
    s1.leases[0].idle_expires_at_ms = 900_000;
    s1.leases[0].renewals_used = 1;
    s1.leases[0].can_renew = false;
    s1.leases[0].seconds_remaining = 1_020;
    let envelope = serde_json::json!({
        "elevated": true,
        "renewed": true,
        "role_id": "super-operator",
        "session": s1,
    })
    .to_string();
    let parsed = parse_auth_session(envelope.as_bytes()).expect("unwrap session envelope");
    assert_eq!(parsed.leases[0].renewals_used, 1);

    eng.on_fetch(
        &FetchKind::AuthRenewRole {
            role_id: "super-operator".into(),
            assertion_json: "{}".into(),
        },
        Ok(envelope),
        780_000,
    );
    assert_eq!(
        eng.store().view().auth.leases[0].hard_expires_at_ms,
        1_800_000
    );
    assert_eq!(eng.store().view().auth.leases[0].renewals_used, 1);
    assert!(!eng.store().view().auth.leases[0].can_renew);
}
