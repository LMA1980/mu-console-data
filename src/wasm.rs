// SPDX-License-Identifier: AGPL-3.0-only
//! Thin browser glue for the dedicated worker (wasm32 only).
//!
//! Forwards worker messages, fetch results, SSE chunks, the 100 ms timer
//! and CacheStorage reads to the [`Engine`] and executes its [`Effect`]s.
//! No decisions are made here.

use std::cell::{Cell, RefCell};

use js_sys::{Array, ArrayBuffer, Date, Reflect, Uint8Array};
use mu_console_protocol::dto::AbRollbackRequestDto;
use mu_console_protocol::{DataEvent, MaintenanceMode};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::{spawn_local, JsFuture};
use web_sys::{
    AbortController, Cache, DedicatedWorkerGlobalScope, MessageEvent, ReadableStreamDefaultReader,
    Request, RequestCache, RequestCredentials, RequestInit, Response,
};

use crate::api::{FetchKind, StreamId};
use crate::coalesce::MIN_INTERVAL_MS;
use crate::engine::{Effect, Engine, HttpError};
use crate::offline::{CACHE_KEY, CACHE_NAME};

thread_local! {
    static ENGINE: RefCell<Option<Engine>> = const { RefCell::new(None) };
    static STREAMS: RefCell<[Option<(u32, AbortController)>; 3]> = const { RefCell::new([None, None, None]) };
    static GENERATION: Cell<u32> = const { Cell::new(0) };
}

fn scope() -> DedicatedWorkerGlobalScope {
    js_sys::global().unchecked_into()
}

fn now_ms() -> u64 {
    // Date.now() is a non-negative integral f64 well below 2^53.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let ms = Date::now() as u64;
    ms
}

fn with_engine<R: Default>(f: impl FnOnce(&mut Engine) -> R) -> R {
    ENGINE.with(|e| e.borrow_mut().as_mut().map(f).unwrap_or_default())
}

fn js_msg(v: &JsValue) -> String {
    v.as_string()
        .or_else(|| {
            Reflect::get(v, &JsValue::from_str("message"))
                .ok()
                .and_then(|m| m.as_string())
        })
        .unwrap_or_else(|| format!("{v:?}"))
}

/// Worker entry point: install `onmessage` and the coalescing timer.
pub fn start() {
    ENGINE.with(|e| *e.borrow_mut() = Some(Engine::new(now_ms())));
    let onmessage = Closure::<dyn FnMut(MessageEvent)>::new(|ev: MessageEvent| {
        let data = ev.data();
        let bytes = if let Some(buf) = data.dyn_ref::<ArrayBuffer>() {
            Uint8Array::new(buf).to_vec()
        } else if let Some(arr) = data.dyn_ref::<Uint8Array>() {
            arr.to_vec()
        } else {
            Vec::new()
        };
        let fx = with_engine(|e| e.handle_frame(&bytes, now_ms()));
        run(fx);
    });
    scope().set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
    onmessage.forget();

    let tick = Closure::<dyn FnMut()>::new(|| {
        let fx = with_engine(|e| e.tick(now_ms()));
        run(fx);
    });
    let period = i32::try_from(MIN_INTERVAL_MS).unwrap_or(100);
    let _ = scope().set_interval_with_callback_and_timeout_and_arguments_0(
        tick.as_ref().unchecked_ref(),
        period,
    );
    tick.forget();
}

fn run(effects: Vec<Effect>) {
    for fx in effects {
        match fx {
            Effect::Post(ev) => post(&ev),
            Effect::Fetch { kind, url } => spawn_local(fetch_json(kind, url)),
            Effect::OpenStream {
                stream,
                url,
                last_event_id,
            } => open_stream(stream, url, last_event_id),
            Effect::CloseStream(stream) => close_stream(stream),
            Effect::SaveOffline(bytes) => spawn_local(async move {
                let _ = save_offline(&bytes).await;
            }),
            Effect::LoadOffline => spawn_local(async {
                let bytes = load_offline().await.ok().flatten();
                let fx = with_engine(|e| e.on_offline_loaded(bytes.as_deref(), now_ms()));
                run(fx);
            }),
        }
    }
}

/// Post a versioned postcard frame as a transferred `ArrayBuffer`.
fn post(ev: &DataEvent) {
    let Ok(bytes) = Engine::encode_event(ev) else {
        return;
    };
    let buf = Uint8Array::from(bytes.as_slice()).buffer();
    let _ = scope().post_message_with_transfer(&buf, &Array::of1(&buf));
}

fn request(url: &str, accept: &str, signal: Option<&AbortController>) -> Result<Request, JsValue> {
    let init = RequestInit::new();
    init.set_method("GET");
    init.set_credentials(RequestCredentials::SameOrigin);
    init.set_cache(RequestCache::NoStore);
    if let Some(c) = signal {
        init.set_signal(Some(&c.signal()));
    }
    let req = Request::new_with_str_and_init(url, &init)?;
    req.headers().set("Accept", accept)?;
    Ok(req)
}

fn json_request(method: &str, url: &str, body_json: Option<&str>) -> Result<Request, JsValue> {
    let init = RequestInit::new();
    init.set_method(method);
    init.set_credentials(RequestCredentials::SameOrigin);
    init.set_cache(RequestCache::NoStore);
    if let Some(body) = body_json {
        init.set_body(&JsValue::from_str(body));
    }
    let req = Request::new_with_str_and_init(url, &init)?;
    req.headers().set("Accept", "application/json")?;
    if body_json.is_some() {
        req.headers().set("Content-Type", "application/json")?;
    }
    Ok(req)
}

fn merge_json_field(
    raw: &str,
    key: &str,
    val: Option<serde_json::Value>,
    fallback_key: &str,
) -> String {
    if let Ok(serde_json::Value::Object(mut obj)) = serde_json::from_str::<serde_json::Value>(raw) {
        if let Some(v) = val {
            obj.entry(key).or_insert(v);
        }
        return serde_json::Value::Object(obj).to_string();
    }
    let mut obj = serde_json::Map::new();
    if let Some(v) = val {
        obj.insert(key.to_owned(), v);
    }
    obj.insert(
        fallback_key.to_owned(),
        serde_json::Value::String(raw.to_owned()),
    );
    serde_json::Value::Object(obj).to_string()
}

fn serialize_json_or_err<T: serde::Serialize>(val: &T) -> Result<String, JsValue> {
    serde_json::to_string(val).map_err(|e| JsValue::from_str(&e.to_string()))
}

fn build_fetch_request(kind: &FetchKind, url: &str) -> Result<Request, JsValue> {
    match kind {
        FetchKind::AuthRedeem(token) => {
            let payload = serde_json::json!({ "token": token, "invite_token": token }).to_string();
            json_request("POST", url, Some(&payload))
        }
        FetchKind::RestartJob(job_id) | FetchKind::ResumeJob(job_id) => {
            let payload = serde_json::json!({ "job_id": job_id }).to_string();
            json_request("POST", url, Some(&payload))
        }
        FetchKind::AbRollback { note, .. } => {
            let payload = serialize_json_or_err(&AbRollbackRequestDto { note: note.clone() })?;
            json_request("POST", url, Some(&payload))
        }
        FetchKind::SetSubsystemMaintenance {
            mode,
            reason,
            auto_clear_secs,
            ..
        } => {
            let mut obj = serde_json::Map::new();
            let (mode_str, state_str, clear) = match mode {
                MaintenanceMode::Auto => ("auto", "live", true),
                MaintenanceMode::Manual(status) => ("manual", status.as_str(), false),
            };
            obj.insert("mode".into(), serde_json::Value::String(mode_str.into()));
            obj.insert("state".into(), serde_json::Value::String(state_str.into()));
            obj.insert("clear".into(), serde_json::Value::Bool(clear));
            if let Some(r) = reason {
                obj.insert("summary".into(), serde_json::Value::String(r.clone()));
                obj.insert("reason".into(), serde_json::Value::String(r.clone()));
            }
            if let Some(secs) = auto_clear_secs {
                obj.insert(
                    "duration_secs".into(),
                    serde_json::Value::Number((*secs).into()),
                );
            }
            let payload = serde_json::Value::Object(obj).to_string();
            json_request("PUT", url, Some(&payload))
        }
        FetchKind::AuthEnableRole(_)
        | FetchKind::AuthDisableRole(_)
        | FetchKind::AuthLockRoles
        | FetchKind::AuthActivity
        | FetchKind::AuthResetUserPasskeys(_) => json_request("POST", url, Some("{}")),
        FetchKind::AuthElevateFinish {
            role_id,
            assertion_json,
        }
        | FetchKind::AuthRenewRole {
            role_id,
            assertion_json,
        } => {
            let payload = merge_json_field(
                assertion_json,
                "role_id",
                Some(serde_json::Value::String(role_id.clone())),
                "assertion_json",
            );
            json_request("POST", url, Some(&payload))
        }
        FetchKind::AuthProfilePut {
            display_name,
            preferred_skin,
            preferred_font,
        } => {
            let mut obj = serde_json::Map::new();
            if let Some(name) = display_name {
                obj.insert(
                    "display_name".into(),
                    serde_json::Value::String(name.clone()),
                );
            }
            if let Some(skin) = preferred_skin {
                if let Ok(v) = serde_json::to_value(skin) {
                    obj.insert("skin".into(), v);
                }
            }
            if let Some(font) = preferred_font {
                if let Ok(v) = serde_json::to_value(font) {
                    obj.insert("font".into(), v);
                }
            }
            let payload = serde_json::Value::Object(obj).to_string();
            json_request("PUT", url, Some(&payload))
        }
        FetchKind::AuthPasskeyRegisterFinish {
            label,
            attestation_json,
        } => {
            let payload = merge_json_field(
                attestation_json,
                "label",
                label.as_ref().map(|s| serde_json::Value::String(s.clone())),
                "attestation_json",
            );
            json_request("POST", url, Some(&payload))
        }
        FetchKind::AuthPasskeyDelete {
            step_up_assertion_json,
            ..
        } => {
            let trimmed = step_up_assertion_json.trim();
            if trimmed.is_empty() {
                json_request("DELETE", url, None)
            } else {
                let payload = if trimmed.starts_with('{') {
                    trimmed.to_owned()
                } else {
                    serde_json::json!({ "step_up_assertion_json": trimmed }).to_string()
                };
                json_request("DELETE", url, Some(&payload))
            }
        }
        FetchKind::AuthCreateInvite { note, ttl_secs } => {
            let mut obj = serde_json::Map::new();
            if let Some(n) = note {
                obj.insert("note".into(), serde_json::Value::String(n.clone()));
            }
            if let Some(ttl) = ttl_secs {
                obj.insert(
                    "ttl_seconds".into(),
                    serde_json::Value::Number((*ttl).into()),
                );
            }
            let payload = serde_json::Value::Object(obj).to_string();
            json_request("POST", url, Some(&payload))
        }
        FetchKind::AuthRevokeInvite(_)
        | FetchKind::AuthRevokeUser(_)
        | FetchKind::AuthDeleteRole(_)
        | FetchKind::AuthDeleteFolio(_) => json_request("DELETE", url, None),
        FetchKind::AuthUpdateUserRoles { bound_roles, .. } => {
            let payload = serde_json::json!({ "bound_roles": bound_roles }).to_string();
            json_request("PUT", url, Some(&payload))
        }
        FetchKind::AuthUpsertRole(spec) => {
            let payload = serialize_json_or_err(spec)?;
            json_request("PUT", url, Some(&payload))
        }
        FetchKind::AuthUpsertFolio(folio) => {
            let payload = serialize_json_or_err(folio)?;
            json_request("PUT", url, Some(&payload))
        }
        FetchKind::AuthUpdateRoleFolioIndex(idx) => {
            let payload = serialize_json_or_err(idx)?;
            json_request("PUT", url, Some(&payload))
        }
        FetchKind::JobLog(_) => request(url, "text/plain, */*", None),
        _ => request(url, "application/json", None),
    }
}

async fn fetch_response(req: &Request) -> Result<Response, JsValue> {
    Ok(JsFuture::from(scope().fetch_with_request(req))
        .await?
        .unchecked_into())
}

async fn fetch_json(kind: FetchKind, url: String) {
    let result = async {
        let req = build_fetch_request(&kind, &url).map_err(|e| HttpError {
            status: 0,
            message: js_msg(&e),
        })?;
        let resp = fetch_response(&req).await.map_err(|e| HttpError {
            status: 0,
            message: js_msg(&e),
        })?;
        if !resp.ok() {
            let status = u32::from(resp.status());
            let status_text = resp.status_text();
            let body = match resp.text() {
                Ok(p) => JsFuture::from(p).await.ok().and_then(|v| v.as_string()),
                Err(_) => None,
            };
            let fallback = if status_text.trim().is_empty() {
                format!("HTTP {status}")
            } else {
                status_text
            };
            return Err(HttpError {
                status,
                message: crate::api::extract_http_error_message(&fallback, body.as_deref()),
            });
        }
        let text = match resp.text() {
            Ok(p) => JsFuture::from(p).await,
            Err(e) => Err(e),
        }
        .map_err(|e| HttpError {
            status: 0,
            message: js_msg(&e),
        })?;
        Ok(text.as_string().unwrap_or_default())
    }
    .await;
    let fx = with_engine(|e| e.on_fetch(&kind, result, now_ms()));
    run(fx);
}

fn is_current(stream: StreamId, generation: u32) -> bool {
    STREAMS.with(|m| {
        m.borrow()[stream.index()]
            .as_ref()
            .is_some_and(|(g, _)| *g == generation)
    })
}

fn open_stream(stream: StreamId, url: String, last_event_id: Option<String>) {
    close_stream(stream);
    let Ok(ctrl) = AbortController::new() else {
        return;
    };
    let generation = GENERATION.with(|g| {
        let next = g.get().wrapping_add(1);
        g.set(next);
        next
    });
    STREAMS.with(|m| m.borrow_mut()[stream.index()] = Some((generation, ctrl.clone())));
    spawn_local(async move {
        let error = read_stream(stream, generation, &url, last_event_id, &ctrl)
            .await
            .err();
        if is_current(stream, generation) {
            STREAMS.with(|m| m.borrow_mut()[stream.index()] = None);
            let fx = with_engine(|e| e.on_stream_closed(stream, error, now_ms()));
            run(fx);
        }
    });
}

async fn read_stream(
    stream: StreamId,
    generation: u32,
    url: &str,
    last_event_id: Option<String>,
    ctrl: &AbortController,
) -> Result<(), String> {
    let req = request(url, "text/event-stream", Some(ctrl)).map_err(|e| js_msg(&e))?;
    if let Some(id) = last_event_id {
        req.headers()
            .set("Last-Event-ID", &id)
            .map_err(|e| js_msg(&e))?;
    }
    let resp = fetch_response(&req).await.map_err(|e| js_msg(&e))?;
    if !resp.ok() {
        return Err(format!("HTTP {} on {url}", resp.status()));
    }
    let body = resp.body().ok_or_else(|| "stream has no body".to_owned())?;
    if is_current(stream, generation) {
        let fx = with_engine(|e| e.on_stream_open(stream, now_ms()));
        run(fx);
    }
    let reader: ReadableStreamDefaultReader = body.get_reader().unchecked_into();
    loop {
        let res = JsFuture::from(reader.read())
            .await
            .map_err(|e| js_msg(&e))?;
        let done = Reflect::get(&res, &JsValue::from_str("done"))
            .map(|v| v.is_truthy())
            .unwrap_or(true);
        if done || !is_current(stream, generation) {
            return Ok(());
        }
        let value = Reflect::get(&res, &JsValue::from_str("value")).map_err(|e| js_msg(&e))?;
        let chunk = Uint8Array::new(&value).to_vec();
        let fx = with_engine(|e| e.on_stream_chunk(stream, &chunk, now_ms()));
        run(fx);
    }
}

fn close_stream(stream: StreamId) {
    if let Some((_, ctrl)) = STREAMS.with(|m| m.borrow_mut()[stream.index()].take()) {
        ctrl.abort();
    }
}

async fn open_cache() -> Result<Cache, JsValue> {
    let caches = scope().caches()?;
    Ok(JsFuture::from(caches.open(CACHE_NAME))
        .await?
        .unchecked_into())
}

async fn save_offline(bytes: &[u8]) -> Result<(), JsValue> {
    let cache = open_cache().await?;
    let body = Uint8Array::from(bytes);
    let resp = Response::new_with_opt_buffer_source(Some(&body))?;
    JsFuture::from(cache.put_with_str(CACHE_KEY, &resp)).await?;
    Ok(())
}

async fn load_offline() -> Result<Option<Vec<u8>>, JsValue> {
    let cache = open_cache().await?;
    let hit = JsFuture::from(cache.match_with_str(CACHE_KEY)).await?;
    if hit.is_undefined() || hit.is_null() {
        return Ok(None);
    }
    let resp: Response = hit.unchecked_into();
    let buf = JsFuture::from(resp.array_buffer()?).await?;
    Ok(Some(Uint8Array::new(&buf).to_vec()))
}
