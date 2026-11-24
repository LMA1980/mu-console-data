// SPDX-License-Identifier: AGPL-3.0-only
//! Dedicated Web Worker IndexedDB cache for OpenTelemetry logs (`wasm32` only).
//!
//! Stores up to [`IDB_MAX_CACHED_LOGS`] entries in database `muconsole-obs-logs-v1`
//! object store `logs` keyed by [`CachedObsLog::k`]. All failures (incognito
//! quota restrictions, disabled storage, blocked upgrades) degrade silently so live
//! UI streaming never blocks or crashes.

use std::cell::RefCell;
use std::rc::Rc;

use js_sys::{Reflect, JSON};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    Event, IdbCursorDirection, IdbCursorWithValue, IdbDatabase, IdbFactory, IdbKeyRange,
    IdbObjectStoreParameters, IdbOpenDbRequest, IdbRequest, IdbTransactionMode,
    IdbVersionChangeEvent,
};

use crate::log_cache::{CachedObsLog, IDB_MAX_CACHED_LOGS, IDB_NAME, IDB_STORE_LOGS};

fn indexed_db_factory() -> Result<IdbFactory, JsValue> {
    let val = Reflect::get(&js_sys::global(), &JsValue::from_str("indexedDB"))?;
    val.dyn_into::<IdbFactory>()
}

async fn await_request(req: &IdbRequest) -> Result<JsValue, JsValue> {
    let ok_slot: Rc<RefCell<Option<Closure<dyn FnMut(Event)>>>> = Rc::new(RefCell::new(None));
    let err_slot: Rc<RefCell<Option<Closure<dyn FnMut(Event)>>>> = Rc::new(RefCell::new(None));

    let promise = js_sys::Promise::new(&mut |resolve, reject| {
        let req_ok = req.clone();
        let reject_ok = reject.clone();
        let on_ok = Closure::wrap(Box::new(move |_ev: Event| match req_ok.result() {
            Ok(v) => {
                let _ = resolve.call1(&JsValue::NULL, &v);
            }
            Err(e) => {
                let _ = reject_ok.call1(&JsValue::NULL, &e);
            }
        }) as Box<dyn FnMut(Event)>);

        let on_err = Closure::wrap(Box::new(move |_ev: Event| {
            let err = JsValue::from_str("IndexedDB request error");
            let _ = reject.call1(&JsValue::NULL, &err);
        }) as Box<dyn FnMut(Event)>);

        req.set_onsuccess(Some(on_ok.as_ref().unchecked_ref()));
        req.set_onerror(Some(on_err.as_ref().unchecked_ref()));
        *ok_slot.borrow_mut() = Some(on_ok);
        *err_slot.borrow_mut() = Some(on_err);
    });

    let res = JsFuture::from(promise).await;
    req.set_onsuccess(None);
    req.set_onerror(None);
    drop(ok_slot);
    drop(err_slot);
    res
}

async fn open_db() -> Result<IdbDatabase, JsValue> {
    let factory = indexed_db_factory()?;
    let open_req: IdbOpenDbRequest = factory.open_with_u32(IDB_NAME, 1)?;
    let upgrade_slot: Rc<RefCell<Option<Closure<dyn FnMut(IdbVersionChangeEvent)>>>> =
        Rc::new(RefCell::new(None));
    let on_upgrade = Closure::wrap(Box::new(move |ev: IdbVersionChangeEvent| {
        let Some(target) = ev.target() else {
            return;
        };
        let Ok(req) = target.dyn_into::<IdbOpenDbRequest>() else {
            return;
        };
        let Ok(result) = req.result() else {
            return;
        };
        let Ok(db) = result.dyn_into::<IdbDatabase>() else {
            return;
        };
        if !db.object_store_names().contains(IDB_STORE_LOGS) {
            let params = IdbObjectStoreParameters::new();
            params.set_key_path(&JsValue::from_str("k"));
            let _ = db.create_object_store_with_optional_parameters(IDB_STORE_LOGS, &params);
        }
    }) as Box<dyn FnMut(IdbVersionChangeEvent)>);
    open_req.set_onupgradeneeded(Some(on_upgrade.as_ref().unchecked_ref()));
    *upgrade_slot.borrow_mut() = Some(on_upgrade);

    let db_val = await_request(&open_req).await;
    open_req.set_onupgradeneeded(None);
    drop(upgrade_slot);
    db_val?.dyn_into::<IdbDatabase>()
}

fn parse_cached_log(val: &JsValue) -> Option<CachedObsLog> {
    let s = JSON::stringify(val).ok()?.as_string()?;
    serde_json::from_str(&s).ok()
}

fn store_count_from_js(val: &JsValue) -> u32 {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let count = val.as_f64().unwrap_or(0.0).clamp(0.0, f64::from(u32::MAX)) as u32;
    count
}

/// Insert or update a batch of logs and enforce the 20,000-entry FIFO ceiling.
pub async fn put_batch(items: &[CachedObsLog]) -> Result<u32, JsValue> {
    if items.is_empty() {
        return Ok(0);
    }
    let db = open_db().await?;
    let tx = db.transaction_with_str_and_mode(IDB_STORE_LOGS, IdbTransactionMode::Readwrite)?;
    let store = tx.object_store(IDB_STORE_LOGS)?;

    for item in items {
        let Ok(json_str) = serde_json::to_string(item) else {
            continue;
        };
        let Ok(js_obj) = JSON::parse(&json_str) else {
            continue;
        };
        let _ = store.put(&js_obj);
    }

    let count_req = store.count()?;
    let count_val = await_request(&count_req).await?;
    let mut total = store_count_from_js(&count_val);

    if total as usize > IDB_MAX_CACHED_LOGS {
        let mut to_evict = (total as usize) - IDB_MAX_CACHED_LOGS;
        let cursor_req =
            store.open_cursor_with_range_and_direction(&JsValue::NULL, IdbCursorDirection::Next)?;
        while to_evict > 0 {
            let step_val = await_request(&cursor_req).await?;
            if step_val.is_null() || step_val.is_undefined() {
                break;
            }
            let cursor: IdbCursorWithValue = step_val.dyn_into()?;
            let del_req = cursor.delete()?;
            let _ = await_request(&del_req).await;
            to_evict -= 1;
            if to_evict == 0 {
                break;
            }
            cursor.continue_()?;
        }
        let refreshed = store.count()?;
        total = store_count_from_js(&await_request(&refreshed).await?);
    }

    db.close();
    Ok(total)
}

async fn read_cursor_range(
    range: Option<IdbKeyRange>,
    direction: IdbCursorDirection,
    limit: usize,
) -> Result<(Vec<CachedObsLog>, u32), JsValue> {
    let db = open_db().await?;
    let tx = db.transaction_with_str_and_mode(IDB_STORE_LOGS, IdbTransactionMode::Readonly)?;
    let store = tx.object_store(IDB_STORE_LOGS)?;
    let count = store_count_from_js(&await_request(&store.count()?).await?);

    let cursor_req = match range.as_ref() {
        Some(r) => store.open_cursor_with_range_and_direction(r.as_ref(), direction)?,
        None => store.open_cursor_with_range_and_direction(&JsValue::NULL, direction)?,
    };

    let mut out = Vec::with_capacity(limit.min(512));
    while out.len() < limit {
        let step_val = await_request(&cursor_req).await?;
        if step_val.is_null() || step_val.is_undefined() {
            break;
        }
        let cursor: IdbCursorWithValue = step_val.dyn_into()?;
        if let Ok(val) = cursor.value() {
            if let Some(entry) = parse_cached_log(&val) {
                out.push(entry);
            }
        }
        if out.len() >= limit {
            break;
        }
        cursor.continue_()?;
    }

    db.close();
    Ok((out, count))
}

/// Read up to `limit` logs strictly older than `before_key` (returned newest-first).
pub async fn read_older(
    before_key: &str,
    limit: usize,
) -> Result<(Vec<CachedObsLog>, u32), JsValue> {
    let range = IdbKeyRange::upper_bound_with_open(&JsValue::from_str(before_key), true)?;
    read_cursor_range(Some(range), IdbCursorDirection::Prev, limit).await
}

/// Read up to `limit` logs immediately newer than `after_key` (returned newest-first).
pub async fn read_newer(
    after_key: &str,
    limit: usize,
) -> Result<(Vec<CachedObsLog>, u32), JsValue> {
    let range = IdbKeyRange::lower_bound_with_open(&JsValue::from_str(after_key), true)?;
    let (mut items, count) =
        read_cursor_range(Some(range), IdbCursorDirection::Next, limit).await?;
    items.reverse();
    Ok((items, count))
}

/// Read the newest `limit` logs from IndexedDB (returned newest-first).
pub async fn read_latest(limit: usize) -> Result<(Vec<CachedObsLog>, u32), JsValue> {
    read_cursor_range(None, IdbCursorDirection::Prev, limit).await
}

/// Fail-closed wipe of all cached logs from browser IndexedDB.
pub async fn clear() -> Result<(), JsValue> {
    let db = open_db().await?;
    let tx = db.transaction_with_str_and_mode(IDB_STORE_LOGS, IdbTransactionMode::Readwrite)?;
    let store = tx.object_store(IDB_STORE_LOGS)?;
    let req = store.clear()?;
    let _ = await_request(&req).await;
    db.close();
    Ok(())
}
