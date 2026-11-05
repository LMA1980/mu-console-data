// SPDX-License-Identifier: AGPL-3.0-only
//! Hand-written Server-Sent Events parser (WHATWG "event stream
//! interpretation").
//!
//! Fed with arbitrary byte chunks from a `fetch` `ReadableStream`; lines may
//! be split anywhere, including inside a UTF-8 sequence or between the `\r`
//! and `\n` of a CRLF pair. Handles multi-line `data:`, `:` comments,
//! `retry:`, `id:` (ignored when it contains NUL), a leading BOM, and the
//! "one optional space after the colon" rule.

use std::mem;

/// One dispatched event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    /// `event:` field; `"message"` when absent.
    pub event: String,
    /// `data:` lines joined with `\n`.
    pub data: String,
    /// Last event id in effect when this event was dispatched.
    pub id: Option<String>,
}

/// Incremental SSE parser.
#[derive(Debug, Default)]
pub struct SseParser {
    buf: Vec<u8>,
    /// The previous chunk ended with `\r`; swallow a leading `\n`.
    pending_cr: bool,
    started: bool,
    event: String,
    data: String,
    has_data: bool,
    /// `id:` seen in the event being parsed (committed on dispatch).
    id_buffer: Option<String>,
    last_event_id: Option<String>,
    retry_ms: Option<u32>,
}

impl SseParser {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Last-Event-ID to send when reconnecting.
    #[must_use]
    pub fn last_event_id(&self) -> Option<&str> {
        self.last_event_id.as_deref()
    }

    /// Latest `retry:` value from the server, in milliseconds.
    #[must_use]
    pub fn retry_ms(&self) -> Option<u32> {
        self.retry_ms
    }

    /// Reset per-connection state (keeps Last-Event-ID and retry).
    pub fn reset_connection(&mut self) {
        self.buf.clear();
        self.pending_cr = false;
        self.started = false;
        self.event.clear();
        self.data.clear();
        self.has_data = false;
        self.id_buffer.clone_from(&self.last_event_id);
    }

    /// Feed a chunk and return the events it completed.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<SseEvent> {
        let mut out = Vec::new();
        let mut start: usize = 0;
        let mut i: usize = 0;
        if self.pending_cr && chunk.first() == Some(&b'\n') {
            start = 1;
            i = 1;
        }
        self.pending_cr = false;
        while i < chunk.len() {
            let b = chunk[i];
            if b == b'\n' || b == b'\r' {
                self.buf.extend_from_slice(&chunk[start..i]);
                let line = mem::take(&mut self.buf);
                self.line(&line, &mut out);
                if b == b'\r' {
                    if chunk.get(i + 1) == Some(&b'\n') {
                        i += 1;
                    } else if i + 1 == chunk.len() {
                        self.pending_cr = true;
                    }
                }
                start = i + 1;
            }
            i += 1;
        }
        if start < chunk.len() {
            self.buf.extend_from_slice(&chunk[start..]);
        }
        out
    }

    fn line(&mut self, raw: &[u8], out: &mut Vec<SseEvent>) {
        let mut raw = raw;
        if !self.started {
            self.started = true;
            if let Some(rest) = raw.strip_prefix(b"\xEF\xBB\xBF") {
                raw = rest;
            }
        }
        let line = String::from_utf8_lossy(raw);
        if line.is_empty() {
            self.dispatch(out);
            return;
        }
        if line.starts_with(':') {
            return;
        }
        let (field, value) = match line.split_once(':') {
            Some((f, v)) => (f, v.strip_prefix(' ').unwrap_or(v)),
            None => (line.as_ref(), ""),
        };
        match field {
            "event" => value.clone_into(&mut self.event),
            "data" => {
                if self.has_data {
                    self.data.push('\n');
                }
                self.data.push_str(value);
                self.has_data = true;
            }
            "id" => {
                if !value.contains('\0') {
                    self.id_buffer = Some(value.to_owned());
                }
            }
            "retry" if !value.is_empty() && value.bytes().all(|c| c.is_ascii_digit()) => {
                if let Ok(ms) = value.parse::<u32>() {
                    self.retry_ms = Some(ms);
                }
            }
            _ => {}
        }
    }

    fn dispatch(&mut self, out: &mut Vec<SseEvent>) {
        self.last_event_id.clone_from(&self.id_buffer);
        let event = mem::take(&mut self.event);
        if !self.has_data {
            return;
        }
        self.has_data = false;
        out.push(SseEvent {
            event: if event.is_empty() {
                "message".to_owned()
            } else {
                event
            },
            data: mem::take(&mut self.data),
            id: self.last_event_id.clone(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(event: &str, data: &str, id: Option<&str>) -> SseEvent {
        SseEvent {
            event: event.into(),
            data: data.into(),
            id: id.map(Into::into),
        }
    }

    #[test]
    fn single_and_multi_line_events() {
        let mut p = SseParser::new();
        let out = p.feed(b"event: branch_created\ndata: {\"a\":1}\n\ndata: line1\ndata: line2\n\n");
        assert_eq!(
            out,
            vec![
                ev("branch_created", "{\"a\":1}", None),
                ev("message", "line1\nline2", None)
            ]
        );
    }

    #[test]
    fn comments_retry_and_ids() {
        let mut p = SseParser::new();
        let out = p
            .feed(b": keep-alive\nretry: 2500\nid: 41\nevent: x\ndata\n\nid: bad\0id\ndata: y\n\n");
        assert_eq!(p.retry_ms(), Some(2500));
        assert_eq!(
            out,
            vec![ev("x", "", Some("41")), ev("message", "y", Some("41"))]
        );
        assert_eq!(p.last_event_id(), Some("41"));
        // Invalid retry values are ignored.
        p.feed(b"retry: 12a\nretry:\n\n");
        assert_eq!(p.retry_ms(), Some(2500));
        // An empty id resets the Last-Event-ID to "".
        p.feed(b"id\n\n");
        assert_eq!(p.last_event_id(), Some(""));
    }

    #[test]
    fn events_without_data_are_not_dispatched() {
        let mut p = SseParser::new();
        assert!(p.feed(b"event: lonely\n\n\n").is_empty());
        // The event name does not leak into the next event.
        assert_eq!(p.feed(b"data: z\n\n"), vec![ev("message", "z", None)]);
    }

    #[test]
    fn only_one_leading_space_is_stripped() {
        let mut p = SseParser::new();
        assert_eq!(p.feed(b"data:  two\ndata:none\n\n")[0].data, " two\nnone");
    }

    #[test]
    fn bom_and_line_endings() {
        let mut p = SseParser::new();
        let out = p.feed(b"\xEF\xBB\xBFdata: a\r\n\r\ndata: b\r\rdata: c\n\n");
        assert_eq!(
            out,
            vec![
                ev("message", "a", None),
                ev("message", "b", None),
                ev("message", "c", None)
            ]
        );
    }

    #[test]
    fn arbitrary_chunk_boundaries_give_identical_events() {
        let stream: &[u8] = "\u{feff}: hi\r\nid: 7\r\nevent: it_progress\r\ndata: {\"name\":\"ünïcødé\"}\r\ndata: second\r\n\r\nretry: 900\ndata: tail\r\r"
            .as_bytes();
        let whole = SseParser::new().feed(stream);
        assert_eq!(whole.len(), 2);
        for size in 1..stream.len() {
            let mut p = SseParser::new();
            let mut got = Vec::new();
            for chunk in stream.chunks(size) {
                got.extend(p.feed(chunk));
            }
            assert_eq!(got, whole, "chunk size {size}");
            assert_eq!(p.retry_ms(), Some(900));
        }
    }

    #[test]
    fn partial_event_is_dropped_on_reconnect() {
        let mut p = SseParser::new();
        p.feed(b"id: 3\ndata: complete\n\nid: 4\ndata: partial");
        p.reset_connection();
        assert_eq!(p.last_event_id(), Some("3"));
        assert_eq!(
            p.feed(b"data: fresh\n\n"),
            vec![ev("message", "fresh", Some("3"))]
        );
    }
}
