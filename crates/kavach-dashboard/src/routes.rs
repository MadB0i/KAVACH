//! HTTP routes: single-page UI, SSE live feed, history and policy APIs.

use std::convert::Infallible;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::extract::{Query, State};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Json};
use futures_core::Stream;
use serde::Deserialize;
use tokio::sync::mpsc;

use crate::event::FeedEvent;
use crate::feed::FeedHub;

/// Shared server state.
#[derive(Debug, Clone)]
pub struct AppState {
    /// Decision-event broadcast hub.
    pub hub: FeedHub,
    /// CLI JSONL feed file tailed for live events and history.
    pub feed_path: PathBuf,
    /// Optional SQLite tamper-evident audit database.
    pub database_path: Option<PathBuf>,
    /// Optional policy file for the read-only summary endpoint.
    pub policy_path: Option<PathBuf>,
}

/// `GET /` — single-page dashboard (no build step, no framework).
pub async fn index() -> Html<&'static str> {
    Html(include_str!("dashboard.html"))
}

/// Stream of broadcast strings forwarded over an mpsc channel, so the SSE
/// response only needs `futures-core` (already in the lock tree) instead of
/// an extra stream-adapter dependency.
struct ForwardStream {
    rx: mpsc::Receiver<Result<Event, Infallible>>,
}

impl Stream for ForwardStream {
    type Item = Result<Event, Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}

/// `GET /events` — server-sent stream of decision events, newest as appended.
pub async fn events(
    State(state): State<Arc<AppState>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let mut rx = state.hub.tx.subscribe();
    let (tx, stream_rx) = mpsc::channel(64);
    tokio::spawn(async move {
        while let Ok(line) = rx.recv().await {
            let event = Event::default().data(line);
            if tx.send(Ok(event)).await.is_err() {
                break;
            }
        }
    });
    Sse::new(ForwardStream { rx: stream_rx }).keep_alive(KeepAlive::default())
}

/// `GET /api/history` query parameters.
#[derive(Debug, Deserialize)]
pub struct HistoryQuery {
    /// Case-insensitive substring over title/explanation/rules/decision.
    pub q: Option<String>,
    /// Filter by decision: `allow`, `deny` or `require_approval`.
    pub decision: Option<String>,
    /// Substring filter over the command executable.
    pub executable: Option<String>,
    /// Substring filter over matched rule IDs.
    pub rule: Option<String>,
    /// Maximum events returned (default 50, hard cap 500).
    pub limit: Option<usize>,
}

/// `GET /api/history` — newest-first read of feed events plus, when
/// `--database` is configured, SQLite audit records.
pub async fn history(
    State(state): State<Arc<AppState>>,
    Query(query): Query<HistoryQuery>,
) -> impl IntoResponse {
    let limit = query.limit.unwrap_or(50).min(500);
    let feed_path = state.feed_path.clone();
    let database_path = state.database_path.clone();

    let events = tokio::task::spawn_blocking(move || {
        read_history(&feed_path, database_path.as_deref(), &query, limit)
    })
    .await
    .unwrap_or_default();

    Json(serde_json::json!({
        "total": events.len(),
        "limit": limit,
        "events": events,
    }))
}

fn read_history(
    feed_path: &std::path::Path,
    database_path: Option<&std::path::Path>,
    query: &HistoryQuery,
    limit: usize,
) -> Vec<FeedEvent> {
    let mut events: Vec<FeedEvent> = Vec::new();

    if let Ok(text) = std::fs::read_to_string(feed_path) {
        events.extend(
            text.lines()
                .filter_map(crate::event::feed_event_from_cli_line),
        );
    }

    if let Some(db) = database_path {
        if let Ok(store) = kavach_audit::AuditStore::builder().open(db.to_str().unwrap_or_default())
        {
            if let Ok(count) = store.event_count() {
                let start = count.saturating_sub(500);
                if let Ok(records) = store.events_after_sequence(start, 500) {
                    events.extend(records.iter().map(crate::event::feed_event_from_audit));
                }
            }
        }
    }

    events.sort_by_key(|e| std::cmp::Reverse(e.at_secs));
    events
        .into_iter()
        .filter(|e| history_matches(e, query))
        .take(limit)
        .collect()
}

fn history_matches(event: &FeedEvent, query: &HistoryQuery) -> bool {
    if let Some(q) = &query.q {
        if !q.is_empty() && !event.matches_query(q) {
            return false;
        }
    }
    if let Some(decision) = &query.decision {
        if !decision.is_empty() && !event.effect.eq_ignore_ascii_case(decision.trim()) {
            return false;
        }
    }
    if let Some(exe) = &query.executable {
        if !exe.is_empty() {
            let haystack = event.executable.as_deref().unwrap_or_default();
            if !haystack.to_lowercase().contains(&exe.to_lowercase()) {
                return false;
            }
        }
    }
    if let Some(rule) = &query.rule {
        if !rule.is_empty()
            && !event
                .matched_rule_ids
                .iter()
                .any(|id| id.to_lowercase().contains(&rule.to_lowercase()))
        {
            return false;
        }
    }
    true
}

/// `GET /api/policy` — read-only summary of the loaded policy file.
/// View-only by design: no endpoint here mutates policy.
pub async fn policy_summary(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let Some(policy_path) = state.policy_path.clone() else {
        return Json(serde_json::json!({
            "loaded": false,
            "error": "no policy file configured (start with --policy)",
        }));
    };
    let summary = tokio::task::spawn_blocking(move || summarize_policy(&policy_path))
        .await
        .unwrap_or_else(|_| serde_json::json!({"loaded": false, "error": "policy summary failed"}));
    Json(summary)
}

fn summarize_policy(policy_path: &std::path::Path) -> serde_json::Value {
    let policy = match kavach_policy::load_policy_from_file(policy_path) {
        Ok(p) => p,
        Err(e) => {
            return serde_json::json!({"loaded": false, "error": e.to_string()});
        }
    };
    let engine = match kavach_policy::PolicyEngine::new(vec![policy.clone()]) {
        Ok(e) => e,
        Err(e) => {
            return serde_json::json!({"loaded": false, "error": e.to_string()});
        }
    };
    let mut executables = std::collections::BTreeSet::new();
    let mut path_globs = std::collections::BTreeSet::new();
    for rule in &policy.rules {
        executables.extend(rule.conditions.executables.clone().unwrap_or_default());
        path_globs.extend(rule.conditions.path_globs.clone().unwrap_or_default());
    }
    let warnings: Vec<serde_json::Value> = engine
        .warnings()
        .iter()
        .map(|w| {
            serde_json::json!({
                "rule_id": w.rule_id.to_string(),
                "message": w.message,
            })
        })
        .collect();
    serde_json::json!({
        "loaded": true,
        "id": policy.id.to_string(),
        "name": policy.name,
        "default_effect": format!("{:?}", policy.default_effect),
        "rule_count": policy.rules.len(),
        "executables": executables.into_iter().collect::<Vec<_>>(),
        "path_globs": path_globs.into_iter().collect::<Vec<_>>(),
        "warnings": warnings,
    })
}
