//! Decision-event feed: tails the CLI JSONL feed file and, when configured,
//! polls the SQLite tamper-evident audit log. Both sources fan into one
//! broadcast channel consumed by the SSE endpoint.

use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::sync::broadcast;

use crate::event::FeedEvent;

/// How often the feed file is polled for appended lines.
const FEED_POLL_INTERVAL: Duration = Duration::from_millis(500);
/// How often the audit database is polled for new sequences.
const AUDIT_POLL_INTERVAL: Duration = Duration::from_secs(2);
/// Maximum lines read from the feed file on startup (recent context only).
const FEED_STARTUP_TAIL_LINES: usize = 200;

/// Shared dashboard state handle for background tasks.
#[derive(Debug, Clone)]
pub struct FeedHub {
    /// Broadcast sender for normalized [`FeedEvent`] JSON strings.
    pub tx: broadcast::Sender<String>,
}

impl FeedHub {
    /// Create a hub with a bounded broadcast buffer.
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(256);
        Self { tx }
    }

    /// Publish one event, ignoring the no-receiver case.
    pub fn publish(&self, event: &FeedEvent) {
        if let Ok(line) = serde_json::to_string(event) {
            let _ = self.tx.send(line);
        }
    }
}

impl Default for FeedHub {
    fn default() -> Self {
        Self::new()
    }
}

/// Spawn the feed-file tailer: streams lines appended after startup, plus a
/// bounded recent tail so a fresh dashboard isn't empty.
pub fn spawn_feed_tailer(hub: FeedHub, feed_path: PathBuf) {
    tokio::spawn(async move {
        let mut offset = initial_offset(&feed_path).await;
        // Replay recent context first (oldest of the tail first).
        for event in read_tail(&feed_path, FEED_STARTUP_TAIL_LINES).await {
            hub.publish(&event);
        }
        loop {
            tokio::time::sleep(FEED_POLL_INTERVAL).await;
            let (next_offset, events) = read_appended(&feed_path, offset).await;
            offset = next_offset;
            for event in events {
                hub.publish(&event);
            }
        }
    });
}

/// Spawn the audit-database poller (only when `--database` is configured).
pub fn spawn_audit_poller(hub: FeedHub, database_path: PathBuf) {
    tokio::spawn(async move {
        let mut last_seen: Option<u64> = None;
        loop {
            let fresh = tokio::task::spawn_blocking({
                let path = database_path.clone();
                move || poll_audit_once(&path, last_seen)
            })
            .await
            .unwrap_or_default();
            for (sequence, event) in fresh {
                last_seen = Some(sequence);
                hub.publish(&event);
            }
            tokio::time::sleep(AUDIT_POLL_INTERVAL).await;
        }
    });
}

async fn initial_offset(feed_path: &Path) -> u64 {
    tokio::fs::metadata(feed_path)
        .await
        .map(|m| m.len())
        .unwrap_or(0)
}

async fn read_tail(feed_path: &Path, max_lines: usize) -> Vec<FeedEvent> {
    let text = tokio::fs::read_to_string(feed_path)
        .await
        .unwrap_or_default();
    text.lines()
        .rev()
        .take(max_lines)
        .filter_map(parse_feed_line)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect()
}

async fn read_appended(feed_path: &Path, offset: u64) -> (u64, Vec<FeedEvent>) {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    let mut file = match tokio::fs::File::open(feed_path).await {
        Ok(f) => f,
        Err(_) => return (offset, Vec::new()),
    };
    let len = file.metadata().await.map(|m| m.len()).unwrap_or(offset);
    if len < offset {
        // Truncated/rotated: reread from the start.
        return (len, read_all(feed_path).await);
    }
    if len == offset {
        return (offset, Vec::new());
    }
    if file.seek(std::io::SeekFrom::Start(offset)).await.is_err() {
        return (offset, Vec::new());
    }
    let mut buf = Vec::new();
    let Ok(_) = file.read_to_end(&mut buf).await else {
        return (offset, Vec::new());
    };
    let text = String::from_utf8_lossy(&buf);
    let events: Vec<FeedEvent> = text.lines().filter_map(parse_feed_line).collect();
    (len, events)
}

async fn read_all(feed_path: &Path) -> Vec<FeedEvent> {
    let text = tokio::fs::read_to_string(feed_path)
        .await
        .unwrap_or_default();
    text.lines().filter_map(parse_feed_line).collect()
}

fn parse_feed_line(line: &str) -> Option<FeedEvent> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    crate::event::feed_event_from_cli_line(line)
}

/// One audit-poll roundtrip (blocking SQLite work, runs on the blocking pool).
fn poll_audit_once(database_path: &Path, after: Option<u64>) -> Vec<(u64, FeedEvent)> {
    let store = match kavach_audit::AuditStore::builder()
        .open(database_path.to_str().unwrap_or_default())
    {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let start = after
        .map(|s| s.saturating_add(1))
        .unwrap_or_else(|| store.event_count().unwrap_or(0).saturating_sub(50));
    store
        .events_after_sequence(start, 100)
        .unwrap_or_default()
        .into_iter()
        .map(|record| {
            let sequence = record.sequence;
            (sequence, crate::event::feed_event_from_audit(&record))
        })
        .collect()
}
