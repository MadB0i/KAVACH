//! `kavach-dashboard` — local read-only decision dashboard.
//!
//! Tails the CLI JSONL decision feed (and, optionally, the SQLite
//! tamper-evident audit log) and serves a single-page UI with a live SSE
//! feed, filterable history and a view-only policy summary.

#![forbid(unsafe_code)]

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use axum::routing::get;
use clap::Parser;

mod event;
mod feed;
mod routes;

use feed::FeedHub;
use routes::AppState;

/// Local read-only dashboard for KAVACH decisions.
#[derive(Debug, Parser)]
#[command(
    name = "kavach-dashboard",
    version,
    about = "Local KAVACH decision dashboard"
)]
struct Args {
    /// JSONL decision feed tailed for live events (written by
    /// `kavach policy check/explain --feed-log`). Falls back to
    /// `KAVACH_FEED_LOG`, then `./kavach-decisions.jsonl`.
    #[arg(long)]
    feed: Option<PathBuf>,
    /// Optional SQLite tamper-evident audit database to tail and search.
    #[arg(long)]
    database: Option<PathBuf>,
    /// Optional policy TOML for the read-only summary endpoint.
    #[arg(long)]
    policy: Option<PathBuf>,
    /// Local port to listen on (always bound to 127.0.0.1).
    #[arg(long, default_value_t = 3939)]
    port: u16,
}

fn feed_path(args: &Args) -> PathBuf {
    if let Some(path) = &args.feed {
        return path.clone();
    }
    if let Ok(env) = std::env::var("KAVACH_FEED_LOG") {
        if !env.is_empty() {
            return PathBuf::from(env);
        }
    }
    PathBuf::from("kavach-decisions.jsonl")
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let feed = feed_path(&args);
    let hub = FeedHub::new();

    feed::spawn_feed_tailer(hub.clone(), feed.clone());
    if let Some(database) = &args.database {
        feed::spawn_audit_poller(hub.clone(), database.clone());
    }

    let state = Arc::new(AppState {
        hub,
        feed_path: feed,
        database_path: args.database.clone(),
        policy_path: args.policy.clone(),
    });

    let app = axum::Router::new()
        .route("/", get(routes::index))
        .route("/events", get(routes::events))
        .route("/api/history", get(routes::history))
        .route("/api/policy", get(routes::policy_summary))
        .with_state(state);

    // Known limitation: local-only bind with no auth. This is a dev tool;
    // never expose it beyond loopback.
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], args.port));
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(e) => {
            let _ = writeln!(std::io::stderr().lock(), "failed to bind {addr}: {e}");
            std::process::exit(1);
        }
    };
    let _ = writeln!(
        std::io::stdout().lock(),
        "kavach-dashboard listening on http://{addr}"
    );
    if let Err(e) = axum::serve(listener, app).await {
        let _ = writeln!(std::io::stderr().lock(), "server error: {e}");
        std::process::exit(1);
    }
}
