//! Hallpass daemon: interactive application firewall.
//!
//! Startup order: config, nftables install, then three long-lived workers:
//! the blocking nfqueue loop on its own thread, the prompt dispatcher, and
//! the IPC server. SIGTERM/SIGINT (and the panic hook) tear the nftables
//! table down so a dead daemon never leaves traffic queued.

#![deny(unsafe_code)]

mod attribution;
mod config;
mod dns;
mod events;
mod ipc;
mod nfqueue;
mod nft;
mod packet;
mod prompt;
mod rules;
mod stats;
#[cfg(test)]
mod testutil;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::signal::unix::{signal, SignalKind};

use crate::attribution::AttributionChain;
use crate::events::EventBus;
use crate::prompt::PromptTable;
use crate::rules::store::RuleStore;
use crate::stats::Counters;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let config_path = match config::parse_args(std::env::args().skip(1)) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    let cfg = match config::Config::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("failed to load config: {e}");
            std::process::exit(1);
        }
    };
    tracing::info!(?cfg, "hallpassd starting");

    if rules::store::effective_uid() != Some(0) {
        tracing::warn!(
            "not running as root: nftables install and packet interception will likely fail"
        );
    }

    let nft_installed = match nft::install(cfg.queue_num) {
        Ok(()) => {
            tracing::info!("nftables ruleset installed");
            true
        }
        Err(e) => {
            tracing::error!("nftables install failed, continuing without interception: {e}");
            false
        }
    };

    // Any panic must not leave the nft table (and thus queued packets)
    // behind. Teardown is idempotent; exiting is safer than running with
    // interception half torn down.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        nft::teardown();
        default_hook(info);
        std::process::exit(101);
    }));

    // Shared state.
    let events = Arc::new(EventBus::default());
    let counters = Arc::new(Counters::default());
    let store = Arc::new(RuleStore::new(cfg.rules_dir.clone()));
    if let Err(e) = rules::store::spawn_watcher(Arc::clone(&store)) {
        tracing::warn!("rules dir watcher unavailable: {e}");
    }

    // Channels between the queue thread and the async side.
    let (prompt_tx, mut prompt_rx) =
        tokio::sync::mpsc::unbounded_channel::<nfqueue::PromptTask>();
    let (verdict_tx, verdict_rx) = tokio::sync::mpsc::unbounded_channel();
    let (dns_tx, mut dns_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

    let prompts = Arc::new(PromptTable::new(
        verdict_tx,
        Arc::clone(&events),
        Arc::clone(&counters),
        Arc::clone(&store),
        Duration::from_secs(cfg.prompt_timeout_secs),
        cfg.max_pending_prompts,
        cfg.default_verdict,
    ));

    // DNS snoop consumer: parse each captured reply and record every
    // resolved IP under the name the application originally asked for.
    // The queue thread reads the cache when it builds a Connection.
    let dns_cache = Arc::new(dns::IpDomainCache::new(dns::CACHE_CAPACITY));
    let snoop_cache = Arc::clone(&dns_cache);
    tokio::spawn(async move {
        while let Some(pkt) = dns_rx.recv().await {
            if let Some(resp) = packet::udp_payload(&pkt).and_then(dns::parse_response) {
                tracing::debug!(
                    domain = %resp.query_name,
                    addrs = resp.addrs.len(),
                    "dns response snooped"
                );
                snoop_cache.absorb(&resp);
            }
        }
    });

    // Prompt dispatcher: unmatched connections from the queue thread.
    let dispatcher_prompts = Arc::clone(&prompts);
    tokio::spawn(async move {
        while let Some(task) = prompt_rx.recv().await {
            dispatcher_prompts.handle_new(task.conn, task.seq);
        }
    });

    // Blocking nfqueue loop on its own thread.
    let shutdown = Arc::new(AtomicBool::new(false));
    let queue_thread = nfqueue::spawn(
        cfg.queue_num,
        nfqueue::QueueDeps {
            attribution: AttributionChain::default_chain(),
            rules: Arc::clone(&store),
            events: Arc::clone(&events),
            stats: Arc::clone(&counters),
            prompt_tx,
            verdict_rx,
            dns_tx,
            dns_cache,
            shutdown: Arc::clone(&shutdown),
        },
    );

    // IPC server.
    let ipc_deps = Arc::new(ipc::server::IpcDeps {
        store,
        prompts,
        events,
        stats: counters,
    });
    let socket_path = cfg.socket_path.clone();
    let ipc_task = tokio::spawn(async move {
        if let Err(e) = ipc::server::run(&socket_path, ipc_deps).await {
            tracing::error!("IPC server failed: {e}");
        }
    });

    // Wait for SIGTERM or SIGINT.
    let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => tracing::info!("SIGINT received"),
        _ = sigterm.recv() => tracing::info!("SIGTERM received"),
    }

    tracing::info!("shutting down");
    shutdown.store(true, Ordering::Relaxed);
    ipc_task.abort();
    if nft_installed {
        nft::teardown();
    }
    let _ = std::fs::remove_file(&cfg.socket_path);
    let _ = queue_thread.join();
    tracing::info!("hallpassd stopped");
}
