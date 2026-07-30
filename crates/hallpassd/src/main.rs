//! Hallpass daemon: interactive application firewall.
//!
//! Startup order: config, nftables install, then three long-lived workers:
//! the blocking nfqueue loop on its own thread, the prompt dispatcher, and
//! the IPC server. SIGTERM/SIGINT tear the nftables table down; the panic
//! hook does too only in fail-open mode (`queue_bypass = true`), because in
//! fail-closed mode the leftover table is what keeps enforcement up.

#![deny(unsafe_code)]

mod attribution;
mod config;
mod dns;
mod events;
mod iface;
mod ipc;
mod nfqueue;
mod nft;
mod packet;
mod prompt;
mod rules;
mod stats;
mod syslog;
#[cfg(test)]
mod testutil;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::signal::unix::{signal, SignalKind};

/// Depth of the observed-DNS queue between the verdict thread and the snoop
/// consumer. Deep enough to absorb a normal resolution burst, shallow enough
/// that a flood costs bounded memory instead of the process.
const DNS_SNOOP_QUEUE_CAP: usize = 1024;

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

    let config_arg = match config::parse_args(std::env::args().skip(1)) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    let cfg = match config::Config::load(&config_arg) {
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

    // Take the control socket before installing any nftables rules. A
    // daemon that filters traffic but cannot be reached answers every
    // prompt with the default verdict and gives the operator no way to
    // see it happening or change it, which under `default_verdict =
    // "allow"` is an open firewall that looks healthy. Binding first
    // makes that failure free to back out of: nothing is installed yet,
    // so exiting leaves the system exactly as it was found.
    let ipc_listener = match ipc::server::bind(&cfg.socket_path) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(
                path = %cfg.socket_path.display(),
                "failed to bind the IPC socket, refusing to filter without a control channel: {e}"
            );
            std::process::exit(1);
        }
    };

    // Bind the nfqueues before installing the nftables rules that feed
    // them, for the same reason the IPC socket binds first. A packet
    // queued while no listener is bound is resolved by the `bypass` flag
    // alone, skipping the default verdict and every rule: under
    // fail-open that silently allows what a rule would deny, for however
    // long the listener takes to arrive. Binding first means the moment
    // packets can be queued, something is there to judge them.
    let queue = match nfqueue::bind(cfg.queue_num) {
        Ok(q) => Some(q),
        Err(e) if cfg.queue_bypass => {
            // Without privileges (development runs) the bind fails and
            // interception is off; IPC and rule management still work.
            tracing::error!("nfqueue bind failed, continuing without interception: {e}");
            None
        }
        Err(e) => {
            tracing::error!("nfqueue bind failed and queue_bypass is off: {e}");
            std::process::exit(1);
        }
    };

    let nft_installed = match &queue {
        None => false,
        Some(_) => match nft::install(cfg.queue_num, cfg.queue_bypass) {
            Ok(()) => {
                tracing::info!("nftables ruleset installed");
                true
            }
            Err(e) if cfg.queue_bypass => {
                tracing::error!("nftables install failed, continuing without interception: {e}");
                false
            }
            Err(e) => {
                // Fail-closed posture: running unenforced would silently
                // contradict the operator's declared choice. Refuse to
                // start.
                tracing::error!("nftables install failed and queue_bypass is off: {e}");
                std::process::exit(1);
            }
        },
    };

    // Fail-open mode: a panic must not leave the nft table (and thus queued
    // packets) behind. Fail-closed mode is the opposite: the table IS the
    // enforcement, so a panicking daemon leaves it up (bypass-less queue
    // drops new connections) until a restart or an explicit teardown.
    // Teardown is idempotent; exiting is safer than running with
    // interception half torn down.
    let default_hook = std::panic::take_hook();
    let teardown_on_panic = cfg.queue_bypass;
    std::panic::set_hook(Box::new(move |info| {
        if teardown_on_panic {
            nft::teardown();
        }
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
    rules::store::spawn_expiry_sweeper(Arc::clone(&store));
    if let Some(syslog_cfg) = cfg.syslog.clone() {
        syslog::spawn(Arc::clone(&events), syslog_cfg);
    }

    // Channels between the queue thread and the async side.
    let (prompt_tx, mut prompt_rx) =
        tokio::sync::mpsc::unbounded_channel::<nfqueue::PromptTask>();
    let (verdict_tx, verdict_rx) = tokio::sync::mpsc::unbounded_channel();
    // Bounded, unlike the two above. Those carry one item per packet the
    // daemon is already holding, so the kernel queue length bounds them. This
    // one carries observed DNS traffic, and the input snoop rule queues any
    // UDP packet with source port 53, so anything that can send to this host
    // can feed it at line rate while the consumer does strictly more work per
    // item (parse plus cache locking) than the producer. Unbounded, that grew
    // until the OOM killer took a root daemon, which under queue_bypass=false
    // blackholes every new connection on the host.
    let (dns_tx, mut dns_rx) =
        tokio::sync::mpsc::channel::<(hallpass_types::FlowTuple, Vec<u8>)>(DNS_SNOOP_QUEUE_CAP);
    // Signalled by the queue thread when its loop dies on a persistent
    // error: the daemon must then shut down (tearing nftables down on the
    // way) rather than keep queueing traffic nobody drains.
    let (fatal_tx, mut fatal_rx) = tokio::sync::mpsc::unbounded_channel::<()>();

    let prompts = Arc::new(PromptTable::new(
        verdict_tx,
        Arc::clone(&events),
        Arc::clone(&counters),
        Arc::clone(&store),
        Duration::from_secs(cfg.prompt_timeout_secs),
        cfg.max_pending_prompts,
        cfg.default_verdict,
    ));

    // DNS snoop consumer: record outbound queries, then only absorb
    // responses that answer one (matching addresses, transaction ID, and
    // question name), so spoofed replies cannot poison the domain cache.
    // The queue thread reads the cache when it builds a Connection.
    let dns_cache = Arc::new(dns::IpDomainCache::new(dns::CACHE_CAPACITY));
    let snoop_cache = Arc::clone(&dns_cache);
    let snoop_stats = Arc::clone(&counters);
    tokio::spawn(async move {
        let tracker = dns::QueryTracker::new(dns::TRACKER_CAPACITY);
        while let Some((tuple, pkt)) = dns_rx.recv().await {
            let Some(payload) = packet::udp_payload(&pkt) else {
                continue;
            };
            if packet::is_dns_response(&tuple) {
                if let Some(resp) = dns::parse_response(payload) {
                    if tracker.validate(tuple.dst, tuple.src, &resp) {
                        tracing::debug!(
                            domain = %resp.query_name,
                            addrs = resp.addrs.len(),
                            "dns response snooped"
                        );
                        snoop_cache.absorb(&resp);
                    } else {
                        snoop_stats.record_dns_spoof_rejected();
                        tracing::debug!(
                            domain = %resp.query_name,
                            from = %tuple.src,
                            "ignoring unsolicited dns response"
                        );
                    }
                }
            } else if packet::is_dns_query(&tuple) {
                if let Some(q) = dns::parse_query(payload) {
                    tracker.observe(tuple.src, tuple.dst, &q);
                }
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

    // Blocking nfqueue loop on its own thread, over the queue bound
    // before the nftables install. None means interception is off for
    // this run (no privileges); rule management still works over IPC.
    let shutdown = Arc::new(AtomicBool::new(false));
    let queue_thread = queue.map(|queue| {
        nfqueue::spawn(
            queue,
            cfg.queue_num,
            nfqueue::QueueDeps {
                attribution: AttributionChain::default_chain(Some(Arc::clone(&dns_cache))),
                rules: Arc::clone(&store),
                events: Arc::clone(&events),
                stats: Arc::clone(&counters),
                prompt_tx,
                verdict_rx,
                dns_tx,
                dns_cache,
                exe_hash: Arc::new(attribution::hash::ExeHashCache::default()),
                unhandled_verdict: cfg.unhandled_proto_verdict,
                shutdown: Arc::clone(&shutdown),
                fatal_tx,
            },
        )
    });

    // IPC server.
    let ipc_deps = Arc::new(ipc::server::IpcDeps {
        store,
        prompts,
        events,
        stats: counters,
    });
    let ipc_task = tokio::spawn(async move {
        if let Err(e) = ipc::server::serve(ipc_listener, ipc_deps).await {
            tracing::error!("IPC server failed: {e}");
        }
    });

    // Wait for SIGTERM, SIGINT, or a fatal queue-loop error.
    let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    let fatal = tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("SIGINT received");
            false
        }
        _ = sigterm.recv() => {
            tracing::info!("SIGTERM received");
            false
        }
        _ = fatal_rx.recv() => {
            tracing::error!("nfqueue loop died, shutting down");
            true
        }
    };

    tracing::info!("shutting down");
    shutdown.store(true, Ordering::Relaxed);
    ipc_task.abort();
    // Same rule as the panic hook: in fail-closed mode the table IS the
    // enforcement, so a daemon dying unexpectedly must leave it standing.
    // Tearing it down here handed an operator who chose queue_bypass = false
    // the opposite of what that setting promises.
    let keep_table_for_enforcement = fatal && !cfg.queue_bypass;
    if nft_installed && !keep_table_for_enforcement {
        nft::teardown();
    } else if keep_table_for_enforcement {
        tracing::warn!("leaving nftables table installed: fail-closed enforcement holds until restart");
    }
    if let Err(e) = std::fs::remove_file(&cfg.socket_path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!("failed to remove socket {}: {e}", cfg.socket_path.display());
        }
    }
    if let Some(t) = queue_thread {
        let _ = t.join();
    }
    tracing::info!("hallpassd stopped");
    // A clean return is exit status 0, which Restart=on-failure ignores. The
    // queue loop dying is a failure and must earn a restart.
    if fatal {
        std::process::exit(1);
    }
}
