//! A stand-in daemon that raises prompts, for trying the GUI by hand.
//!
//! `cargo xtask dev` runs the real daemon but fabricates connections, not
//! prompts, and the live one needs root. This speaks the wire protocol on a
//! scratch socket and answers just enough for the agent and the management
//! window: the handshake, the prompt slot, stats, config and empty lists.
//! Every `--every` seconds (default 20) it raises a batch of prompts: three
//! from one program, one from a packaged app, one unattributed. Answers are
//! printed; a prompt nobody answers expires on its deadline like the real
//! one.
//!
//! ```text
//! cargo run -p hallpass-ui --example demo_daemon -- [--socket PATH] [--every SECS]
//! cargo run -p hallpass-ui -- agent --socket PATH
//! ```
//!
//! The agent refuses to start next to an installed one (one per user);
//! quit that one from its tray first.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hallpass_types::wire::{read_msg, write_msg};
use hallpass_types::{
    ClientMsg, Connection, DaemonMsg, FirstSeen, FlowTuple, PromptContext, Proto, RuntimeConfig,
    Stats, Verdict, PROTOCOL_VERSION,
};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;

/// How long a prompt waits before its default verdict, as the daemon's
/// default `prompt_timeout_secs`.
const TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Default)]
struct State {
    /// The prompt handler's outbound channel, if a client holds the slot.
    handler: Option<mpsc::UnboundedSender<DaemonMsg>>,
    /// Pending prompts, re-delivered to a handler that claims the slot.
    pending: BTreeMap<u64, DaemonMsg>,
    next_id: u64,
}

type Shared = Arc<Mutex<State>>;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut args = std::env::args().skip(1);
    let mut socket = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("hallpass-demo.sock");
    let mut every = 20u64;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--socket" => socket = args.next().expect("--socket PATH").into(),
            "--every" => {
                every = args
                    .next()
                    .and_then(|s| s.parse().ok())
                    .expect("--every SECS")
            }
            other => panic!("unknown argument: {other}"),
        }
    }
    let _ = std::fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket).expect("binding the demo socket");
    println!("demo daemon on {}", socket.display());
    println!(
        "  cargo run -p hallpass-ui -- agent --socket {}",
        socket.display()
    );
    println!(
        "  cargo run -p hallpass-ui -- --socket {}",
        socket.display()
    );

    let state = Shared::default();
    tokio::spawn(raise_batches(
        Arc::clone(&state),
        Duration::from_secs(every),
    ));
    loop {
        let (stream, _) = listener.accept().await.expect("accept");
        tokio::spawn(serve(stream, Arc::clone(&state)));
    }
}

/// Raise a batch as soon as a handler holds the slot, then every `every`
/// while one does.
async fn raise_batches(state: Shared, every: Duration) {
    let mut last: Option<std::time::Instant> = None;
    loop {
        let has_handler = state.lock().unwrap().handler.is_some();
        if has_handler && last.is_none_or(|t| t.elapsed() >= every) {
            last = Some(std::time::Instant::now());
            let batch = [
                (Some("/usr/bin/curl"), None, "93.184.216.34:443", false),
                (Some("/usr/bin/curl"), None, "93.184.216.35:443", false),
                (Some("/usr/bin/curl"), None, "1.1.1.1:53", false),
                (
                    Some("/app/bin/browser"),
                    Some("flatpak:org.example.Browser"),
                    "151.101.1.69:443",
                    true,
                ),
                (None, None, "203.0.113.9:8080", false),
            ];
            for (exe, app_id, dst, new) in batch {
                raise(&state, exe, app_id, dst, new);
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

fn raise(state: &Shared, exe: Option<&str>, app_id: Option<&str>, dst: &str, new: bool) {
    let mut st = state.lock().unwrap();
    st.next_id += 1;
    let id = st.next_id;
    let deadline_ms = hallpass_types::unix_ms_now() + TIMEOUT.as_millis() as u64;
    let msg = DaemonMsg::PromptRequest {
        id,
        conn: Connection {
            tuple: FlowTuple {
                proto: Proto::Tcp,
                src: "10.0.0.2:50000".parse().unwrap(),
                dst: dst.parse().unwrap(),
            },
            uid: Some(1000),
            pid: Some(4000 + id as u32),
            exe_path: exe.map(PathBuf::from),
            cmdline: exe.map(|e| format!("{e} --demo")),
            parent_exe: None,
            domain: None,
            iface: None,
            app_id: app_id.map(String::from),
            first_seen: new.then_some(FirstSeen {
                app: true,
                dest: true,
            }),
        },
        deadline_ms,
        context: PromptContext::default(),
    };
    st.pending.insert(id, msg.clone());
    if let Some(handler) = &st.handler {
        let _ = handler.send(msg);
    }
    drop(st);
    let state = Arc::clone(state);
    tokio::spawn(async move {
        tokio::time::sleep(TIMEOUT).await;
        let mut st = state.lock().unwrap();
        if st.pending.remove(&id).is_some() {
            println!("prompt {id}: expired, default verdict");
            if let Some(handler) = &st.handler {
                let _ = handler.send(DaemonMsg::PromptExpired { id });
            }
        }
    });
}

async fn serve(stream: UnixStream, state: Shared) {
    let (mut reader, mut writer) = stream.into_split();
    let (tx, mut rx) = mpsc::unbounded_channel::<DaemonMsg>();
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if write_msg(&mut writer, &msg).await.is_err() {
                break;
            }
        }
    });
    while let Ok(msg) = read_msg::<ClientMsg, _>(&mut reader).await {
        let reply = handle(msg, &tx, &state);
        if let Some(reply) = reply {
            let _ = tx.send(reply);
        }
    }
    let mut st = state.lock().unwrap();
    if st.handler.as_ref().is_some_and(|h| h.same_channel(&tx)) {
        st.handler = None;
        println!("prompt handler disconnected");
    }
}

fn handle(
    msg: ClientMsg,
    tx: &mpsc::UnboundedSender<DaemonMsg>,
    state: &Shared,
) -> Option<DaemonMsg> {
    let mut st = state.lock().unwrap();
    Some(match msg {
        ClientMsg::Hello { .. } => DaemonMsg::HelloAck {
            version: PROTOCOL_VERSION,
        },
        ClientMsg::Subscribe { prompts: false, .. } => DaemonMsg::Ok,
        ClientMsg::Subscribe { prompts: true, .. } => match &st.handler {
            Some(h) if !h.is_closed() => DaemonMsg::Err {
                message: "a prompt handler is already connected".into(),
            },
            _ => {
                println!("prompt handler connected");
                // The Ok first, then the re-delivery, as the daemon orders it.
                let _ = tx.send(DaemonMsg::Ok);
                for msg in st.pending.values() {
                    let _ = tx.send(msg.clone());
                }
                st.handler = Some(tx.clone());
                return None;
            }
        },
        ClientMsg::PromptReply {
            id,
            verdict,
            duration,
            scope,
            pin_exe,
        } => {
            let is_handler = st.handler.as_ref().is_some_and(|h| h.same_channel(tx));
            if !is_handler || st.pending.remove(&id).is_none() {
                return Some(DaemonMsg::Err {
                    message: format!("no pending prompt {id} for this client"),
                });
            }
            println!("prompt {id}: {verdict:?} {duration:?} {scope:?} pin={pin_exe}");
            DaemonMsg::Ok
        }
        ClientMsg::Stats => DaemonMsg::Stats(Stats {
            enforcing: true,
            prompt_handler_connected: st.handler.as_ref().is_some_and(|h| !h.is_closed()),
            ..Stats::default()
        }),
        ClientMsg::ConfigGet => DaemonMsg::Config(RuntimeConfig {
            prompt_timeout_secs: TIMEOUT.as_secs(),
            default_verdict: Verdict::Deny,
            enforce: true,
        }),
        ClientMsg::RuleList => DaemonMsg::Rules(Vec::new()),
        ClientMsg::EventHistory { .. } => DaemonMsg::Events(Vec::new()),
        ClientMsg::RuleStats => DaemonMsg::RuleHits(Vec::new()),
        ClientMsg::LockdownGet => DaemonMsg::LockdownState(None),
        other => DaemonMsg::Err {
            message: format!("the demo daemon does not do {other:?}"),
        },
    })
}
