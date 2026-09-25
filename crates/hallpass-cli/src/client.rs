//! Daemon connection: handshake, request/response, message streaming.

use std::fmt;
use std::path::Path;

use hallpass_types::wire::{self, WireError};
use hallpass_types::{ClientMsg, DaemonMsg, Lockdown, Rule, RuntimeConfig, PROTOCOL_VERSION};
use tokio::net::UnixStream;

/// Errors surfaced to the user, mapped to exit codes.
#[derive(Debug)]
pub enum CliError {
    /// Could not connect to (or handshake with) the daemon. Exit code 2.
    Connect(String),
    /// The daemon replied with [`DaemonMsg::Err`]. Exit code 1.
    Daemon(String),
    /// The daemon replied with something unexpected. Exit code 1.
    Protocol(String),
    /// Something the operator supplied was unusable: a file that cannot be
    /// read or parsed, or a partly failed import. Exit code 1.
    Input(String),
}

impl CliError {
    /// Exit code for this error.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Connect(_) => crate::EXIT_CONN,
            Self::Daemon(_) | Self::Protocol(_) | Self::Input(_) => crate::EXIT_ERR,
        }
    }

    /// Build a protocol error for an unexpected daemon reply.
    pub fn unexpected(msg: &DaemonMsg) -> Self {
        Self::Protocol(format!("unexpected reply from daemon: {msg:?}"))
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Daemon messages quote rule names and paths, and an import error
        // quotes a file not necessarily written here, so any of these can
        // carry whatever a rule file or a process put there. Sanitizing in
        // Display covers every printer at once instead of trusting each call
        // site to remember.
        use hallpass_types::sanitize_for_display as clean;
        match self {
            Self::Connect(e) => write!(f, "{} - is hallpassd running?", clean(e)),
            Self::Daemon(m) => write!(f, "daemon: {}", clean(m)),
            Self::Protocol(m) | Self::Input(m) => write!(f, "{}", clean(m)),
        }
    }
}

impl From<WireError> for CliError {
    fn from(e: WireError) -> Self {
        // A wire failure mid-conversation means the daemon connection broke.
        Self::Connect(format!("connection to daemon lost: {e}"))
    }
}

/// A connected, handshaken daemon client.
pub struct Client {
    stream: UnixStream,
}

impl Client {
    /// Connect to the daemon socket and perform the Hello handshake.
    pub async fn connect(socket: &Path) -> Result<Self, CliError> {
        let handshake_failed = |e: WireError| CliError::Connect(format!("handshake failed: {e}"));
        let mut stream = UnixStream::connect(socket).await.map_err(|e| {
            CliError::Connect(format!("cannot connect to {}: {e}", socket.display()))
        })?;
        let hello = ClientMsg::Hello {
            version: PROTOCOL_VERSION,
        };
        wire::write_msg(&mut stream, &hello)
            .await
            .map_err(handshake_failed)?;
        match wire::read_msg::<DaemonMsg, _>(&mut stream)
            .await
            .map_err(handshake_failed)?
        {
            // A mismatch is fatal, not a warning. The daemon refuses the
            // connection on its side anyway, so carrying on only produced a
            // second, less clear failure; and where a version does answer,
            // guessing at frames the other end decodes differently is how a
            // client silently misreads policy.
            DaemonMsg::HelloAck { version } if version != PROTOCOL_VERSION => {
                Err(CliError::Connect(format!(
                    "protocol version mismatch: daemon v{version}, client v{PROTOCOL_VERSION}; \
                     the daemon, CLI and UI ship together and must be upgraded together"
                )))
            }
            DaemonMsg::HelloAck { .. } => Ok(Self { stream }),
            DaemonMsg::Err { message } => Err(CliError::Connect(format!(
                "daemon rejected handshake: {message}"
            ))),
            other => Err(CliError::Connect(format!(
                "unexpected handshake reply: {other:?}"
            ))),
        }
    }

    /// Consume the client, returning the underlying stream (for splitting
    /// into concurrent read/write halves).
    pub fn into_stream(self) -> UnixStream {
        self.stream
    }

    /// Send a message to the daemon.
    pub async fn send(&mut self, msg: ClientMsg) -> Result<(), CliError> {
        Ok(wire::write_msg(&mut self.stream, &msg).await?)
    }

    /// Receive the next daemon message.
    pub async fn recv(&mut self) -> Result<DaemonMsg, CliError> {
        Ok(wire::read_msg(&mut self.stream).await?)
    }

    /// Send a request and return the reply. [`DaemonMsg::Err`] becomes
    /// [`CliError::Daemon`].
    pub async fn request(&mut self, msg: ClientMsg) -> Result<DaemonMsg, CliError> {
        self.send(msg).await?;
        match self.recv().await? {
            DaemonMsg::Err { message } => Err(CliError::Daemon(message)),
            reply => Ok(reply),
        }
    }

    /// Send a request whose only success reply is [`DaemonMsg::Ok`].
    pub async fn request_ok(&mut self, msg: ClientMsg) -> Result<(), CliError> {
        match self.request(msg).await? {
            DaemonMsg::Ok => Ok(()),
            other => Err(CliError::unexpected(&other)),
        }
    }

    /// The runtime settings as the operator set them (`ConfigGet`).
    pub async fn config(&mut self) -> Result<RuntimeConfig, CliError> {
        match self.request(ClientMsg::ConfigGet).await? {
            DaemonMsg::Config(cfg) => Ok(cfg),
            other => Err(CliError::unexpected(&other)),
        }
    }

    /// The lockdown posture in force, if any (`LockdownGet`).
    pub async fn lockdown(&mut self) -> Result<Option<Lockdown>, CliError> {
        match self.request(ClientMsg::LockdownGet).await? {
            DaemonMsg::LockdownState(state) => Ok(state),
            other => Err(CliError::unexpected(&other)),
        }
    }

    /// The whole ruleset (`RuleList`).
    pub async fn rules(&mut self) -> Result<Vec<Rule>, CliError> {
        match self.request(ClientMsg::RuleList).await? {
            DaemonMsg::Rules(rules) => Ok(rules),
            other => Err(CliError::unexpected(&other)),
        }
    }
}

/// Read daemon messages on a task of their own and hand them over a channel.
///
/// `read_msg` is not cancel-safe: raced against anything else in a
/// `select!`, a frame arriving across the other branch loses what was
/// already read and the rest of the stream decodes from its middle. Selecting
/// on the returned channel is safe. The task ends after passing on the first
/// read error, or once the receiver is dropped.
pub fn spawn_reader<R>(mut reader: R) -> tokio::sync::mpsc::Receiver<Result<DaemonMsg, WireError>>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    let (tx, rx) = tokio::sync::mpsc::channel(16);
    tokio::spawn(async move {
        loop {
            let msg = wire::read_msg::<DaemonMsg, _>(&mut reader).await;
            let stop = msg.is_err();
            if tx.send(msg).await.is_err() || stop {
                break;
            }
        }
    });
    rx
}
