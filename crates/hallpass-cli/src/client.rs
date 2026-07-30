//! Daemon connection: handshake, request/response, message streaming.

use std::fmt;
use std::path::Path;

use hallpass_types::wire::{self, WireError};
use hallpass_types::{ClientMsg, DaemonMsg, PROTOCOL_VERSION};
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
}

impl CliError {
    /// Exit code for this error.
    pub fn exit_code(&self) -> i32 {
        match self {
            CliError::Connect(_) => crate::EXIT_CONN,
            CliError::Daemon(_) | CliError::Protocol(_) => crate::EXIT_ERR,
        }
    }

    /// Build a protocol error for an unexpected daemon reply.
    pub fn unexpected(msg: &DaemonMsg) -> Self {
        CliError::Protocol(format!("unexpected reply from daemon: {msg:?}"))
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Daemon messages quote rule names and paths, so they can carry
        // whatever a rule file or a process put there. Sanitizing in Display
        // covers every printer of these errors at once, rather than relying on
        // each call site to remember (watch.rs did; the plain command paths in
        // lib.rs did not).
        use hallpass_types::sanitize_for_display as clean;
        match self {
            CliError::Connect(e) => write!(f, "{} - is hallpassd running?", clean(e)),
            CliError::Daemon(m) => write!(f, "daemon: {}", clean(m)),
            CliError::Protocol(m) => write!(f, "{}", clean(m)),
        }
    }
}

impl From<WireError> for CliError {
    fn from(e: WireError) -> Self {
        // A wire failure mid-conversation means the daemon connection broke.
        CliError::Connect(format!("connection to daemon lost: {e}"))
    }
}

/// A connected, handshaken daemon client.
pub struct Client {
    stream: UnixStream,
}

impl Client {
    /// Connect to the daemon socket and perform the Hello handshake.
    pub async fn connect(socket: &Path) -> Result<Self, CliError> {
        let mut stream = UnixStream::connect(socket).await.map_err(|e| {
            CliError::Connect(format!("cannot connect to {}: {e}", socket.display()))
        })?;
        wire::write_msg(
            &mut stream,
            &ClientMsg::Hello {
                version: PROTOCOL_VERSION,
            },
        )
        .await
        .map_err(|e| CliError::Connect(format!("handshake failed: {e}")))?;
        match wire::read_msg::<DaemonMsg, _>(&mut stream)
            .await
            .map_err(|e| CliError::Connect(format!("handshake failed: {e}")))?
        {
            DaemonMsg::HelloAck { version } => {
                if version != PROTOCOL_VERSION {
                    eprintln!(
                        "warning: daemon protocol v{version}, client v{PROTOCOL_VERSION}"
                    );
                }
                Ok(Client { stream })
            }
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
}
