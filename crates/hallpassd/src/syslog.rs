//! Event export to syslog: local datagram socket or a remote collector.
//!
//! A plain [`EventBus`] subscriber, so export never sits on the packet
//! path: a stalled or unreachable collector costs events (the broadcast
//! channel lags), never verdicts. Messages are RFC 5424 frames whose
//! structured data carries the decision fields, or raw JSON for
//! collectors that prefer to parse the payload themselves.

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hallpass_types::ConnEvent;
use serde::Deserialize;
use tokio::net::{UdpSocket, UnixDatagram};

use crate::events::EventBus;

/// Where exported events go.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum SyslogTarget {
    /// Local syslog datagram socket (`/dev/log` by default).
    Local {
        /// Socket path.
        #[serde(default = "default_socket")]
        path: PathBuf,
    },
    /// Remote collector over UDP.
    Udp {
        /// `host:port` of the collector.
        addr: String,
    },
}

fn default_socket() -> PathBuf {
    PathBuf::from("/dev/log")
}

/// Wire format of exported events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SyslogFormat {
    /// RFC 5424 with the decision in structured data.
    #[default]
    Rfc5424,
    /// RFC 5424 header with a JSON object as the message.
    Json,
}

/// Event export configuration. Absent from the config file means no
/// export at all.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyslogConfig {
    /// Destination.
    pub target: SyslogTarget,
    /// Message format.
    #[serde(default)]
    pub format: SyslogFormat,
}

/// Facility 4 (security/authorization). Distro syslog configs route this
/// to auth.log rather than the general syslog file.
const FACILITY: u8 = 4;
/// Severity 6 (informational) for allowed connections.
const SEVERITY_INFO: u8 = 6;
/// Severity 4 (warning) for denied/rejected ones, so a collector can
/// prioritize blocks without parsing the payload.
const SEVERITY_WARNING: u8 = 4;

/// IANA reserved-for-documentation Private Enterprise Number. RFC 5424
/// requires an enterprise-scoped SD-ID; replace this if hallpass ever
/// registers its own PEN.
const SD_ID: &str = "hallpass@32473";

/// Per-field cap in characters. `cmdline` in particular is unbounded and
/// process-controlled, and an oversized datagram is silently dropped by
/// UDP collectors (and truncated mid-field by local syslogd), so a
/// hostile command line must not be able to push the frame past what a
/// collector accepts. Truncated values end in an ellipsis.
const MAX_FIELD_CHARS: usize = 200;

/// Which escaping rules a field value is written under.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Escape {
    /// RFC 5424 PARAM-VALUE: `"`, `\`, `]`.
    Sd,
    /// JSON string literal.
    Json,
}

/// Escaping, control-character-neutralizing, truncating sink for one
/// field value. Values reach syslog through this and nothing else: they
/// are process- or network-controlled, and a raw newline would end the
/// frame and let the rest be read as a second, forged record.
struct FieldWriter<'a> {
    out: &'a mut String,
    escape: Escape,
    remaining: usize,
    truncated: bool,
}

impl<'a> FieldWriter<'a> {
    fn new(out: &'a mut String, escape: Escape) -> FieldWriter<'a> {
        FieldWriter {
            out,
            escape,
            remaining: MAX_FIELD_CHARS,
            truncated: false,
        }
    }

    fn finish(self) {
        if self.truncated {
            self.out.push_str("...");
        }
    }
}

impl std::fmt::Write for FieldWriter<'_> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        for c in s.chars() {
            if self.remaining == 0 {
                self.truncated = true;
                return Ok(());
            }
            self.remaining -= 1;
            // Control characters (and DEL) are never emitted literally in
            // either format: in structured data they would break framing.
            if (c as u32) < 0x20 || c as u32 == 0x7f {
                match self.escape {
                    Escape::Sd => {
                        // rsyslog's own convention for an escaped byte.
                        let _ = write!(self.out, "#{:03o}", c as u32);
                    }
                    Escape::Json => {
                        let _ = write!(self.out, "\\u{:04x}", c as u32);
                    }
                }
                continue;
            }
            match (self.escape, c) {
                (Escape::Sd, '"' | '\\' | ']') => {
                    self.out.push('\\');
                    self.out.push(c);
                }
                (Escape::Json, '"') => self.out.push_str("\\\""),
                (Escape::Json, '\\') => self.out.push_str("\\\\"),
                _ => self.out.push(c),
            }
        }
        Ok(())
    }
}

/// Visit the decision fields of an event in order. Values are passed as
/// `Display` so the writer can escape them streaming, with no
/// intermediate `String` per field.
fn for_each_field(ev: &ConnEvent, mut visit: impl FnMut(&'static str, &dyn std::fmt::Display)) {
    let c = &ev.conn;
    visit("verdict", &ev.verdict.as_str());
    // Only emitted in observe mode, and deliberately not folded into
    // `verdict`: a collector matching verdict="deny" keeps working, and a
    // line without this field means the verdict was applied. Silently
    // exporting an unenforced deny as a plain deny would put blocks that
    // never happened into an audit trail.
    if !ev.enforced {
        visit("enforced", &"false");
    }
    visit("proto", &c.tuple.proto);
    visit("src", &c.tuple.src);
    visit("dst", &c.tuple.dst);
    if let Some(rule) = &ev.rule_name {
        visit("rule", rule);
    }
    if let Some(exe) = &c.exe_path {
        visit("exe", &exe.display());
    }
    if let Some(cmdline) = &c.cmdline {
        visit("cmdline", cmdline);
    }
    if let Some(domain) = &c.domain {
        visit("domain", domain);
    }
    if let Some(iface) = &c.iface {
        visit("iface", iface);
    }
    if let Some(app_id) = &c.app_id {
        visit("app_id", app_id);
    }
    // Same vocabulary as the CLI's `new=` field, and absent for the same two
    // different reasons a line can lack any other field here: nothing was
    // new, or the daemon is not tracking. A collector cannot tell those
    // apart, which is why "first_seen" is worth alerting on and its absence
    // is worth nothing.
    //
    // Alert on it, but do not treat it as a complete record of first
    // contacts. Exactly one event per (application, destination) ever
    // carries it - the store records while it reports - and export is an
    // ordinary event subscriber: a lagging broadcast, an unreachable
    // collector or a send timeout drops that event like any other, and
    // nothing re-sends it, because by then the pair is no longer new. What
    // is lost is the annotation, never the event's verdict.
    if let Some(tag) = c.first_seen.and_then(|f| f.tag()) {
        visit("first_seen", &tag);
    }
    if let Some(pid) = c.pid {
        visit("pid", &pid);
    }
    if let Some(uid) = c.uid {
        visit("uid", &uid);
    }
}

/// Render one event as a syslog line (no trailing newline).
pub fn format_event(ev: &ConnEvent, format: SyslogFormat, hostname: &str, pid: u32) -> String {
    let severity = match ev.verdict {
        hallpass_types::Verdict::Allow => SEVERITY_INFO,
        hallpass_types::Verdict::Deny | hallpass_types::Verdict::Reject => SEVERITY_WARNING,
    };
    let prival = FACILITY * 8 + severity;
    // RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID ...
    let ts = hallpass_types::format_rfc3339(ev.unix_ms);
    let mut out = format!("<{prival}>1 {ts} {hostname} hallpassd {pid} conn ");
    match format {
        SyslogFormat::Rfc5424 => {
            out.push('[');
            out.push_str(SD_ID);
            for_each_field(ev, |k, v| {
                let _ = write!(out, " {k}=\"");
                let mut w = FieldWriter::new(&mut out, Escape::Sd);
                let _ = write!(w, "{v}");
                w.finish();
                out.push('"');
            });
            out.push(']');
        }
        SyslogFormat::Json => {
            // RFC 5424 wants a BOM before a UTF-8 MSG.
            out.push_str("- \u{feff}{");
            let mut first = true;
            for_each_field(ev, |k, v| {
                if !first {
                    out.push(',');
                }
                first = false;
                let _ = write!(out, "\"{k}\":\"");
                let mut w = FieldWriter::new(&mut out, Escape::Json);
                let _ = write!(w, "{v}");
                w.finish();
                out.push('"');
            });
            let _ = write!(out, ",\"unix_ms\":{}", ev.unix_ms);
            out.push('}');
        }
    }
    out
}

/// An opened syslog destination.
enum Sink {
    Unix { sock: UnixDatagram, path: PathBuf },
    Udp { sock: UdpSocket, addr: SocketAddr },
}

/// Mark the export socket so the ruleset lets its datagrams past the
/// verdict queue; see [`crate::nft::EXPORT_MARK`] for the loop this closes.
///
/// A failure costs the exemption, not the export, so it warns rather than
/// refusing to start: SO_MARK needs CAP_NET_ADMIN, which a development run
/// as an ordinary user does not have, and such a run has no nftables table
/// to be exempted from either.
fn mark_exempt(sock: &UdpSocket) {
    if let Err(e) = socket2::SockRef::from(sock).set_mark(crate::nft::EXPORT_MARK) {
        tracing::warn!(
            "could not mark the syslog export socket; its datagrams will be \
             filtered like any other traffic, and each one exported will \
             produce another event: {e}"
        );
        return;
    }
    // The exemption rule also requires the socket to be root-owned, so
    // setting the mark is only half of it. A daemon running non-root with
    // CAP_NET_ADMIN granted (an ambient capability in a modified unit) marks
    // the socket successfully and still gets filtered, which would bring the
    // loop back with nothing in the log to explain it.
    if crate::rules::store::effective_uid() != Some(0) {
        tracing::warn!(
            "syslog export socket marked, but this daemon is not root and the \
             exemption rule requires a root-owned socket: export datagrams will \
             be filtered, and each exported event will produce another"
        );
    }
}

impl Sink {
    async fn open(target: &SyslogTarget) -> Result<Sink, String> {
        match target {
            SyslogTarget::Local { path } => {
                let sock = UnixDatagram::unbound().map_err(|e| format!("unix socket: {e}"))?;
                // Connect is deferred to send time: /dev/log may not exist
                // yet at startup, and syslogd restarts recreate it.
                Ok(Sink::Unix {
                    sock,
                    path: path.clone(),
                })
            }
            SyslogTarget::Udp { addr } => {
                let addr: SocketAddr = addr
                    .parse()
                    .map_err(|e| format!("bad syslog address {addr:?}: {e}"))?;
                let bind = if addr.is_ipv4() {
                    "0.0.0.0:0"
                } else {
                    "[::]:0"
                };
                let sock = UdpSocket::bind(bind)
                    .await
                    .map_err(|e| format!("udp socket: {e}"))?;
                mark_exempt(&sock);
                Ok(Sink::Udp { sock, addr })
            }
        }
    }

    async fn send(&self, line: &str) -> std::io::Result<()> {
        match self {
            Sink::Unix { sock, path } => sock.send_to(line.as_bytes(), path).await.map(|_| ()),
            Sink::Udp { sock, addr } => sock.send_to(line.as_bytes(), addr).await.map(|_| ()),
        }
    }
}

/// A stalled peer must not park the export task forever: a local syslogd
/// with a full receive queue can leave a datagram send pending.
const SEND_TIMEOUT: Duration = Duration::from_secs(2);

/// How long to stay quiet between reports while sends keep failing. A
/// broken sink is reported periodically (with a running drop count)
/// rather than once, so "export active" never silently means "exporting
/// nothing", and never floods the daemon's own log either.
const FAILURE_REPORT_INTERVAL: Duration = Duration::from_secs(60);

/// Subscribe to `events` and export each decision to syslog.
pub fn spawn(events: Arc<EventBus>, cfg: SyslogConfig) {
    tokio::spawn(async move {
        let sink = match Sink::open(&cfg.target).await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("syslog export disabled: {e}");
                return;
            }
        };
        let hostname = hostname();
        let pid = std::process::id();
        let mut rx = events.subscribe();
        let mut dropped: u64 = 0;
        let mut last_report: Option<Instant> = None;
        tracing::info!(?cfg.target, ?cfg.format, "syslog export active");
        loop {
            match rx.recv().await {
                Ok(ev) => {
                    let line = format_event(&ev, cfg.format, &hostname, pid);
                    let sent = match tokio::time::timeout(SEND_TIMEOUT, sink.send(&line)).await {
                        Ok(Ok(())) => Ok(()),
                        Ok(Err(e)) => Err(e.to_string()),
                        Err(_) => Err("send timed out".to_string()),
                    };
                    match sent {
                        Ok(()) => {
                            if dropped > 0 {
                                tracing::info!(dropped, "syslog export recovered");
                                dropped = 0;
                                last_report = None;
                            }
                        }
                        Err(e) => {
                            dropped += 1;
                            let due =
                                last_report.is_none_or(|t| t.elapsed() >= FAILURE_REPORT_INTERVAL);
                            if due {
                                last_report = Some(Instant::now());
                                tracing::warn!(dropped, "syslog send failing: {e}");
                            }
                        }
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(dropped = n, "syslog export lagged");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
            }
        }
    });
}

/// Hostname for the syslog header, or "-" (RFC 5424 nil) if unknown.
fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty() && h.len() <= 255 && h.bytes().all(|b| b > b' ' && b < 0x7f))
        .unwrap_or_else(|| "-".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hallpass_types::{Connection, FlowTuple, Proto, Verdict};
    use std::path::PathBuf;

    fn event() -> ConnEvent {
        ConnEvent {
            conn: Connection {
                tuple: FlowTuple {
                    proto: Proto::Tcp,
                    src: "10.0.0.1:40000".parse().unwrap(),
                    dst: "93.184.216.34:443".parse().unwrap(),
                },
                uid: Some(1000),
                pid: Some(4242),
                exe_path: Some(PathBuf::from("/usr/bin/curl")),
                cmdline: Some("curl https://example.org".into()),
                parent_exe: None,
                domain: Some("example.org".into()),
                iface: Some("eth0".into()),
                app_id: None,
                first_seen: None,
            },
            verdict: Verdict::Deny,
            rule_name: Some("block-example".into()),
            unix_ms: 1_720_000_000_123,
            enforced: true,
        }
    }

    #[test]
    fn rfc5424_frame() {
        let line = format_event(&event(), SyslogFormat::Rfc5424, "box", 7);
        // Deny maps to facility 4, severity 4 (warning): 4 * 8 + 4.
        assert!(line.starts_with("<36>1 2024-07-03T09:46:40.123Z box hallpassd 7 conn "));
        assert!(line.contains(r#"[hallpass@32473 verdict="deny""#));
        assert!(line.contains(r#"dst="93.184.216.34:443""#));
        assert!(line.contains(r#"rule="block-example""#));
        assert!(line.contains(r#"domain="example.org""#));
        assert!(line.ends_with(']'));

        // Allowed connections are informational: 4 * 8 + 6.
        let mut allowed = event();
        allowed.verdict = Verdict::Allow;
        assert!(format_event(&allowed, SyslogFormat::Rfc5424, "box", 7).starts_with("<38>1 "));
    }

    #[test]
    fn json_frame_and_escaping() {
        let mut ev = event();
        ev.conn.cmdline = Some("curl \"a\"\nb\\c".into());
        let line = format_event(&ev, SyslogFormat::Json, "box", 7);
        let json = line.split_once("conn - \u{feff}").unwrap().1;
        assert!(json.starts_with('{') && json.ends_with('}'));
        // Quote and backslash escaped; the newline becomes an escape
        // sequence rather than a byte that could split the frame.
        assert!(json.contains(r#""cmdline":"curl \"a\"\u000ab\\c""#));
        assert!(json.contains(r#""unix_ms":1720000000123"#));
    }

    #[test]
    fn structured_data_escaping() {
        let mut ev = event();
        ev.rule_name = Some(r#"we"ird]\rule"#.into());
        let line = format_event(&ev, SyslogFormat::Rfc5424, "box", 7);
        assert!(line.contains(r#"rule="we\"ird\]\\rule""#));
    }

    #[test]
    fn control_characters_cannot_forge_a_second_record() {
        // A process controls its own argv, and a hostile DNS answer
        // controls the domain: neither may inject a frame separator.
        let forged = "x\n<38>1 2024-07-03T09:46:40.000Z box hallpassd 1 conn \
                      [hallpass@32473 verdict=\"allow\"]";
        for format in [SyslogFormat::Rfc5424, SyslogFormat::Json] {
            let mut ev = event();
            ev.conn.cmdline = Some(forged.to_string());
            ev.conn.domain = Some("evil\r\nexample.org".to_string());
            let line = format_event(&ev, format, "box", 7);
            // The frame separator is what matters: a record that cannot
            // be split cannot be forged, whatever the payload spells.
            assert!(!line.contains('\n'), "newline survived into {format:?}");
            assert!(
                !line.contains('\r'),
                "carriage return survived into {format:?}"
            );
            // The forged text survives as inert payload inside the quoted
            // value; without a separator no parser can read it as its own
            // record, and the real frame header appears exactly once.
            assert_eq!(line.matches("hallpassd 7 conn").count(), 1);
            assert!(line.starts_with("<36>1 "));
        }
    }

    #[test]
    fn long_fields_are_truncated() {
        let mut ev = event();
        ev.conn.cmdline = Some("A".repeat(100_000));
        for format in [SyslogFormat::Rfc5424, SyslogFormat::Json] {
            let line = format_event(&ev, format, "box", 7);
            assert!(line.contains(&"A".repeat(MAX_FIELD_CHARS)));
            assert!(!line.contains(&"A".repeat(MAX_FIELD_CHARS + 1)));
            assert!(line.contains("..."));
            // Comfortably inside what a UDP collector must accept.
            assert!(
                line.len() < 2048,
                "{format:?} frame too large: {}",
                line.len()
            );
        }
    }

    #[test]
    fn absent_fields_are_omitted() {
        let mut ev = event();
        ev.conn.exe_path = None;
        ev.conn.domain = None;
        ev.rule_name = None;
        let line = format_event(&ev, SyslogFormat::Rfc5424, "box", 7);
        assert!(!line.contains("exe="));
        assert!(!line.contains("domain="));
        assert!(!line.contains("rule="));
        assert!(line.contains(r#"verdict="deny""#));
    }

    #[test]
    fn config_parsing() {
        let local: SyslogConfig = toml::from_str("[target]\nkind = \"local\"\n").unwrap();
        assert_eq!(
            local.target,
            SyslogTarget::Local {
                path: PathBuf::from("/dev/log")
            }
        );
        assert_eq!(local.format, SyslogFormat::Rfc5424);

        let remote: SyslogConfig = toml::from_str(
            "format = \"json\"\n[target]\nkind = \"udp\"\naddr = \"10.0.0.9:514\"\n",
        )
        .unwrap();
        assert_eq!(
            remote.target,
            SyslogTarget::Udp {
                addr: "10.0.0.9:514".into()
            }
        );
        assert_eq!(remote.format, SyslogFormat::Json);

        assert!(toml::from_str::<SyslogConfig>("[target]\nkind = \"carrier-pigeon\"\n").is_err());
    }

    #[tokio::test]
    async fn unix_sink_delivers_to_a_listening_socket() {
        let dir = crate::testutil::TestDir::new("syslog");
        let path = dir.path().join("log.sock");
        let server = UnixDatagram::bind(&path).unwrap();
        let sink = Sink::open(&SyslogTarget::Local { path: path.clone() })
            .await
            .unwrap();
        sink.send("<38>1 hello").await.unwrap();
        let mut buf = [0u8; 128];
        let n = server.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"<38>1 hello");
    }

    #[tokio::test]
    async fn bad_udp_address_is_an_error() {
        assert!(Sink::open(&SyslogTarget::Udp {
            addr: "not-an-address".into()
        })
        .await
        .is_err());
    }
}
