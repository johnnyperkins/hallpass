//! Desktop notifications for prompt arrivals.
//!
//! A prompt window cannot interrupt an operator who is working in
//! another application: it takes a process start to appear, and the
//! compositor decides whether a new window gets focus or stays on top at
//! all (on Wayland, never on top). A desktop notification is the
//! platform's sanctioned interrupt: it renders over whatever is focused,
//! immediately, from any thread. So this module runs on its own thread in
//! the agent and hears about prompts straight from the network thread.
//!
//! Its state derives from the message streams alone: an inbound
//! `PromptRequest` opens or updates a banner, an inbound `PromptExpired`
//! or an outbound `PromptReply` retires the id, and a disconnect retires
//! everything (the daemon re-issues surviving prompts on reconnect).
//! Deriving from the streams rather than sharing the agent's router keeps
//! this from becoming one more hand-synced copy of "what is pending".
//!
//! Deliberately absent: Allow/Deny actions on the banner. A verdict
//! deserves the full context the prompt window shows (path, command line,
//! the pending list), not a decision made from a two-line banner that the
//! lock screen may also display.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc::Receiver;

use hallpass_types::Connection;

use crate::prompt;

/// What the network thread tells the notifier.
#[derive(Debug)]
pub enum NotifyEvent {
    /// A prompt was requested (or re-delivered) by the daemon.
    Request {
        id: u64,
        /// Boxed: a `Connection` is an order of magnitude larger than
        /// the other variants, and every event rides a channel by value.
        conn: Box<Connection>,
        deadline_ms: u64,
    },
    /// A prompt is no longer pending: expired, swept by a covering rule,
    /// or answered by this client (the reply left the outgoing queue).
    Gone { id: u64 },
    /// The daemon connection is gone; every pending prompt died with it.
    Disconnected,
}

/// Most application groups with a live banner at once. The daemon's
/// pending-prompt table is the real bound; this is a local backstop so a
/// misbehaving stream cannot grow the map. Past the cap a new group gets
/// no banner, which costs awareness of that group only, never a verdict:
/// the prompt still goes to its window.
const MAX_BANNER_GROUPS: usize = 64;

/// One banner per application, keyed as the prompt windows are
/// (executable, application id): a browser at startup is one banner with a
/// count, not a stack, and two packaged applications running one path are
/// two banners, as they are two windows. Unattributed prompts are not
/// grouped, for the same reason their windows are not: two unattributed
/// programs are not "the same app".
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Key {
    App(PathBuf, Option<String>),
    Anon(u64),
}

impl Key {
    fn of(conn: &Connection, id: u64) -> Key {
        match &conn.exe_path {
            Some(exe) => Key::App(exe.clone(), conn.app_id.clone()),
            None => Key::Anon(id),
        }
    }
}

/// Where banners actually go. The real implementation talks DBus; tests
/// substitute a recorder, because CI has no notification daemon.
trait Sink {
    type Handle;
    fn show(&mut self, summary: &str, body: &str, timeout_ms: u32) -> Option<Self::Handle>;
    fn update(&mut self, handle: &mut Self::Handle, summary: &str, body: &str, timeout_ms: u32);
    fn close(&mut self, handle: Self::Handle);
}

/// One pending prompt as the banner needs it.
struct Entry {
    id: u64,
    conn: Connection,
    deadline_ms: u64,
}

struct Group<H> {
    entries: Vec<Entry>,
    /// None when the sink refused to show (no daemon, cap hit at show
    /// time): the group is still tracked so a later retire is a no-op
    /// rather than a mismatch.
    banner: Option<H>,
}

/// The stream-derived banner state.
struct Tracker<S: Sink> {
    sink: S,
    groups: HashMap<Key, Group<S::Handle>>,
}

/// GNOME renders a small HTML subset in notification bodies, so a domain
/// or path containing markup would restyle the text the operator reads.
/// Escaped after sanitization: `sanitize_for_display` strips control and
/// bidi hazards but deliberately leaves printable ASCII alone.
fn escape_markup(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Banner text for a group: newest last, the front prompt named, the
/// rest counted. Every field is chosen by the process being judged, so
/// everything goes through the same sanitizers the prompt window uses,
/// plus the markup escape.
fn banner_text(entries: &[Entry]) -> (String, String) {
    let front = &entries[0];
    let name = escape_markup(&prompt::exe_name(&front.conn));
    let dest = escape_markup(&prompt::format_dest(&front.conn));
    // The summary is the line a banner shows when nothing else fits, and it
    // is the same six words for every prompt. Saying that this one is from
    // an application (or to a destination) never seen here is the one thing
    // that distinguishes a prompt worth walking back to the keyboard for.
    //
    // Across the whole group, not just the front entry: a group is keyed on
    // the application, not the destination, so a prompt for a destination
    // this program has never reached coalesces behind a routine one from
    // the same program. Reading only the front would drop the marker for
    // exactly the prompt that earned it, in the one situation the banner
    // exists for - the operator is not looking at the screen.
    let anything_new = entries
        .iter()
        .any(|e| e.conn.first_seen.and_then(|f| f.tag()).is_some());
    let summary = if anything_new {
        "Connection request (NEW)"
    } else {
        "Connection request"
    }
    .to_string();
    let body = if entries.len() == 1 {
        format!("{name} wants to connect to {dest}")
    } else {
        format!(
            "{name} wants to connect to {dest} ({} more pending)",
            entries.len() - 1
        )
    };
    (summary, body)
}

/// Milliseconds until the last deadline in the group, so the banner
/// retires itself with the prompts even if every close signal is lost.
fn remaining_ms(entries: &[Entry], now_ms: u64) -> u32 {
    let last = entries.iter().map(|e| e.deadline_ms).max().unwrap_or(0);
    last.saturating_sub(now_ms).min(u32::MAX as u64).max(1_000) as u32
}

impl<S: Sink> Tracker<S> {
    fn new(sink: S) -> Self {
        Tracker {
            sink,
            groups: HashMap::new(),
        }
    }

    fn handle(&mut self, event: NotifyEvent, now_ms: u64) {
        match event {
            NotifyEvent::Request {
                id,
                conn,
                deadline_ms,
            } => self.request(id, *conn, deadline_ms, now_ms),
            NotifyEvent::Gone { id } => self.gone(id, now_ms),
            NotifyEvent::Disconnected => self.clear(),
        }
    }

    fn request(&mut self, id: u64, conn: Connection, deadline_ms: u64, now_ms: u64) {
        let key = Key::of(&conn, id);
        if !self.groups.contains_key(&key) && self.groups.len() >= MAX_BANNER_GROUPS {
            tracing::warn!(
                "banner group cap reached; not raising a notification (the prompt window is unaffected)"
            );
            return;
        }
        let group = self.groups.entry(key).or_insert_with(|| Group {
            entries: Vec::new(),
            banner: None,
        });
        // The daemon re-delivers pending prompts to a reconnecting
        // handler; a duplicate must not inflate the count.
        if group.entries.iter().any(|e| e.id == id) {
            return;
        }
        group.entries.push(Entry {
            id,
            conn,
            deadline_ms,
        });
        let (summary, body) = banner_text(&group.entries);
        let timeout = remaining_ms(&group.entries, now_ms);
        match group.banner.as_mut() {
            Some(handle) => self.sink.update(handle, &summary, &body, timeout),
            None => group.banner = self.sink.show(&summary, &body, timeout),
        }
    }

    fn gone(&mut self, id: u64, now_ms: u64) {
        let Some(key) = self
            .groups
            .iter()
            .find(|(_, g)| g.entries.iter().any(|e| e.id == id))
            .map(|(k, _)| k.clone())
        else {
            return; // answered before this client connected, or never shown
        };
        let group = self.groups.get_mut(&key).expect("key from this map");
        group.entries.retain(|e| e.id != id);
        if group.entries.is_empty() {
            let group = self.groups.remove(&key).expect("key from this map");
            if let Some(handle) = group.banner {
                self.sink.close(handle);
            }
        } else {
            let (summary, body) = banner_text(&group.entries);
            let timeout = remaining_ms(&group.entries, now_ms);
            if let Some(handle) = group.banner.as_mut() {
                self.sink.update(handle, &summary, &body, timeout);
            }
        }
    }

    fn clear(&mut self) {
        for (_, group) in self.groups.drain() {
            if let Some(handle) = group.banner {
                self.sink.close(handle);
            }
        }
    }
}

/// The DBus-backed sink. A missing notification daemon degrades to the
/// prompt windows alone: warned once, then quiet, and never a failure the
/// prompt flow can see.
struct DbusSink {
    warned: bool,
}

impl Sink for DbusSink {
    type Handle = notify_rust::NotificationHandle;

    fn show(&mut self, summary: &str, body: &str, timeout_ms: u32) -> Option<Self::Handle> {
        let shown = notify_rust::Notification::new()
            .appname("hallpass")
            .summary(summary)
            .body(body)
            .urgency(notify_rust::Urgency::Critical)
            .timeout(notify_rust::Timeout::Milliseconds(timeout_ms))
            .show();
        match shown {
            Ok(handle) => Some(handle),
            Err(e) => {
                if !self.warned {
                    self.warned = true;
                    tracing::warn!("desktop notifications unavailable: {e}");
                } else {
                    tracing::debug!("desktop notification failed: {e}");
                }
                None
            }
        }
    }

    fn update(&mut self, handle: &mut Self::Handle, summary: &str, body: &str, timeout_ms: u32) {
        handle.summary(summary);
        handle.body(body);
        handle.timeout(notify_rust::Timeout::Milliseconds(timeout_ms));
        if let Err(e) = handle.update() {
            tracing::debug!("desktop notification update failed: {e}");
        }
    }

    fn close(&mut self, handle: Self::Handle) {
        handle.close();
    }
}

/// Spawn the notifier thread. Blocking DBus round trips live here and
/// nowhere near a frame. The thread ends once every sender is gone and the
/// banners left are retired; a process that exits right after must wait for
/// it, or those banners outlive it.
pub fn spawn(rx: Receiver<NotifyEvent>) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("hallpass-notify".into())
        .spawn(move || {
            let mut tracker = Tracker::new(DbusSink { warned: false });
            while let Ok(event) = rx.recv() {
                tracker.handle(event, hallpass_types::unix_ms_now());
            }
            // Channel closed: the app is exiting; retire what is left so
            // no banner outlives the process that would answer it.
            tracker.clear();
        })
        .expect("failed to spawn notifier thread")
}

#[cfg(test)]
mod tests {
    use super::*;
    use hallpass_types::{FlowTuple, Proto};

    #[derive(Debug, PartialEq)]
    enum Call {
        Show(String, u32),
        Update(u32, String),
        Close(u32),
    }

    #[derive(Default)]
    struct FakeSink {
        calls: Vec<Call>,
        next: u32,
    }

    impl Sink for FakeSink {
        type Handle = u32;
        fn show(&mut self, _summary: &str, body: &str, timeout_ms: u32) -> Option<u32> {
            self.next += 1;
            self.calls.push(Call::Show(body.to_string(), timeout_ms));
            Some(self.next)
        }
        fn update(&mut self, handle: &mut u32, _summary: &str, body: &str, _timeout_ms: u32) {
            self.calls.push(Call::Update(*handle, body.to_string()));
        }
        fn close(&mut self, handle: u32) {
            self.calls.push(Call::Close(handle));
        }
    }

    fn conn(exe: Option<&str>, domain: Option<&str>) -> Connection {
        Connection {
            tuple: FlowTuple {
                proto: Proto::Tcp,
                src: "10.0.0.1:40000".parse().unwrap(),
                dst: "93.184.216.34:443".parse().unwrap(),
            },
            uid: Some(1000),
            pid: Some(1),
            exe_path: exe.map(PathBuf::from),
            cmdline: None,
            parent_exe: None,
            domain: domain.map(String::from),
            iface: None,
            app_id: None,
            first_seen: None,
        }
    }

    fn request(id: u64, exe: Option<&str>) -> NotifyEvent {
        NotifyEvent::Request {
            id,
            conn: Box::new(conn(exe, None)),
            deadline_ms: 40_000,
        }
    }

    fn tracker() -> Tracker<FakeSink> {
        Tracker::new(FakeSink::default())
    }

    /// The banner exists for the operator who is not looking at the screen,
    /// so the NEW marker has to survive coalescing. Groups are keyed on the
    /// application, not the destination: a prompt for a destination this
    /// program has never reached lands behind a routine one from the same
    /// program, and reading only the front entry dropped the marker for
    /// exactly the prompt that earned it.
    #[test]
    fn a_new_prompt_behind_a_routine_one_still_marks_the_banner() {
        let routine = Entry {
            id: 1,
            conn: conn(Some("/usr/bin/curl"), None),
            deadline_ms: 40_000,
        };
        let mut fresh = routine.conn.clone();
        fresh.first_seen = Some(hallpass_types::FirstSeen {
            app: false,
            dest: true,
        });
        let fresh = Entry {
            id: 2,
            conn: fresh,
            deadline_ms: 40_000,
        };

        let (summary, _) = banner_text(&[routine, fresh]);
        assert_eq!(summary, "Connection request (NEW)");
    }

    /// Nothing new, and tracking off, both read as an ordinary request: a
    /// banner claiming NEW for a feature that is off would be a lie.
    #[test]
    fn an_ordinary_group_is_not_marked() {
        for quiet in [
            Some(hallpass_types::FirstSeen {
                app: false,
                dest: false,
            }),
            None,
        ] {
            let mut c = conn(Some("/usr/bin/curl"), None);
            c.first_seen = quiet;
            let (summary, _) = banner_text(&[Entry {
                id: 1,
                conn: c,
                deadline_ms: 40_000,
            }]);
            assert_eq!(summary, "Connection request", "{quiet:?}");
        }
    }

    #[test]
    fn one_banner_per_app_with_a_count() {
        let mut t = tracker();
        t.handle(request(1, Some("/usr/bin/curl")), 10_000);
        t.handle(request(2, Some("/usr/bin/curl")), 10_000);
        t.handle(request(3, Some("/usr/bin/wget")), 10_000);
        assert_eq!(
            t.sink.calls,
            vec![
                Call::Show("curl wants to connect to 93.184.216.34:443".into(), 30_000),
                Call::Update(
                    1,
                    "curl wants to connect to 93.184.216.34:443 (1 more pending)".into()
                ),
                Call::Show("wget wants to connect to 93.184.216.34:443".into(), 30_000),
            ]
        );
    }

    #[test]
    fn retiring_the_last_id_closes_the_banner() {
        let mut t = tracker();
        t.handle(request(1, Some("/usr/bin/curl")), 10_000);
        t.handle(request(2, Some("/usr/bin/curl")), 10_000);
        t.handle(NotifyEvent::Gone { id: 1 }, 10_000);
        t.handle(NotifyEvent::Gone { id: 2 }, 10_000);
        assert_eq!(
            t.sink.calls.last(),
            Some(&Call::Close(1)),
            "{:?}",
            t.sink.calls
        );
        assert!(t.groups.is_empty());
    }

    /// The daemon re-delivers pending prompts when a handler reconnects;
    /// a duplicate id must not inflate the pending count.
    #[test]
    fn redelivered_prompts_do_not_double_count() {
        let mut t = tracker();
        t.handle(request(1, Some("/usr/bin/curl")), 10_000);
        t.handle(request(1, Some("/usr/bin/curl")), 10_000);
        assert_eq!(t.sink.calls.len(), 1, "{:?}", t.sink.calls);
    }

    #[test]
    fn disconnect_closes_every_banner() {
        let mut t = tracker();
        t.handle(request(1, Some("/usr/bin/curl")), 10_000);
        t.handle(request(2, Some("/usr/bin/wget")), 10_000);
        t.handle(NotifyEvent::Disconnected, 10_000);
        let closes = t
            .sink
            .calls
            .iter()
            .filter(|c| matches!(c, Call::Close(_)))
            .count();
        assert_eq!(closes, 2, "{:?}", t.sink.calls);
        assert!(t.groups.is_empty());
    }

    /// Two packaged applications running one path are two prompt windows,
    /// so they are two banners: merged, one would name the other's prompts
    /// in its count.
    #[test]
    fn one_path_under_two_app_ids_is_two_banners() {
        let mut t = tracker();
        for (id, app) in [(1, "flatpak:org.example.A"), (2, "flatpak:org.example.B")] {
            let mut c = conn(Some("/app/bin/tool"), None);
            c.app_id = Some(app.into());
            t.handle(
                NotifyEvent::Request {
                    id,
                    conn: Box::new(c),
                    deadline_ms: 40_000,
                },
                10_000,
            );
        }
        let shows = t
            .sink
            .calls
            .iter()
            .filter(|c| matches!(c, Call::Show(..)))
            .count();
        assert_eq!(shows, 2, "{:?}", t.sink.calls);
    }

    /// Unattributed prompts are separate banners, same reasoning as
    /// their windows: two unattributed programs are not "the same app".
    #[test]
    fn anonymous_prompts_are_not_grouped() {
        let mut t = tracker();
        t.handle(request(1, None), 10_000);
        t.handle(request(2, None), 10_000);
        let shows = t
            .sink
            .calls
            .iter()
            .filter(|c| matches!(c, Call::Show(..)))
            .count();
        assert_eq!(shows, 2, "{:?}", t.sink.calls);
    }

    /// GNOME renders an HTML subset in bodies; a hostile domain must not
    /// restyle the text the operator reads.
    #[test]
    fn markup_in_hostile_fields_is_escaped() {
        let mut t = tracker();
        t.handle(
            NotifyEvent::Request {
                id: 1,
                conn: Box::new(conn(Some("/usr/bin/curl"), Some("<b>bank.example</b>"))),
                deadline_ms: 40_000,
            },
            10_000,
        );
        let Call::Show(body, _) = &t.sink.calls[0] else {
            panic!("expected a show: {:?}", t.sink.calls);
        };
        assert!(!body.contains('<'), "{body}");
        assert!(body.contains("&lt;b&gt;"), "{body}");
    }

    /// A gone id for a prompt this client never saw (answered elsewhere
    /// before connecting) must not touch anything.
    #[test]
    fn unknown_gone_is_ignored() {
        let mut t = tracker();
        t.handle(NotifyEvent::Gone { id: 99 }, 10_000);
        assert!(t.sink.calls.is_empty());
    }

    /// Past the group cap new groups get no banner: awareness loss for
    /// that group only, never a verdict, and the prompt window still shows.
    #[test]
    fn group_cap_drops_new_banners_not_old_ones() {
        let mut t = tracker();
        for id in 0..MAX_BANNER_GROUPS as u64 {
            t.handle(request(id, Some(&format!("/bin/app{id}"))), 10_000);
        }
        let shows = t.sink.calls.len();
        t.handle(request(999, Some("/bin/straw")), 10_000);
        assert_eq!(t.sink.calls.len(), shows, "the straw got a banner");
        // Existing groups keep updating.
        t.handle(request(1_000, Some("/bin/app0")), 10_000);
        assert!(matches!(t.sink.calls.last(), Some(Call::Update(..))));
    }
}
