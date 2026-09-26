//! Fuzz entry points: every parser that reads bytes an attacker chooses.
//!
//! Each function takes raw fuzzer input, drives one parser, and asserts what
//! that parser promises about its output. A panic is a finding. The
//! `fuzz/` crate calls these; the tests below run them over a few seeds so a
//! normal `cargo test` keeps them compiling and sane.

use std::path::PathBuf;

use hallpass_types::{ConnEvent, Connection, FlowTuple, Proto, Rule, Verdict};

use crate::attribution::{procfs, sockdiag};
use crate::rules::model::CompiledRule;
use crate::syslog::{format_event, SyslogFormat};
use crate::{conntrack, conntrack_events, dns, packet};

/// DNS messages, as the wire snooper sees them: anything that reaches this
/// host from source port 53, and anything a local process sends to port 53.
pub fn dns(data: &[u8]) {
    if let Some(q) = dns::parse_query(data) {
        assert_clean_name(&q.query_name);
    }
    if let Some(r) = dns::parse_response(data) {
        assert_clean_name(&r.query_name);
    }
}

/// A name either snooper may cache: bounded, and free of the bytes the
/// snoopers promise to refuse.
fn assert_clean_name(name: &str) {
    assert!(name.len() <= dns::MAX_NAME_LEN, "{} bytes", name.len());
    assert!(
        !name.bytes().any(dns::is_hostile_name_byte),
        "hostile byte in {name:?}"
    );
    assert!(
        !name.chars().any(hallpass_types::is_display_hazard),
        "display hazard in {name:?}"
    );
}

/// IP packets from the verdict and snoop queues. The first byte picks how
/// much longer the kernel claims the packet was, so the truncated path is
/// reached too.
pub fn packet(data: &[u8]) {
    let Some((&extra, payload)) = data.split_first() else {
        return;
    };
    let _ = packet::parse(payload, payload.len());
    let _ = packet::parse(payload, payload.len() + usize::from(extra));
    if let Some(udp) = packet::udp_payload(payload) {
        let start = udp.as_ptr() as usize - payload.as_ptr() as usize;
        assert!(start + udp.len() <= payload.len());
    }
}

/// Netlink replies: sock_diag lookups, conntrack delete acks, and conntrack
/// destroy events. The kernel writes these, but they are the one binary
/// format parsed on the verdict thread's attribution path, so they are held
/// to the same standard.
pub fn netlink(data: &[u8]) {
    let _ = sockdiag::parse_reply(data);
    let _ = conntrack::parse_ack(data);
    let _ = conntrack_events::parse_datagram(data);
}

/// `/proc/<pid>/cgroup` contents. Any user names their own scopes, so this
/// text is theirs; an identity that comes out must be one the rest of the
/// system accepts.
pub fn cgroup(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    if let Some(id) = procfs::app_id_from_cgroup(&text) {
        assert!(hallpass_types::valid_app_id(&id), "{id:?}");
    }
}

/// A process's argv, as read from `/proc/<pid>/cmdline` and capped.
pub fn cmdline(data: &[u8]) {
    let text = String::from_utf8_lossy(data).into_owned();
    let out = procfs::truncate_cmdline(text.clone());
    if text.len() <= procfs::MAX_CMDLINE_BYTES {
        assert_eq!(out, text);
    } else {
        let kept = out.strip_suffix("...[truncated]").expect("cut is marked");
        assert!(kept.len() <= procfs::MAX_CMDLINE_BYTES);
        assert!(text.starts_with(kept));
    }
}

/// Lines of `/proc/net/{tcp,udp}{,6}`.
pub fn proc_net_line(data: &[u8]) {
    let _ = procfs::parse_proc_net_line(&String::from_utf8_lossy(data));
}

/// A rule as a client or a rules.d file states it. List-file operands are
/// dropped first: compiling one reads the named file, and a fuzzer naming
/// `/dev/zero` would measure the disk, not the compiler.
pub fn rule(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(mut rule) = toml::from_str::<Rule>(text) else {
        return;
    };
    rule.matcher.domains_file = None;
    rule.matcher.ips_file = None;
    rule.matcher.hashes_file = None;
    let _ = CompiledRule::compile(&rule);
}

/// Syslog export of an event whose strings a process chose. Whatever they
/// hold, the line must frame as one record: no control characters, and
/// structured data that parses back into exactly the fields sent.
///
/// Returns the JSON-format body and how many keys it must hold, for the
/// caller to parse: this crate has no JSON parser outside its tests.
pub fn syslog(data: &[u8]) -> (String, usize) {
    let text = String::from_utf8_lossy(data);
    let mut fields = text.split('\0').map(str::to_owned);
    let mut next = || fields.next();
    let ev = ConnEvent {
        conn: Connection {
            tuple: FlowTuple {
                proto: Proto::Udp,
                src: "10.0.0.1:40000".parse().unwrap(),
                dst: "10.0.0.2:514".parse().unwrap(),
            },
            uid: Some(1000),
            pid: Some(42),
            exe_path: next().map(PathBuf::from),
            cmdline: next(),
            parent_exe: None,
            domain: next(),
            iface: next(),
            app_id: next(),
            first_seen: None,
        },
        verdict: Verdict::Deny,
        rule_name: next(),
        unix_ms: 1_720_000_000_000,
        enforced: false,
    };
    let body = |format| {
        let line = format_event(&ev, format, "host", 7);
        assert!(
            !line.chars().any(char::is_control),
            "control character in {line:?}"
        );
        let (_, body) = line.split_once(" conn ").expect("header ends in the msgid");
        body.to_owned()
    };
    let sd = body(SyslogFormat::Rfc5424);
    assert_eq!(sd_param_count(&sd), Some(field_count(&ev)), "{sd:?}");
    let json = body(SyslogFormat::Json)
        .strip_prefix("- \u{feff}")
        .expect("BOM prefix")
        .to_owned();
    // Every exported field plus unix_ms.
    (json, field_count(&ev) + 1)
}

/// How many fields `syslog::for_each_field` emits for `ev`.
fn field_count(ev: &ConnEvent) -> usize {
    let c = &ev.conn;
    // verdict, proto, src, dst, pid, uid
    let fixed = 6 + usize::from(!ev.enforced);
    fixed
        + [
            ev.rule_name.is_some(),
            c.exe_path.is_some(),
            c.cmdline.is_some(),
            c.domain.is_some(),
            c.iface.is_some(),
            c.app_id.is_some(),
        ]
        .into_iter()
        .filter(|&present| present)
        .count()
}

/// Parse one RFC 5424 SD-ELEMENT (`[id k="v" ...]`) that must span all of
/// `body`, returning its parameter count. Inside a value only `"`, `\` and
/// `]` may follow a backslash, and none of the three may appear bare.
fn sd_param_count(body: &str) -> Option<usize> {
    let rest = body.strip_prefix('[')?;
    let mut chars = rest.chars().peekable();
    // SD-ID runs to the first space.
    while chars.next_if(|&c| c != ' ' && c != ']').is_some() {}
    let mut count = 0;
    loop {
        match chars.next()? {
            ']' => return chars.next().is_none().then_some(count),
            ' ' => {}
            _ => return None,
        }
        while chars.next_if(|&c| c != '=').is_some() {}
        if chars.next()? != '=' || chars.next()? != '"' {
            return None;
        }
        loop {
            match chars.next()? {
                '\\' => {
                    if !matches!(chars.next()?, '"' | '\\' | ']') {
                        return None;
                    }
                }
                '"' => break,
                ']' => return None,
                _ => {}
            }
        }
        count += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every entry point survives empty, short and hostile seeds. The fuzzer
    /// does the real work; this keeps the harness compiling and its oracles
    /// agreeing with the code on inputs that are known to be fine.
    #[test]
    fn entry_points_accept_their_seeds() {
        let seeds: [&[u8]; 5] = [
            b"",
            b"\0",
            b"curl\0curl https://example.org\0example.org\0eth0\0flatpak:org.x.Y\0rule",
            "\x1b[2J\r\n\"]\\\0\u{202e}\0".as_bytes(),
            &[0xff; 64],
        ];
        for seed in seeds {
            dns(seed);
            packet(seed);
            netlink(seed);
            cgroup(seed);
            cmdline(seed);
            proc_net_line(seed);
            rule(seed);
            let (json, keys) = syslog(seed);
            let value: serde_json::Value =
                serde_json::from_str(&json).unwrap_or_else(|e| panic!("{e}: {json:?}"));
            assert_eq!(value.as_object().map(serde_json::Map::len), Some(keys));
        }
        cmdline(&vec![b'a'; procfs::MAX_CMDLINE_BYTES * 2]);
        rule(b"name = \"r\"\naction = \"allow\"\nduration = \"forever\"\npriority = 1\nenabled = true\n[match]\nexe_glob = \"/usr/bin/*\"\n");
        cgroup(b"0::/user.slice/app-flatpak-org.mozilla.firefox-1234.scope\n");
    }

    #[test]
    fn sd_parser_agrees_with_the_writer() {
        assert_eq!(sd_param_count(r#"[id a="1" b="x\"y\]z\\"]"#), Some(2));
        assert_eq!(sd_param_count(r#"[id a="1"] trailing"#), None);
        assert_eq!(sd_param_count(r#"[id a="x]y"]"#), None);
    }
}
