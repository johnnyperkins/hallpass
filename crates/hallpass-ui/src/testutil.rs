//! Fixtures shared by this crate's tests.

use std::path::PathBuf;

use hallpass_types::{Connection, FlowTuple, Proto};

/// A TCP connection from uid 1000 to `dst`, attributed to `exe` when given,
/// with every optional field empty. Tests that need one filled in set it
/// with struct-update syntax, so a field added to `Connection` is added
/// here once rather than in every module's own copy.
pub fn conn(exe: Option<&str>, dst: &str) -> Connection {
    Connection {
        tuple: FlowTuple {
            proto: Proto::Tcp,
            src: "10.0.0.1:40000".parse().expect("source address"),
            dst: dst.parse().expect("destination address"),
        },
        uid: Some(1000),
        pid: Some(4242),
        exe_path: exe.map(PathBuf::from),
        cmdline: None,
        parent_exe: None,
        domain: None,
        iface: None,
        app_id: None,
        first_seen: None,
    }
}
