//! Shared test helpers.

use std::path::{Path, PathBuf};

use hallpass_types::{RuntimeConfig, Verdict};

/// An enforcing `RuntimeConfig`, so tests spell only what they are about.
/// Override the rest by struct update: `RuntimeConfig { enforce: false,
/// ..runtime_config(5, Verdict::Allow) }`.
pub fn runtime_config(prompt_timeout_secs: u64, default_verdict: Verdict) -> RuntimeConfig {
    RuntimeConfig {
        prompt_timeout_secs,
        default_verdict,
        enforce: true,
    }
}

/// The uid this test process runs as.
///
/// Read from `/proc/self` rather than through libc: the workspace denies
/// unsafe code, and this is the same read the daemon's own uid checks use.
/// Session coverage is uid-scoped, so a test that opens a session over its
/// own process tree needs the real value, not a plausible one.
pub fn own_uid() -> u32 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self")
        .expect("read /proc/self")
        .uid()
}

/// Give an existing path a mode the daemon's file-trust checks accept.
///
/// The umask is what makes this necessary. `std::fs::write` creates with
/// `0666 & ~umask` and `create_dir_all` with `0777 & ~umask`, so on a host
/// running the `umask 002` that Debian and Ubuntu ship by default
/// (`USERGROUPS_ENAB`), every fixture lands group-writable and
/// [`crate::rules::store::file_perms_ok`] correctly refuses it. Eighteen
/// tests then failed - all of them *on the security checks themselves* -
/// which reads as those checks having regressed rather than as a property of
/// whoever's shell ran the suite. A verification gate that fails for a reason
/// the code did not cause is a gate people learn to skip.
///
/// Set after the write rather than through `OpenOptions::mode`, because
/// `open(2)` applies the umask to that argument too.
pub fn trust_mode(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mode = if path.is_dir() { 0o755 } else { 0o644 };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .expect("set test fixture mode");
}

/// Write a fixture file the daemon's trust checks accept, whatever the
/// umask. See [`trust_mode`].
pub fn write_trusted(path: &Path, contents: impl AsRef<[u8]>) {
    std::fs::write(path, contents).expect("write test fixture");
    trust_mode(path);
}

/// Fresh per-test temp directory, removed on drop (including on panic).
pub struct TestDir(PathBuf);

impl TestDir {
    pub fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("hallpassd-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // The directory too, not just the files in it: a rules directory the
        // group can write is the one thing every per-file check assumes away,
        // so fixtures must not model the state the daemon refuses.
        trust_mode(&dir);
        Self(dir)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    /// Write `contents` to `name` inside this directory, at a mode the
    /// daemon's trust checks accept. Returns the path.
    pub fn write(&self, name: &str, contents: impl AsRef<[u8]>) -> PathBuf {
        let path = self.0.join(name);
        write_trusted(&path, contents);
        path
    }

    /// A subdirectory of this one, at a mode the trust checks accept.
    pub fn subdir(&self, name: &str) -> PathBuf {
        let path = self.0.join(name);
        std::fs::create_dir_all(&path).expect("create test subdir");
        trust_mode(&path);
        path
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
