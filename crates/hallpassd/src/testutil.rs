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

/// Fresh per-test temp directory, removed on drop (including on panic).
pub struct TestDir(PathBuf);

impl TestDir {
    pub fn new(tag: &str) -> TestDir {
        let dir = std::env::temp_dir().join(format!("hallpassd-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        TestDir(dir)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
