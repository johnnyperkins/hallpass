//! Interface index to name resolution via /sys/class/net.
//!
//! NFQUEUE reports interfaces as kernel ifindex values; rules match on
//! names ("eth0", "wg0"). Names are cached and the /sys scan repeated only
//! when an unknown index appears (interface hotplug); an index that stays
//! unknown after a rescan is cached as `if<N>` so it cannot trigger a scan
//! per packet.
//!
//! Known limitation: renaming an interface without changing its ifindex
//! keeps serving the old name until some unknown index triggers a rescan.
//! Interface renames essentially only happen at boot, before the daemon
//! starts, so no timer-based refresh is spent on it.

use std::collections::HashMap;
use std::sync::Mutex;

/// Cached ifindex -> name map.
#[derive(Default)]
pub struct IfaceMap {
    entries: Mutex<HashMap<u32, String>>,
}

impl IfaceMap {
    /// Name for `index`, or `None` for index 0 (no interface reported).
    pub fn name(&self, index: u32) -> Option<String> {
        if index == 0 {
            return None;
        }
        let mut entries = self.entries.lock().unwrap();
        if let Some(name) = entries.get(&index) {
            return Some(name.clone());
        }
        // Merge instead of replace: cached placeholders survive, so two
        // alternating unknown indexes cannot force a scan per lookup.
        // Fresh names win over stale ones for every scanned index.
        entries.extend(scan());
        let name = entries
            .entry(index)
            .or_insert_with(|| format!("if{index}"))
            .clone();
        Some(name)
    }
}

/// Read every interface's ifindex from /sys/class/net.
fn scan() -> HashMap<u32, String> {
    let mut map = HashMap::new();
    let Ok(read) = std::fs::read_dir("/sys/class/net") else {
        return map;
    };
    for entry in read.flatten() {
        let Some(name) = entry.file_name().to_str().map(String::from) else {
            continue;
        };
        let Ok(text) = std::fs::read_to_string(entry.path().join("ifindex")) else {
            continue;
        };
        if let Ok(index) = text.trim().parse::<u32>() {
            map.insert(index, name);
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_index_is_none_and_unknown_gets_placeholder() {
        let map = IfaceMap::default();
        assert_eq!(map.name(0), None);
        // u32::MAX is never a real ifindex; after the rescan fails to find
        // it, the placeholder is cached (and stable on repeat lookups).
        assert_eq!(map.name(u32::MAX), Some(format!("if{}", u32::MAX)));
        assert_eq!(map.name(u32::MAX), Some(format!("if{}", u32::MAX)));
    }

    #[test]
    fn loopback_resolves_on_linux() {
        // Every Linux system has "lo"; find its index in the scan and
        // confirm the map resolves it.
        let scanned = scan();
        if let Some((&idx, _)) = scanned.iter().find(|(_, n)| *n == "lo") {
            assert_eq!(IfaceMap::default().name(idx).as_deref(), Some("lo"));
        }
    }
}
