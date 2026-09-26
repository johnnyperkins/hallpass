//! Verdicts remembered for UDP flows the peer has not answered.
//!
//! A UDP flow stays `ct state new` until a reply arrives, so without this
//! every datagram of an unanswered flow is decided on its own: attributed,
//! matched, logged as an event, and prompted about again after a `once`
//! answer. The first decision is remembered for the flow for as long as the
//! kernel keeps an unreplied UDP entry, so the flow is judged once, as an
//! answered one is.
//!
//! What is remembered is the policy verdict, before the mode is applied. Any
//! change that could decide the flow differently (the ruleset, the mode, the
//! default verdict) forgets everything, and entries expire rather than being
//! refreshed, so a flow that keeps sending is re-judged, and re-attributed,
//! at that interval.

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hallpass_types::{FlowTuple, Verdict};
use lru::LruCache;

use crate::rules::engine::RuleSet;

/// How long a remembered verdict holds: the kernel's default timeout for an
/// unreplied UDP entry (`nf_conntrack_udp_timeout`).
pub const TTL: Duration = Duration::from_secs(30);

/// Flows remembered at once. Past it the least recently used is forgotten,
/// which costs that flow a fresh decision, never a wrong one.
const CAPACITY: usize = 4096;

/// What a remembered verdict was decided under. A new ruleset snapshot is a
/// new allocation, and the old one is held here, so pointer identity cannot
/// be fooled by an address being reused.
struct Epoch {
    ruleset: Arc<RuleSet>,
    enforcing: bool,
    default_verdict: Verdict,
}

impl Epoch {
    fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.ruleset, &other.ruleset)
            && self.enforcing == other.enforcing
            && self.default_verdict == other.default_verdict
    }
}

pub struct UdpMemo {
    entries: LruCache<FlowTuple, (Verdict, Instant)>,
    epoch: Option<Epoch>,
}

impl Default for UdpMemo {
    fn default() -> Self {
        Self {
            entries: LruCache::new(NonZeroUsize::new(CAPACITY).expect("nonzero")),
            epoch: None,
        }
    }
}

impl UdpMemo {
    /// The remembered verdict for `tuple`, if one is still valid under the
    /// ruleset and settings in force now.
    pub fn get(
        &mut self,
        tuple: &FlowTuple,
        ruleset: Arc<RuleSet>,
        enforcing: bool,
        default_verdict: Verdict,
        now: Instant,
    ) -> Option<Verdict> {
        let epoch = Epoch {
            ruleset,
            enforcing,
            default_verdict,
        };
        if !self.epoch.as_ref().is_some_and(|e| e.same(&epoch)) {
            self.entries.clear();
            self.epoch = Some(epoch);
            return None;
        }
        match self.entries.get(tuple) {
            Some(&(verdict, expires)) if now < expires => Some(verdict),
            Some(_) => {
                self.entries.pop(tuple);
                None
            }
            None => None,
        }
    }

    /// Remember `verdict` for `tuple`. A no-op for anything but UDP.
    ///
    /// Recorded under whatever epoch the last [`UdpMemo::get`] saw. If the
    /// decision was made under a newer one, the next `get` finds the epoch
    /// moved and forgets it, which costs a re-decision and nothing else.
    pub fn put(&mut self, tuple: FlowTuple, verdict: Verdict, now: Instant) {
        if tuple.proto == hallpass_types::Proto::Udp {
            self.entries.put(tuple, (verdict, now + TTL));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hallpass_types::Proto;

    fn udp(src: &str, dst: &str) -> FlowTuple {
        FlowTuple {
            proto: Proto::Udp,
            src: src.parse().unwrap(),
            dst: dst.parse().unwrap(),
        }
    }

    #[test]
    fn remembers_within_the_ttl_and_forgets_after() {
        let rules = Arc::new(RuleSet::compile(&[]));
        let t = udp("10.0.0.1:40000", "10.0.0.2:514");
        let now = Instant::now();
        let mut memo = UdpMemo::default();
        let get =
            |memo: &mut UdpMemo, at| memo.get(&t, Arc::clone(&rules), true, Verdict::Deny, at);

        assert_eq!(get(&mut memo, now), None);
        memo.put(t, Verdict::Allow, now);
        assert_eq!(get(&mut memo, now + TTL / 2), Some(Verdict::Allow));
        assert_eq!(get(&mut memo, now + TTL), None);
    }

    #[test]
    fn any_change_that_could_decide_differently_forgets_everything() {
        let rules = Arc::new(RuleSet::compile(&[]));
        let t = udp("10.0.0.1:40000", "10.0.0.2:514");
        let now = Instant::now();
        let fresh = |r: &Arc<RuleSet>, enforcing, default| {
            let mut memo = UdpMemo::default();
            memo.get(&t, Arc::clone(&rules), true, Verdict::Deny, now);
            memo.put(t, Verdict::Allow, now);
            memo.get(&t, Arc::clone(r), enforcing, default, now)
        };
        assert_eq!(fresh(&rules, true, Verdict::Deny), Some(Verdict::Allow));
        let reloaded = Arc::new(RuleSet::compile(&[]));
        assert_eq!(fresh(&reloaded, true, Verdict::Deny), None, "ruleset");
        assert_eq!(fresh(&rules, false, Verdict::Deny), None, "mode");
        assert_eq!(fresh(&rules, true, Verdict::Allow), None, "default");
    }

    #[test]
    fn only_udp_is_remembered() {
        let rules = Arc::new(RuleSet::compile(&[]));
        let mut t = udp("10.0.0.1:40000", "10.0.0.2:443");
        t.proto = Proto::Tcp;
        let now = Instant::now();
        let mut memo = UdpMemo::default();
        memo.get(&t, Arc::clone(&rules), true, Verdict::Deny, now);
        memo.put(t, Verdict::Allow, now);
        assert_eq!(memo.get(&t, rules, true, Verdict::Deny, now), None);
    }
}
