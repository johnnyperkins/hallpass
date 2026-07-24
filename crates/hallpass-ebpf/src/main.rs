//! Hallpass eBPF programs: socket-to-process attribution.
//!
//! - kprobe/kretprobe on tcp_v4_connect and tcp_v6_connect record the
//!   flow tuple of every outgoing TCP connection in SOCK_MAP.
//! - kprobes on udp_sendmsg and udpv6_sendmsg do the same for UDP.
//! - tracepoints on sched_process_exec / sched_process_exit stream
//!   process lifecycle events over a ring buffer so userspace can keep
//!   a fresh pid -> exe/cmdline cache.
//!
//! Byte order convention (shared with hallpass-ebpf-common): addresses
//! are raw network-order bytes, ports are host order.
//!
//! struct offsets: sock_common/msghdr field offsets are `#[no_mangle]`
//! globals that the loader patches with values resolved from the running
//! kernel's BTF (see hallpassd's attribution::btf). The compiled-in
//! defaults are the x86_64 CONFIG_NET_NS=y layout, used as-is when BTF
//! is unavailable. If an offset is still wrong, lookups miss and
//! hallpassd falls back to procfs attribution; nothing breaks.

#![no_std]
#![no_main]
#![allow(clippy::result_unit_err)]

use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read_kernel,
        bpf_probe_read_user, bpf_probe_read_user_str_bytes,
    },
    macros::{kprobe, kretprobe, map, tracepoint, uprobe, uretprobe},
    maps::{HashMap, LruHashMap, PerCpuArray, RingBuf},
    programs::{ProbeContext, RetProbeContext, TracePointContext},
};
use hallpass_ebpf_common::{
    DnsEvent, ExecEvent, AF_INET, AF_INET6, DNS_NAME_CAP, EVENT_EXEC, EVENT_EXIT, FlowKey,
    FlowVal, PROTO_TCP, PROTO_UDP,
};

// struct sock_common / msghdr field offsets. Loader-patched globals
// (hallpassd resolves the real values from kernel BTF and overrides them
// by symbol name; unpatched, these x86_64 CONFIG_NET_NS=y defaults
// apply). Read only through `off()` so the compiler cannot fold the
// defaults into the code.
#[no_mangle]
static OFF_SKC_DADDR: u32 = 0; // __be32
#[no_mangle]
static OFF_SKC_RCV_SADDR: u32 = 4; // __be32
#[no_mangle]
static OFF_SKC_DPORT: u32 = 12; // __be16
#[no_mangle]
static OFF_SKC_NUM: u32 = 14; // u16, host order
#[no_mangle]
static OFF_SKC_FAMILY: u32 = 16; // u16
#[no_mangle]
static OFF_SKC_V6_DADDR: u32 = 56; // struct in6_addr
#[no_mangle]
static OFF_SKC_V6_RCV_SADDR: u32 = 72; // struct in6_addr
#[no_mangle]
static OFF_MSG_NAME: u32 = 0; // void *

#[inline(always)]
fn off(global: &'static u32) -> usize {
    unsafe { core::ptr::read_volatile(global) as usize }
}

// struct sockaddr_in / sockaddr_in6 field offsets.
const SIN_PORT: usize = 2; // __be16 in both
const SIN_ADDR: usize = 4; // __be32
const SIN6_ADDR: usize = 8; // 16 bytes

/// Flow tuple -> owning process. LRU so stale flows age out on their own.
#[map]
static SOCK_MAP: LruHashMap<FlowKey, FlowVal> = LruHashMap::with_max_entries(8192, 0);

/// tcp_connect entry scratch: pid_tgid -> sock pointer, consumed by the
/// kretprobe of the same call.
#[map]
static PROC_SCRATCH: HashMap<u64, u64> = HashMap::with_max_entries(512, 0);

/// Process exec/exit events for the userspace cache.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// getaddrinfo entry scratch: the queried name is copied here at entry so
/// the return probe records what was actually looked up, not whatever the
/// (attacker-controllable) node buffer holds after the blocking call. LRU
/// so a missed return probe (thread killed mid-call) ages out instead of
/// wedging the map. Keyed by pid_tgid.
#[map]
static DNS_SCRATCH: LruHashMap<u64, DnsScratch> = LruHashMap::with_max_entries(512, 0);

/// Captured getaddrinfo arguments carried from entry to return.
#[repr(C)]
#[derive(Clone, Copy)]
struct DnsScratch {
    /// `struct addrinfo **res` out-parameter pointer.
    res: u64,
    /// Length of the captured name (no NUL).
    name_len: u32,
    /// The queried hostname, copied at entry.
    name: [u8; DNS_NAME_CAP],
}

/// Resolved (name, address) pairs for the userspace domain cache.
#[map]
static DNS_EVENTS: RingBuf = RingBuf::with_byte_size(128 * 1024, 0);

// A DnsScratch and a DnsEvent are ~280 bytes each: two of them blow the
// 512-byte BPF stack, so both probes assemble their values in per-CPU
// scratch maps instead. Programs are non-preemptible on their CPU, so a
// single slot each is enough.
#[map]
static DNS_SCRATCH_BUF: PerCpuArray<DnsScratch> = PerCpuArray::with_max_entries(1, 0);
#[map]
static DNS_EVENT_BUF: PerCpuArray<DnsEvent> = PerCpuArray::with_max_entries(1, 0);

#[inline(always)]
unsafe fn read<T>(base: u64, off: usize) -> Result<T, ()> {
    bpf_probe_read_kernel((base as usize + off) as *const T).map_err(|_| ())
}

fn current_flow_val() -> FlowVal {
    FlowVal {
        pid: (bpf_get_current_pid_tgid() >> 32) as u32,
        uid: bpf_get_current_uid_gid() as u32,
    }
}

/// Build the FlowKey for a connected socket. `proto` is PROTO_TCP or
/// PROTO_UDP; for UDP an explicit destination (from msghdr) overrides the
/// socket's connected peer.
unsafe fn sock_flow_key(sk: u64, proto: u8, dest: Option<(&[u8], u16)>) -> Result<FlowKey, ()> {
    let family: u16 = read(sk, off(&OFF_SKC_FAMILY))?;
    let sport: u16 = read(sk, off(&OFF_SKC_NUM))?;
    match family as u8 {
        AF_INET => {
            let saddr: u32 = read(sk, off(&OFF_SKC_RCV_SADDR))?;
            let (daddr, dport) = match dest {
                Some((addr, port)) if addr.len() >= 4 => {
                    ([addr[0], addr[1], addr[2], addr[3]], port)
                }
                _ => {
                    let d: u32 = read(sk, off(&OFF_SKC_DADDR))?;
                    (d.to_ne_bytes(), u16::from_be(read::<u16>(sk, off(&OFF_SKC_DPORT))?))
                }
            };
            Ok(FlowKey::v4(proto, saddr.to_ne_bytes(), sport, daddr, dport))
        }
        AF_INET6 => {
            let saddr: [u8; 16] = read(sk, off(&OFF_SKC_V6_RCV_SADDR))?;
            let (daddr, dport): ([u8; 16], u16) = match dest {
                Some((addr, port)) if addr.len() >= 16 => {
                    let mut d = [0u8; 16];
                    d.copy_from_slice(&addr[..16]);
                    (d, port)
                }
                _ => (
                    read(sk, off(&OFF_SKC_V6_DADDR))?,
                    u16::from_be(read::<u16>(sk, off(&OFF_SKC_DPORT))?),
                ),
            };
            // Dual-stack sockets carry v4-mapped peers; the wire traffic
            // is IPv4, so store the key the packet path will look up.
            if is_v4_mapped(&daddr) {
                let mut s4 = [0u8; 4];
                let mut d4 = [0u8; 4];
                s4.copy_from_slice(&saddr[12..16]);
                d4.copy_from_slice(&daddr[12..16]);
                return Ok(FlowKey::v4(proto, s4, sport, d4, dport));
            }
            Ok(FlowKey::v6(proto, saddr, sport, daddr, dport))
        }
        _ => Err(()),
    }
}

fn is_v4_mapped(addr: &[u8; 16]) -> bool {
    addr[..10] == [0u8; 10] && addr[10] == 0xff && addr[11] == 0xff
}

// Attached by userspace to both tcp_v4_connect and tcp_v6_connect.
#[kprobe]
pub fn tcp_connect_enter(ctx: ProbeContext) -> u32 {
    let Some(sk): Option<*const u8> = ctx.arg(0) else {
        return 0;
    };
    let _ = PROC_SCRATCH.insert(bpf_get_current_pid_tgid(), sk as u64, 0);
    0
}

// Attached by userspace to both tcp_v4_connect and tcp_v6_connect.
#[kretprobe]
pub fn tcp_connect_ret(ctx: RetProbeContext) -> u32 {
    let id = bpf_get_current_pid_tgid();
    let sk = match unsafe { PROC_SCRATCH.get(id) } {
        Some(sk) => *sk,
        None => return 0,
    };
    let _ = PROC_SCRATCH.remove(id);
    if ctx.ret::<i32>() != 0 {
        return 0; // connect failed; nothing to attribute
    }
    if let Ok(key) = unsafe { sock_flow_key(sk, PROTO_TCP, None) } {
        let _ = SOCK_MAP.insert(key, current_flow_val(), 0);
    }
    0
}

/// Shared body of the two UDP sendmsg probes. `addr_off`/`addr_len`
/// locate the address inside the sockaddr found at msg->msg_name.
fn udp_send(ctx: &ProbeContext, addr_off: usize, addr_len: usize) -> u32 {
    let (Some(sk), Some(msg)): (Option<*const u8>, Option<*const u8>) = (ctx.arg(0), ctx.arg(1))
    else {
        return 0;
    };
    let (sk, msg) = (sk as u64, msg as u64);
    let mut buf = [0u8; 16];
    let dest = unsafe {
        match read::<u64>(msg, off(&OFF_MSG_NAME)) {
            Ok(name) if name != 0 => {
                let port: u16 = match read(name, SIN_PORT) {
                    Ok(p) => u16::from_be(p),
                    Err(()) => return 0,
                };
                match read::<[u8; 16]>(name, addr_off) {
                    Ok(a) => buf = a,
                    Err(()) => {
                        // sockaddr_in is shorter than 16 bytes past
                        // sin_addr; retry with the exact 4 bytes.
                        match read::<[u8; 4]>(name, addr_off) {
                            Ok(a) => buf[..4].copy_from_slice(&a),
                            Err(()) => return 0,
                        }
                    }
                }
                Some((&buf[..addr_len], port))
            }
            _ => None, // connected UDP socket; peer lives in the sock
        }
    };
    if let Ok(key) = unsafe { sock_flow_key(sk, PROTO_UDP, dest) } {
        let _ = SOCK_MAP.insert(key, current_flow_val(), 0);
    }
    0
}

#[kprobe]
pub fn udp_sendmsg(ctx: ProbeContext) -> u32 {
    udp_send(&ctx, SIN_ADDR, 4)
}

#[kprobe]
pub fn udpv6_sendmsg(ctx: ProbeContext) -> u32 {
    udp_send(&ctx, SIN6_ADDR, 16)
}

// struct addrinfo field offsets, 64-bit glibc and musl (both lay the
// POSIX fields out identically: four ints, socklen_t + padding, then
// three pointers).
const AI_FAMILY: usize = 4; // int
const AI_ADDR: usize = 24; // struct sockaddr *
const AI_NEXT: usize = 40; // struct addrinfo *

/// Result-list entries walked per getaddrinfo call. Bounded for the
/// verifier; real resolutions rarely exceed a handful of addresses.
const MAX_ADDRS: usize = 10;

#[inline(always)]
unsafe fn read_user<T>(base: u64, off: usize) -> Result<T, ()> {
    bpf_probe_read_user((base as usize + off) as *const T).map_err(|_| ())
}

// Attached to glibc/musl getaddrinfo: int getaddrinfo(node, service,
// hints, struct addrinfo **res). The addrinfo offsets below are the
// 64-bit glibc/musl layout; a 32-bit process would need different
// offsets, so misreads there just drop events (reads are fault-safe).
#[uprobe]
pub fn getaddrinfo_enter(ctx: ProbeContext) -> u32 {
    let (Some(node), Some(res)): (Option<*const u8>, Option<*const u8>) = (ctx.arg(0), ctx.arg(3))
    else {
        return 0;
    };
    if node.is_null() || res.is_null() {
        return 0;
    }
    // Capture the name NOW: getaddrinfo blocks for the resolution, during
    // which another thread could rewrite the buffer, so reading it at
    // return could bind a real address to a forged name and poison the
    // domain cache. Reading it here pins it to this call. The value is
    // assembled in per-CPU scratch to stay off the BPF stack.
    let Some(scratch) = DNS_SCRATCH_BUF.get_ptr_mut(0) else {
        return 0;
    };
    let scratch = unsafe { &mut *scratch };
    scratch.res = res as u64;
    scratch.name_len = 0;
    match unsafe { bpf_probe_read_user_str_bytes(node as *const u8, &mut scratch.name) } {
        Ok(s) if !s.is_empty() => scratch.name_len = s.len() as u32,
        _ => return 0,
    }
    let _ = DNS_SCRATCH.insert(bpf_get_current_pid_tgid(), &*scratch, 0);
    0
}

#[uretprobe]
pub fn getaddrinfo_ret(ctx: RetProbeContext) -> u32 {
    let id = bpf_get_current_pid_tgid();
    let (Some(scratch), Some(ev)) = (
        unsafe { DNS_SCRATCH.get(id) },
        DNS_EVENT_BUF.get_ptr_mut(0),
    ) else {
        return 0;
    };
    let ev = unsafe { &mut *ev };
    let res = scratch.res;
    let failed = ctx.ret::<i32>() != 0;
    if !failed {
        ev.name_len = scratch.name_len;
        ev.name = scratch.name;
        ev._pad = [0u8; 3];
    }
    let _ = DNS_SCRATCH.remove(id);
    if failed {
        return 0; // resolution failed; nothing to record
    }

    // Walk the result list, one event per address.
    let mut ai: u64 = match unsafe { read_user(res, 0) } {
        Ok(p) => p,
        Err(()) => return 0,
    };
    for _ in 0..MAX_ADDRS {
        if ai == 0 {
            break;
        }
        let family: i32 = match unsafe { read_user(ai, AI_FAMILY) } {
            Ok(f) => f,
            Err(()) => return 0,
        };
        let sa: u64 = match unsafe { read_user(ai, AI_ADDR) } {
            Ok(p) => p,
            Err(()) => return 0,
        };
        if sa != 0 {
            let emitted = unsafe {
                match family as u8 {
                    AF_INET => match read_user::<[u8; 4]>(sa, SIN_ADDR) {
                        Ok(a) => {
                            ev.addr = [0u8; 16];
                            ev.addr[..4].copy_from_slice(&a);
                            ev.family = AF_INET;
                            true
                        }
                        Err(()) => false,
                    },
                    AF_INET6 => match read_user::<[u8; 16]>(sa, SIN6_ADDR) {
                        Ok(a) => {
                            ev.addr = a;
                            ev.family = AF_INET6;
                            true
                        }
                        Err(()) => false,
                    },
                    _ => false,
                }
            };
            if emitted {
                let _ = DNS_EVENTS.output::<DnsEvent>(&*ev, 0);
            }
        }
        ai = match unsafe { read_user(ai, AI_NEXT) } {
            Ok(p) => p,
            Err(()) => return 0,
        };
    }
    0
}

fn emit_event(kind: u32) {
    let ev = ExecEvent {
        pid: (bpf_get_current_pid_tgid() >> 32) as u32,
        kind,
    };
    let _ = EVENTS.output::<ExecEvent>(&ev, 0);
}

#[tracepoint]
pub fn sched_process_exec(_ctx: TracePointContext) -> u32 {
    emit_event(EVENT_EXEC);
    0
}

#[tracepoint]
pub fn sched_process_exit(_ctx: TracePointContext) -> u32 {
    let id = bpf_get_current_pid_tgid();
    // The tracepoint fires per thread; only whole-process exit matters.
    if (id >> 32) as u32 == id as u32 {
        emit_event(EVENT_EXIT);
    }
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    #[allow(clippy::empty_loop)]
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 4] = *b"GPL\0";
