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
//! struct offsets: this program reads sock_common/msghdr fields at fixed
//! offsets valid for x86_64 kernels with CONFIG_NET_NS=y (every distro
//! kernel). If a field moves, lookups miss and hallpassd falls back to
//! procfs attribution; nothing breaks.

#![no_std]
#![no_main]
#![allow(clippy::result_unit_err)]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read_kernel},
    macros::{kprobe, kretprobe, map, tracepoint},
    maps::{HashMap, LruHashMap, RingBuf},
    programs::{ProbeContext, RetProbeContext, TracePointContext},
};
use hallpass_ebpf_common::{
    ExecEvent, FlowKey, FlowVal, AF_INET, AF_INET6, EVENT_EXEC, EVENT_EXIT, PROTO_TCP, PROTO_UDP,
};

// struct sock_common field offsets (x86_64, CONFIG_NET_NS=y).
const SKC_DADDR: usize = 0; // __be32
const SKC_RCV_SADDR: usize = 4; // __be32
const SKC_DPORT: usize = 12; // __be16
const SKC_NUM: usize = 14; // u16, host order
const SKC_FAMILY: usize = 16; // u16
const SKC_V6_DADDR: usize = 56; // struct in6_addr
const SKC_V6_RCV_SADDR: usize = 72; // struct in6_addr

// struct msghdr: msg_name is the first field.
const MSG_NAME: usize = 0;

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
    let family: u16 = read(sk, SKC_FAMILY)?;
    let sport: u16 = read(sk, SKC_NUM)?;
    match family as u8 {
        AF_INET => {
            let saddr: u32 = read(sk, SKC_RCV_SADDR)?;
            let (daddr, dport) = match dest {
                Some((addr, port)) if addr.len() >= 4 => {
                    ([addr[0], addr[1], addr[2], addr[3]], port)
                }
                _ => {
                    let d: u32 = read(sk, SKC_DADDR)?;
                    (d.to_ne_bytes(), u16::from_be(read::<u16>(sk, SKC_DPORT)?))
                }
            };
            Ok(FlowKey::v4(proto, saddr.to_ne_bytes(), sport, daddr, dport))
        }
        AF_INET6 => {
            let saddr: [u8; 16] = read(sk, SKC_V6_RCV_SADDR)?;
            let (daddr, dport): ([u8; 16], u16) = match dest {
                Some((addr, port)) if addr.len() >= 16 => {
                    let mut d = [0u8; 16];
                    d.copy_from_slice(&addr[..16]);
                    (d, port)
                }
                _ => (
                    read(sk, SKC_V6_DADDR)?,
                    u16::from_be(read::<u16>(sk, SKC_DPORT)?),
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
        match read::<u64>(msg, MSG_NAME) {
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
