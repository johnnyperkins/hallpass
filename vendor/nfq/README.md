# nfq - NetFilter queue for Rust

Vendored from nfq 0.2.5 (crates.io, upstream commit 73598c8) and patched for
hallpassd, which uses it through `[patch.crates-io]` in the workspace root.
The changes, all in `src/lib.rs`:

- `recv` no longer fails on a non-zero error ack. It counts it (see
  `take_ack_errors`) and keeps parsing the batch, so the packet messages
  after it are not lost.
- `set_copy_range` sizes the receive buffer for the largest range set on the
  socket, not the most recent one.
- `set_recv_buffer_size_force` sets `SO_RCVBUFFORCE`.
- `get_hw_addr` spells out a borrow that current rustc denies as an implicit
  autoref when the crate builds as a path dependency (same semantics).

`nfq` is Rust library for performing userspace handling of packets queued by the kernel packet
packet filter chains.

## License
In contrast to `libnetfilter_queue` which is licensed under GPL 2.0, which will require all
binaries using that library to be bound by GPL, `nfq` is dual-licensed under MIT/Apache-2.0.
`nfq` achieves this by communicates with kernel via NETLINK sockets directly.

## Example

Here is an example which accepts all packets.
```rust
use nfq::{Queue, Verdict};

fn main() -> std::io::Result<()> {
   let mut queue = Queue::open()?; 
   queue.bind(0)?;
   loop {
       let mut msg = queue.recv()?;
       msg.set_verdict(Verdict::Accept);
       queue.verdict(msg)?;
   }
   Ok(())
}
```
