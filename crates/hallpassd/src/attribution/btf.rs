//! Minimal read-only BTF parser: resolve struct field byte offsets from
//! the kernel's type descriptions in /sys/kernel/btf/vmlinux.
//!
//! The eBPF attribution programs read fields of `struct sock_common` and
//! `struct msghdr` with `bpf_probe_read_kernel`. Their offsets differ
//! across kernel versions, configs, and architectures, so hardcoding them
//! is fragile. This module resolves the real offsets at daemon startup;
//! the loader patches them into the programs as globals, with the
//! compiled-in x86_64 defaults as the fallback when BTF is unavailable.
//!
//! Only what offset resolution needs is implemented: the type section is
//! walked once to index all types, then struct lookups by name descend
//! through named members and anonymous struct/union members (accumulating
//! bit offsets) until the requested field is found. aya's own BTF walker
//! is `pub(crate)`, hence this ~200-line standalone parser instead of a
//! new dependency.
//!
//! Format reference: Documentation/bpf/btf.rst in the kernel tree.

/// BTF type kinds (BTF_KIND_*).
const KIND_INT: u32 = 1;
const KIND_ARRAY: u32 = 3;
const KIND_STRUCT: u32 = 4;
const KIND_UNION: u32 = 5;
const KIND_ENUM: u32 = 6;
const KIND_TYPEDEF: u32 = 8;
const KIND_VOLATILE: u32 = 9;
const KIND_CONST: u32 = 10;
const KIND_RESTRICT: u32 = 11;
const KIND_FUNC_PROTO: u32 = 13;
const KIND_VAR: u32 = 14;
const KIND_DATASEC: u32 = 15;
const KIND_DECL_TAG: u32 = 17;
const KIND_ENUM64: u32 = 19;
const KIND_MAX: u32 = 19;

/// Parsed BTF blob with an index of type record offsets.
pub struct Btf {
    data: Vec<u8>,
    /// Byte offset of each type record inside `data`; type id = index + 1.
    types: Vec<usize>,
    str_start: usize,
    str_len: usize,
}

fn u16_at(data: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(data.get(off..off + 2)?.try_into().ok()?))
}

fn u32_at(data: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(off..off + 4)?.try_into().ok()?))
}

impl Btf {
    /// Parse the kernel's BTF from /sys/kernel/btf/vmlinux.
    pub fn from_sys_fs() -> Result<Btf, String> {
        let data = std::fs::read("/sys/kernel/btf/vmlinux")
            .map_err(|e| format!("read /sys/kernel/btf/vmlinux: {e}"))?;
        Btf::from_bytes(data)
    }

    /// Parse a raw BTF blob (header + type section + string section).
    pub fn from_bytes(data: Vec<u8>) -> Result<Btf, String> {
        if u16_at(&data, 0) != Some(0xeb9f) {
            return Err("bad BTF magic".into());
        }
        let hdr_len = u32_at(&data, 4).ok_or("truncated header")? as usize;
        let type_off = u32_at(&data, 8).ok_or("truncated header")? as usize;
        let type_len = u32_at(&data, 12).ok_or("truncated header")? as usize;
        let str_off = u32_at(&data, 16).ok_or("truncated header")? as usize;
        let str_len = u32_at(&data, 20).ok_or("truncated header")? as usize;

        let type_start = hdr_len.checked_add(type_off).ok_or("type_off overflow")?;
        let type_end = type_start.checked_add(type_len).ok_or("type_len overflow")?;
        let str_start = hdr_len.checked_add(str_off).ok_or("str_off overflow")?;
        if type_end > data.len() || str_start.saturating_add(str_len) > data.len() {
            return Err("sections exceed blob".into());
        }

        // Index the type section: each record is 12 bytes of btf_type plus
        // kind-dependent trailing data.
        let mut types = Vec::new();
        let mut pos = type_start;
        while pos < type_end {
            let info = u32_at(&data, pos + 4).ok_or("truncated type record")?;
            let kind = (info >> 24) & 0x1f;
            let vlen = (info & 0xffff) as usize;
            if kind > KIND_MAX {
                return Err(format!("unknown BTF kind {kind}"));
            }
            let extra = match kind {
                KIND_INT | KIND_VAR | KIND_DECL_TAG => 4,
                KIND_ARRAY => 12,
                KIND_STRUCT | KIND_UNION | KIND_DATASEC | KIND_ENUM64 => vlen * 12,
                KIND_ENUM | KIND_FUNC_PROTO => vlen * 8,
                _ => 0,
            };
            types.push(pos);
            pos = pos
                .checked_add(12 + extra)
                .filter(|p| *p <= type_end)
                .ok_or("type record exceeds section")?;
        }
        Ok(Btf {
            data,
            types,
            str_start,
            str_len,
        })
    }

    /// NUL-terminated string at `name_off` in the string section.
    fn name(&self, name_off: u32) -> Option<&str> {
        let start = self.str_start + name_off as usize;
        let end = self.str_start + self.str_len;
        let bytes = self.data.get(start..end)?;
        let nul = bytes.iter().position(|b| *b == 0)?;
        std::str::from_utf8(&bytes[..nul]).ok()
    }

    fn kind_of(&self, rec: usize) -> Option<u32> {
        Some((u32_at(&self.data, rec + 4)? >> 24) & 0x1f)
    }

    /// Record offset for a type id (ids are 1-based; 0 is `void`).
    fn record(&self, type_id: u32) -> Option<usize> {
        self.types.get(type_id.checked_sub(1)? as usize).copied()
    }

    /// Follow typedef/const/volatile/restrict chains to the concrete type.
    fn resolve(&self, mut type_id: u32) -> Option<u32> {
        for _ in 0..16 {
            let rec = self.record(type_id)?;
            match self.kind_of(rec)? {
                KIND_TYPEDEF | KIND_CONST | KIND_VOLATILE | KIND_RESTRICT => {
                    type_id = u32_at(&self.data, rec + 8)?;
                }
                _ => return Some(type_id),
            }
        }
        None // modifier cycle; malformed
    }

    /// Type id of the first struct named `name`. One linear scan of the
    /// type table; callers doing several lookups on the same struct
    /// should resolve the id once and use [`Btf::field_offset`].
    pub fn struct_id(&self, name: &str) -> Option<u32> {
        (1..=self.types.len() as u32).find(|id| {
            self.record(*id).is_some_and(|rec| {
                self.kind_of(rec) == Some(KIND_STRUCT)
                    && u32_at(&self.data, rec)
                        .and_then(|n| self.name(n))
                        .is_some_and(|n| n == name)
            })
        })
    }

    /// Bit offset of `field` inside struct/union `type_id`, descending
    /// into anonymous struct/union members.
    fn field_bit_offset(&self, type_id: u32, field: &str, depth: u32) -> Option<u32> {
        if depth > 8 {
            return None;
        }
        let rec = self.record(self.resolve(type_id)?)?;
        let info = u32_at(&self.data, rec + 4)?;
        let kind = (info >> 24) & 0x1f;
        if kind != KIND_STRUCT && kind != KIND_UNION {
            return None;
        }
        let vlen = info & 0xffff;
        let kind_flag = info >> 31 == 1;
        for i in 0..vlen {
            // btf_member { name_off, type, offset } after the 12-byte header.
            let m = rec + 12 + (i as usize) * 12;
            let name_off = u32_at(&self.data, m)?;
            let raw_off = u32_at(&self.data, m + 8)?;
            // With kind_flag, offset packs (bitfield_size << 24 | bit_offset).
            let (bitfield, bit_off) = if kind_flag {
                (raw_off >> 24, raw_off & 0x00ff_ffff)
            } else {
                (0, raw_off)
            };
            if name_off != 0 {
                if self.name(name_off) == Some(field) {
                    // A bitfield has no byte offset to patch in.
                    return (bitfield == 0).then_some(bit_off);
                }
            } else {
                // Anonymous struct/union: search inside it.
                let inner = u32_at(&self.data, m + 4)?;
                if let Some(off) = self.field_bit_offset(inner, field, depth + 1) {
                    return Some(bit_off + off);
                }
            }
        }
        None
    }

    /// Byte offset of `field` within struct/union `type_id`, or None when
    /// the field is missing, is a bitfield, or is not byte-aligned.
    pub fn field_offset(&self, type_id: u32, field: &str) -> Option<u32> {
        let bits = self.field_bit_offset(type_id, field, 0)?;
        (bits % 8 == 0).then_some(bits / 8)
    }

    /// [`Btf::field_offset`] with the struct looked up by name.
    pub fn struct_field_offset(&self, struct_name: &str, field: &str) -> Option<u32> {
        self.field_offset(self.struct_id(struct_name)?, field)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic BTF blob from (kind, name, size_or_type, extra)
    /// records plus a string table.
    struct Blob {
        types: Vec<u8>,
        strings: Vec<u8>,
        count: u32,
    }

    impl Blob {
        fn new() -> Blob {
            Blob {
                types: Vec::new(),
                strings: vec![0], // offset 0 = anonymous
                count: 0,
            }
        }

        fn intern(&mut self, s: &str) -> u32 {
            let off = self.strings.len() as u32;
            self.strings.extend_from_slice(s.as_bytes());
            self.strings.push(0);
            off
        }

        /// Append one type record; returns its 1-based id.
        fn ty(&mut self, name: &str, kind: u32, vlen: u32, kind_flag: bool, size_or_type: u32, extra: &[u32]) -> u32 {
            let name_off = if name.is_empty() { 0 } else { self.intern(name) };
            let info = (u32::from(kind_flag) << 31) | (kind << 24) | vlen;
            for w in [name_off, info, size_or_type] {
                self.types.extend_from_slice(&w.to_le_bytes());
            }
            for w in extra {
                self.types.extend_from_slice(&w.to_le_bytes());
            }
            self.count += 1;
            self.count
        }

        fn build(&self) -> Vec<u8> {
            let mut out = Vec::new();
            out.extend_from_slice(&0xeb9fu16.to_le_bytes());
            out.push(1); // version
            out.push(0); // flags
            out.extend_from_slice(&24u32.to_le_bytes()); // hdr_len
            out.extend_from_slice(&0u32.to_le_bytes()); // type_off
            out.extend_from_slice(&(self.types.len() as u32).to_le_bytes());
            out.extend_from_slice(&(self.types.len() as u32).to_le_bytes()); // str_off
            out.extend_from_slice(&(self.strings.len() as u32).to_le_bytes());
            out.extend_from_slice(&self.types);
            out.extend_from_slice(&self.strings);
            out
        }
    }

    /// A struct with a plain member, an anonymous union holding a nested
    /// anonymous struct (the sock_common skc_daddr shape), and a bitfield.
    fn fixture() -> Btf {
        let mut b = Blob::new();
        // id 1: u32
        b.ty("u32", KIND_INT, 0, false, 4, &[0]);
        // id 2: anonymous inner struct { daddr @0; saddr @32 }
        let daddr = b.intern("daddr");
        let saddr = b.intern("saddr");
        b.ty("", KIND_STRUCT, 2, false, 8, &[daddr, 1, 0, saddr, 1, 32]);
        // id 3: anonymous union { whole @0; <anon struct id 2> @0 }
        let whole = b.intern("whole");
        b.ty("", KIND_UNION, 2, false, 8, &[whole, 1, 0, 0, 2, 0]);
        // id 4: struct outer { family @0; <anon union> @64; flags:4 @128 }
        let family = b.intern("family");
        let flags = b.intern("flags");
        b.ty(
            "outer",
            KIND_STRUCT,
            3,
            true,
            24,
            &[family, 1, 0, 0, 3, 64, flags, 1, (4 << 24) | 128],
        );
        Btf::from_bytes(b.build()).unwrap()
    }

    #[test]
    fn named_and_nested_fields_resolve() {
        let btf = fixture();
        assert_eq!(btf.struct_field_offset("outer", "family"), Some(0));
        assert_eq!(btf.struct_field_offset("outer", "whole"), Some(8));
        // Through anon union, then anon struct: 64 + 32 bits = 12 bytes.
        assert_eq!(btf.struct_field_offset("outer", "daddr"), Some(8));
        assert_eq!(btf.struct_field_offset("outer", "saddr"), Some(12));
    }

    #[test]
    fn bitfields_and_missing_names_rejected() {
        let btf = fixture();
        assert_eq!(btf.struct_field_offset("outer", "flags"), None); // bitfield
        assert_eq!(btf.struct_field_offset("outer", "nope"), None);
        assert_eq!(btf.struct_field_offset("missing", "family"), None);
    }

    #[test]
    fn garbage_rejected() {
        assert!(Btf::from_bytes(vec![]).is_err());
        assert!(Btf::from_bytes(vec![0u8; 64]).is_err());
        let mut b = Blob::new();
        b.ty("x", 31, 0, false, 0, &[]); // unknown kind
        assert!(Btf::from_bytes(b.build()).is_err());
    }

    /// Against the live kernel, when available: the exact structs the
    /// eBPF programs read must resolve, at sane offsets.
    #[test]
    fn live_vmlinux_resolves_sock_common() {
        let Ok(btf) = Btf::from_sys_fs() else {
            eprintln!("SKIP: no /sys/kernel/btf/vmlinux");
            return;
        };
        let sk_common = btf.struct_field_offset("sock", "__sk_common").unwrap();
        assert_eq!(sk_common, 0, "__sk_common is documented as first in struct sock");
        for field in [
            "skc_daddr",
            "skc_rcv_saddr",
            "skc_dport",
            "skc_num",
            "skc_family",
            "skc_v6_daddr",
            "skc_v6_rcv_saddr",
        ] {
            let off = btf.struct_field_offset("sock_common", field).unwrap();
            assert!(off < 256, "{field} offset {off} implausible");
        }
        assert!(btf.struct_field_offset("msghdr", "msg_name").is_some());
    }
}
