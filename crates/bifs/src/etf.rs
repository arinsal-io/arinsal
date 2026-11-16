//! ETF BIFs over live process heap terms.
// Port of erts/emulator/beam/external.c (external term sizing, encoding, and decoding), OTP-29.1.1.

use std::sync::OnceLock;

static LOCAL_NODE_HASH: OnceLock<u32> = OnceLock::new();

// Port of erts/emulator/beam/external.c:134-194, OTP-29.1.1.
pub fn local_node_hash() -> u32 {
    *LOCAL_NODE_HASH.get_or_init(|| {
        let uname = rustix::system::uname();
        let hostname = uname.nodename().to_bytes();
        let hostname = &hostname[..hostname.len().min(255)];
        let pid = std::process::id().to_string();
        let offset =
            crate::time_offset_nanos_value().expect("the system time offset is available") as i64;
        let mut node_id = Vec::with_capacity(8 + hostname.len() + pid.len());
        node_id.extend_from_slice(&offset.to_le_bytes());
        node_id.extend_from_slice(hostname);
        node_id.extend_from_slice(pid.as_bytes());
        block_hash(&node_id, crate::monotonic_time_raw_nanos() as u32)
    })
}

/// Incremental Jenkins block hash used by `LOCAL_EXT`.
// Port of erts_block_hash_init/erts_block_hash in
// erts/emulator/beam/erl_term_hashing.c:450-577, OTP-29.1.1.
pub struct BlockHashWalk {
    a: u32,
    b: u32,
    c: u32,
    length: usize,
    cursor: usize,
    hash: Option<u32>,
}

impl BlockHashWalk {
    /// `erts_block_hash_init` over `length` bytes with the hash of this node as the seed, as
    /// `LOCAL_EXT` uses it.
    pub fn local(length: usize) -> Self {
        Self::new(length, local_node_hash())
    }

    /// The hash once `step` reported the end of the data.
    pub fn hash(&self) -> Option<u32> {
        self.hash
    }

    fn new(length: usize, initial: u32) -> Self {
        Self {
            a: 0x9e37_79b9,
            b: 0x9e37_79b9,
            c: initial,
            length,
            cursor: 0,
            hash: None,
        }
    }

    /// `erts_block_hash` with `budget` bytes: whether the data is done and the bytes hashed.
    pub fn step(&mut self, bytes: &[u8], budget: usize) -> (bool, usize) {
        if self.hash.is_some() {
            return (true, 0);
        }
        debug_assert_eq!(bytes.len(), self.length);
        let remaining = self.length - self.cursor;
        let (full, yields) = if budget < remaining {
            let full = budget / 12 * 12;
            if remaining > full + 12 {
                (full + 12, true)
            } else {
                (remaining - remaining % 12, false)
            }
        } else {
            (remaining - remaining % 12, false)
        };
        let end = self.cursor + full;
        let (chunks, remaining_chunks) = bytes[self.cursor..end].as_chunks::<12>();
        debug_assert!(remaining_chunks.is_empty());
        for chunk in chunks {
            self.a = self
                .a
                .wrapping_add(u32::from_le_bytes(chunk[0..4].try_into().unwrap()));
            self.b = self
                .b
                .wrapping_add(u32::from_le_bytes(chunk[4..8].try_into().unwrap()));
            self.c = self
                .c
                .wrapping_add(u32::from_le_bytes(chunk[8..12].try_into().unwrap()));
            (self.a, self.b, self.c) = block_hash_mix(self.a, self.b, self.c);
        }
        self.cursor = end;
        if yields {
            return (false, full);
        }

        let remaining_bytes = &bytes[self.cursor..];
        self.c = self.c.wrapping_add(self.length as u32);
        for (index, byte) in remaining_bytes.iter().enumerate() {
            match index {
                0..=3 => self.a = self.a.wrapping_add((*byte as u32) << (8 * index)),
                4..=7 => self.b = self.b.wrapping_add((*byte as u32) << (8 * (index - 4))),
                _ => self.c = self.c.wrapping_add((*byte as u32) << (8 * (index - 7))),
            }
        }
        self.cursor = self.length;
        self.c = block_hash_mix(self.a, self.b, self.c).2;
        self.hash = Some(self.c);
        (true, full + remaining_bytes.len())
    }
}

fn block_hash(bytes: &[u8], initial: u32) -> u32 {
    let mut walk = BlockHashWalk::new(bytes.len(), initial);
    let (done, _) = walk.step(bytes, usize::MAX);
    debug_assert!(done);
    walk.hash.expect("unlimited block hash completes")
}

#[inline]
fn block_hash_mix(mut a: u32, mut b: u32, mut c: u32) -> (u32, u32, u32) {
    a = a.wrapping_sub(b).wrapping_sub(c) ^ (c >> 13);
    b = b.wrapping_sub(c).wrapping_sub(a) ^ (a << 8);
    c = c.wrapping_sub(a).wrapping_sub(b) ^ (b >> 13);
    a = a.wrapping_sub(b).wrapping_sub(c) ^ (c >> 12);
    b = b.wrapping_sub(c).wrapping_sub(a) ^ (a << 16);
    c = c.wrapping_sub(a).wrapping_sub(b) ^ (b >> 5);
    a = a.wrapping_sub(b).wrapping_sub(c) ^ (c >> 3);
    b = b.wrapping_sub(c).wrapping_sub(a) ^ (a << 10);
    c = c.wrapping_sub(a).wrapping_sub(b) ^ (b >> 15);
    (a, b, c)
}

// Port of erts/emulator/beam/external.c:4046-4105, OTP-29.1.1.
pub fn local_term_hash(bytes: &[u8]) -> u32 {
    block_hash(bytes, local_node_hash())
}
