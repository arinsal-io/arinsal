// Port of erts/emulator/beam/hash.c (hash_init, hash_get_slot, hash_put, hash_remove, rehash)
// and erl_child_setup.c (forker_hash_init, fhash, fcmp), OTP-29.1.1.

/// The `HashBucket` prefix followed by the `ErtsSysExitStatus` PID and port payload.
#[repr(C)]
struct HashBucket {
    next: Option<Box<HashBucket>>,
    hvalue: usize,
    os_pid: libc::pid_t,
    port_id: u64,
}

/// The process-local `Hash` used for child PID to port mappings.
pub(super) struct Hash {
    shift: usize,
    max_shift: usize,
    shrink_threshold: isize,
    grow_threshold: usize,
    nobjs: usize,
    bucket: Vec<Option<Box<HashBucket>>>,
}

impl Hash {
    /// `hash_new(0, "forker_hash", 16, forker_hash_functions)`.
    pub(super) fn new() -> Self {
        let mut shift = 1;
        while (1usize << shift) < 16 {
            shift += 1;
        }
        let shift = usize::BITS as usize - shift;
        let mut hash = Self {
            shift,
            max_shift: shift,
            shrink_threshold: 0,
            grow_threshold: 0,
            nobjs: 0,
            bucket: empty_buckets(1usize << (usize::BITS as usize - shift)),
        };
        hash.set_thresholds();
        hash
    }

    /// `hash_put`: existing entries retain their original `port_id`.
    pub(super) fn put(&mut self, os_pid: libc::pid_t, port_id: u64) {
        let hvalue = fhash(os_pid);
        let ix = self.slot(hvalue);
        let mut bucket = self.bucket[ix].as_deref();
        while let Some(entry) = bucket {
            if entry.hvalue == hvalue && fcmp(os_pid, entry.os_pid) {
                return;
            }
            bucket = entry.next.as_deref();
        }

        self.bucket[ix] = Some(Box::new(HashBucket {
            next: self.bucket[ix].take(),
            hvalue,
            os_pid,
            port_id,
        }));
        self.nobjs += 1;
        if self.nobjs > self.grow_threshold {
            self.rehash(true);
        }
    }

    /// `hash_remove`: unlink and return the entry, without a value replacement.
    pub(super) fn remove(&mut self, os_pid: libc::pid_t) -> Option<u64> {
        let hvalue = fhash(os_pid);
        let ix = self.slot(hvalue);
        let mut link = &mut self.bucket[ix];
        while let Some(entry) = link {
            if entry.hvalue == hvalue && fcmp(os_pid, entry.os_pid) {
                let mut removed = link.take().expect("matched hash bucket");
                *link = removed.next.take();
                self.nobjs -= 1;
                if (self.nobjs as isize) < self.shrink_threshold {
                    self.rehash(false);
                }
                return Some(removed.port_id);
            }
            link = &mut link.as_mut().expect("present hash bucket").next;
        }
        None
    }

    /// `set_thresholds` in hash.c.
    fn set_thresholds(&mut self) {
        let slots = self.bucket.len();
        self.grow_threshold = (8 * slots) / 5;
        self.shrink_threshold = if self.shift < self.max_shift {
            (slots / 5) as isize
        } else {
            -1
        };
    }

    /// `hash_get_slot` from hash.h, with the platform `UWord` width.
    fn slot(&self, hvalue: usize) -> usize {
        let hvalue = hvalue ^ (hvalue >> self.shift);
        #[cfg(target_pointer_width = "64")]
        let multiplier = 11_400_714_819_323_198_485usize;
        #[cfg(target_pointer_width = "32")]
        let multiplier = 2_654_435_769usize;
        multiplier.wrapping_mul(hvalue) >> self.shift
    }

    /// `rehash`: relink existing buckets in old slot and chain order.
    fn rehash(&mut self, grow: bool) {
        if grow {
            self.shift -= 1;
        } else {
            if self.shift == self.max_shift {
                return;
            }
            self.shift += 1;
        }

        let mut new_bucket = empty_buckets(1usize << (usize::BITS as usize - self.shift));
        for mut chain in std::mem::take(&mut self.bucket) {
            while let Some(mut entry) = chain {
                chain = entry.next.take();
                let ix = self.slot(entry.hvalue);
                entry.next = new_bucket[ix].take();
                new_bucket[ix] = Some(entry);
            }
        }
        self.bucket = new_bucket;
        self.set_thresholds();
    }
}

fn empty_buckets(size: usize) -> Vec<Option<Box<HashBucket>>> {
    std::iter::repeat_with(|| None).take(size).collect()
}

/// `fcmp`: compare the signed `pid_t` key.
fn fcmp(left: libc::pid_t, right: libc::pid_t) -> bool {
    left == right
}

/// `fhash`: six-round 32-bit integer mix from erl_child_setup.c.
fn fhash(os_pid: libc::pid_t) -> usize {
    let mut value = os_pid as u32;
    value = value.wrapping_add(0x7ed5_5d16).wrapping_add(value << 12);
    value = (value ^ 0xc761_c23c) ^ (value >> 19);
    value = value.wrapping_add(0x1656_67b1).wrapping_add(value << 5);
    value = value.wrapping_add(0xd3a2_646c) ^ (value << 9);
    value = value.wrapping_add(0xfd70_46c5).wrapping_add(value << 3);
    value = (value ^ 0xb55a_4f09) ^ (value >> 16);
    value as usize
}

#[cfg(test)]
mod tests {
    use super::Hash;

    #[test]
    fn child_setup_hash_uses_erts_growth_and_floor_size() {
        let mut hash = Hash::new();
        similar_asserts::assert_eq!(hash.bucket.len(), 16);

        for pid in 1..=26 {
            hash.put(pid, pid as u64);
        }
        similar_asserts::assert_eq!(hash.bucket.len(), 32);

        for pid in 1..=21 {
            similar_asserts::assert_eq!(hash.remove(pid), Some(pid as u64));
        }
        similar_asserts::assert_eq!(hash.bucket.len(), 16);

        for pid in 22..=26 {
            similar_asserts::assert_eq!(hash.remove(pid), Some(pid as u64));
        }
        similar_asserts::assert_eq!(hash.bucket.len(), 16);
    }

    #[test]
    fn child_setup_hash_put_keeps_existing_pid_entry() {
        let mut hash = Hash::new();
        hash.put(7, 11);
        hash.put(7, 13);
        similar_asserts::assert_eq!(hash.remove(7), Some(11));
        similar_asserts::assert_eq!(hash.remove(7), None);
    }
}
