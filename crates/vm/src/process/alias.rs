use super::*;

const ALIAS_SLAB: usize = 4096;

const ALIAS_SLABS: usize = 256;

const ALIAS_INACTIVE: u64 = 1;

/// Alias → pid map. Dense reference ids use atomic slabs, so reply sends do
/// not acquire a global mutex after the slab's one-time allocation.
pub(super) struct AliasTable {
    slabs: Box<[OnceLock<Box<[AtomicU64]>>]>,
    /// Ids beyond the dense slabs (per-scheduler reference counters): sharded by id so the
    /// scheduler threads of unrelated processes do not meet on one lock.
    overflow: Box<[AliasShard]>,
}

const ALIAS_SHARDS: usize = 64;

type AliasShard = parking_lot::Mutex<
    HashMap<u64, (Option<Pid>, bool), std::hash::BuildHasherDefault<AliasHasher>>,
>;

/// Multiplicative hash of the reference id; ids are not attacker chosen.
#[derive(Default)]
struct AliasHasher(u64);

impl std::hash::Hasher for AliasHasher {
    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 = (self.0 ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3);
        }
    }

    fn write_u64(&mut self, value: u64) {
        self.0 = value.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    }

    fn finish(&self) -> u64 {
        self.0 ^ (self.0 >> 32)
    }
}

fn alias_shard(id: u64) -> usize {
    ((id.wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 40) as usize) % ALIAS_SHARDS
}

impl AliasTable {
    pub(super) fn new() -> Self {
        Self {
            slabs: (0..ALIAS_SLABS).map(|_| OnceLock::new()).collect(),
            overflow: (0..ALIAS_SHARDS)
                .map(|_| parking_lot::Mutex::new(HashMap::default()))
                .collect(),
        }
    }

    fn encode(target: Option<Pid>, priority: bool) -> u64 {
        match target {
            None => ALIAS_INACTIVE,
            // Pid data is 60 bits. Bit 60 marks a live alias
            // so the inactive sentinel `1` cannot collide with pid 0. Bit 61
            // marks a priority alias (OTP 28+).
            Some(pid) => {
                const PRESENT: u64 = 1 << 60;
                const PRIORITY: u64 = 1 << 61;
                let mut raw = PRESENT | pid.data();
                if priority {
                    raw |= PRIORITY;
                }
                raw
            }
        }
    }

    fn decode(raw: u64) -> Option<(Option<Pid>, bool)> {
        if raw == 0 {
            return None;
        }
        if raw == ALIAS_INACTIVE {
            return Some((None, false));
        }
        const PRESENT: u64 = 1 << 60;
        const PRIORITY: u64 = 1 << 61;
        if raw & PRESENT == 0 {
            return None;
        }
        Some((Some(Pid::from_data(raw)), raw & PRIORITY != 0))
    }

    pub(super) fn load(&self, id: u64) -> Option<(Option<Pid>, bool)> {
        if id / ALIAS_SLAB as u64 >= ALIAS_SLABS as u64 {
            return self.overflow[alias_shard(id)].lock().get(&id).copied();
        }
        let slab = self.slabs.get((id / ALIAS_SLAB as u64) as usize)?.get()?;
        let slot = (id % ALIAS_SLAB as u64) as usize;
        let raw = slab[slot].load(Ordering::Acquire);
        Self::decode(raw)
    }

    pub(super) fn store(&self, id: u64, target: Option<Pid>, priority: bool) {
        if id / ALIAS_SLAB as u64 >= ALIAS_SLABS as u64 {
            self.overflow[alias_shard(id)]
                .lock()
                .insert(id, (target, priority && target.is_some()));
            return;
        }
        let slab = self.slabs[(id / ALIAS_SLAB as u64) as usize]
            .get_or_init(|| (0..ALIAS_SLAB).map(|_| AtomicU64::new(0)).collect());
        let slot = (id % ALIAS_SLAB as u64) as usize;
        slab[slot].store(
            Self::encode(target, priority && target.is_some()),
            Ordering::Release,
        );
    }
}
