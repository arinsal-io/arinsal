import re

with open("crates/pterm/src/lib.rs", "r") as f:
    content = f.read()

# Replace Table and its impl
table_str = """#[derive(Clone)]
struct Table {
    buckets: HashMap<u64, Vec<Arc<Stored>>>,
    count: usize,
    slots: usize,
}
impl Table {
    fn new() -> Self {
        Self {
            buckets: HashMap::new(),
            count: 0,
            slots: 8,
        }
    }
    fn find(&self, key: Term, hash: u64) -> Option<(usize, &Arc<Stored>)> {
        self.buckets
            .get(&hash)?
            .iter()
            .enumerate()
            .find(|(_, item)| exact_eq(item.key, key))
    }
}"""

# Port of erl_bif_persistent.c:42 (Parameters for the hash table)
new_table_str = """// Port of erts/emulator/beam/erl_bif_persistent.c:42 (Parameters for the hash table), OTP-29.1.1
const INITIAL_SIZE: usize = 8;
const LOAD_FACTOR: usize = 50;

#[derive(Clone)]
struct Table {
    allocated: usize,
    num_entries: usize,
    // Port of erts/emulator/beam/erl_bif_persistent.c:58 (hash_table), OTP-29.1.1
    term: Vec<Option<Arc<Stored>>>,
}

impl Table {
    fn new() -> Self {
        // Port of erts/emulator/beam/erl_bif_persistent.c:786 (create_initial_table), OTP-29.1.1
        Self {
            allocated: INITIAL_SIZE,
            num_entries: 0,
            term: vec![None; INITIAL_SIZE],
        }
    }

    // Port of erts/emulator/beam/erl_bif_persistent.c:46 (MUST_GROW), OTP-29.1.1
    fn must_grow(&self) -> bool {
        100 * self.num_entries >= LOAD_FACTOR * self.allocated
    }

    // Port of erts/emulator/beam/erl_bif_persistent.c:47 (MUST_SHRINK), OTP-29.1.1
    fn must_shrink(&self) -> bool {
        200 * self.num_entries <= LOAD_FACTOR * self.allocated && self.allocated > INITIAL_SIZE
    }

    // Port of erts/emulator/beam/erl_bif_persistent.c:1005 (lookup), OTP-29.1.1
    fn lookup(&self, key: Term, hash: u64) -> usize {
        let mask = self.allocated - 1;
        let mut idx = hash as usize;
        loop {
            let i = idx & mask;
            let bucket = &self.term[i];
            match bucket {
                None => return i,
                Some(stored) => {
                    if exact_eq(stored.key, key) {
                        return i;
                    }
                }
            }
            idx = idx.wrapping_add(1);
        }
    }
}"""

content = content.replace(table_str, new_table_str)

with open("crates/pterm/src/lib.rs", "w") as f:
    f.write(content)
