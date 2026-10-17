//! Budgeted traversal of hash tables for `select`, `match`, `match_object` and `select_count`.
//!
//! The VM drives one cycle per call of [`Table::hash_scan`] and keeps what a trapped call
//! resumes from: the slot, the count and the results so far.

use super::*;
use match_spec::{HeadKey, MatchProgram};

/// Iterations of one traversal cycle before the call traps.
// Port of MAX_SELECT_CHUNK_ITERATIONS and MAX_SELECT_COUNT_ITERATIONS in
// erts/emulator/beam/erl_db_hash.c, OTP-29.1.1.
pub const HASH_SELECT_ITERATIONS: isize = 1000;

/// How much of a traversal another process may change underneath it.
// Port of `enum DbIterSafety` in erts/emulator/beam/erl_db.h and of ITERATION_SAFETY in
// erl_db.c, OTP-29.1.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IterSafety {
    /// Fine-grained locks: writers run during the cycle.
    Unsafe,
    /// The table lock keeps writers out of one cycle.
    SafeLocked,
    /// Only the calling process can write.
    Safe,
}

/// The buckets a traversal visits.
// Port of `struct mp_info` in erts/emulator/beam/erl_db_hash.c and of analyze_pattern,
// OTP-29.1.1.
pub struct HashScanPlan {
    key_slots: Option<Vec<usize>>,
    something_can_match: bool,
}

impl HashScanPlan {
    /// Every bucket in slot order, as a trapped call resumes.
    // Port of erts/emulator/beam/erl_db_hash.c, match_traverse_continue, OTP-29.1.1.
    pub fn all_slots() -> Self {
        Self {
            key_slots: None,
            something_can_match: true,
        }
    }

    /// Whether some clause can match any object.
    pub fn something_can_match(&self) -> bool {
        self.something_can_match
    }

    /// Whether every clause names its key, so only those buckets are visited and the
    /// traversal never traps.
    pub fn key_given(&self) -> bool {
        self.key_slots.is_some()
    }
}

/// Where one traversal cycle ended.
pub struct HashScanEnd {
    /// Iterations left of the budget; below zero when the last bucket ran past it.
    pub iterations_left: isize,
    /// The slot a trapped call resumes from, or `None` when the table is exhausted.
    pub trap_slot: Option<usize>,
}

/// Results of earlier cycles of a trapped `select`, kept outside the process heap.
// Port of the match_list a trapped call carries in its continuation (erl_db_hash.c,
// select_chunk_on_trap), OTP-29.1.1.
pub struct SavedMatches {
    heap: VecHeap,
    terms: Vec<Term>,
}

impl SavedMatches {
    /// No results yet.
    pub fn new() -> Self {
        Self {
            heap: VecHeap::new(),
            terms: Vec::new(),
        }
    }

    /// Keep the results of a cycle, oldest first.
    pub fn extend(&mut self, results: &[Term]) -> Result<(), EtsError> {
        for &term in results {
            self.terms.push(copy_term(term, &mut self.heap)?);
        }
        Ok(())
    }

    /// Whether no result was kept.
    pub fn is_empty(&self) -> bool {
        self.terms.is_empty()
    }

    /// The saved results as terms on `dst`, oldest first.
    pub fn copy_out<H: HeapAlloc>(&self, dst: &mut H) -> Result<Vec<Term>, EtsError> {
        self.terms
            .iter()
            .map(|&term| Ok(copy_term(term, dst)?))
            .collect()
    }
}

impl Default for SavedMatches {
    fn default() -> Self {
        Self::new()
    }
}

impl Table {
    /// Whether the table is a hash table (set, bag or duplicate_bag).
    pub fn is_hash(&self) -> bool {
        matches!(self.storage, Storage::Hash(_))
    }

    /// How safe a traversal by `caller` is without a fixation.
    // Port of erts/emulator/beam/erl_db.c (ITERATION_SAFETY, ONLY_WRITER), OTP-29.1.1.
    pub fn iteration_safety(&self, caller: Term) -> IterSafety {
        let only_writer =
            self.options.protection != Protection::Public && exact_eq(self.options.owner, caller);
        if !self.is_hash() || only_writer {
            IterSafety::Safe
        } else if self.options.write_concurrency != WriteConcurrency::Disabled {
            IterSafety::Unsafe
        } else {
            IterSafety::SafeLocked
        }
    }

    /// Choose the buckets for a program's clause heads.
    // Port of erts/emulator/beam/erl_db_hash.c, analyze_pattern, OTP-29.1.1.
    pub fn hash_scan_plan(&self, program: &MatchProgram) -> HashScanPlan {
        let Storage::Hash(storage) = &self.storage else {
            return HashScanPlan {
                key_slots: None,
                something_can_match: true,
            };
        };
        let fine_locked = self.options.write_concurrency != WriteConcurrency::Disabled;
        let mut slots: Vec<usize> = Vec::new();
        let mut key_given = true;
        let mut something_can_match = false;
        for head in program.head_keys(self.options.keypos) {
            if !key_given {
                break;
            }
            match head {
                HeadKey::Variable | HeadKey::Unbound => {
                    key_given = false;
                    something_can_match = true;
                }
                HeadKey::Missing => {}
                HeadKey::Bound(key) => {
                    let hash = ets_hash(key);
                    let slot = storage.slot_index(hash >> 1);
                    let present = fine_locked
                        || storage.with_objects_hash(hash, |mut objects| {
                            objects.any(|node| {
                                node.hvalue == (hash >> 1)
                                    && exact_eq(node.key(self.options.keypos), key)
                            })
                        });
                    if present {
                        if !slots.contains(&slot) {
                            slots.push(slot);
                        }
                        something_can_match = true;
                    }
                }
            }
        }
        HashScanPlan {
            key_slots: key_given.then_some(slots),
            something_can_match,
        }
    }

    /// One traversal cycle: visit objects from slot `from` until the table ends or the
    /// iteration budget is spent at a bucket boundary.
    // Port of erts/emulator/beam/erl_db_hash.c, match_traverse and match_traverse_continue,
    // OTP-29.1.1.
    pub(crate) fn hash_scan(
        &self,
        plan: &HashScanPlan,
        from: usize,
        mut iterations: isize,
        visit: &mut dyn FnMut(&StoredTerm) -> Result<(), EtsError>,
    ) -> Result<HashScanEnd, EtsError> {
        let Storage::Hash(storage) = &self.storage else {
            return Err(EtsError::BadArg);
        };
        let mut step = |slot: usize| -> Result<isize, EtsError> {
            let mut visited = 0;
            storage.try_with_slot_ordered(slot, false, |object, _| {
                visit(object)?;
                visited += 1;
                Ok::<_, EtsError>(())
            })?;
            Ok(visited)
        };
        if let Some(slots) = &plan.key_slots {
            for &slot in slots {
                iterations -= step(slot)?;
            }
            return Ok(HashScanEnd {
                iterations_left: iterations,
                trap_slot: None,
            });
        }
        if from >= storage.nactive() {
            return Err(EtsError::BadArg);
        }
        // Port of erts/emulator/beam/erl_db_hash.c, next_slot: a fine-locked table
        // visits the buckets of one lock after the other.
        let nlocks = if self.options.write_concurrency == WriteConcurrency::Disabled {
            1
        } else {
            storage.lock_count().max(1)
        };
        let mut slot = from;
        loop {
            iterations -= step(slot)?;
            slot += nlocks;
            if slot >= storage.nactive() {
                slot = (slot + 1) & (nlocks - 1);
                if slot == 0 {
                    return Ok(HashScanEnd {
                        iterations_left: iterations,
                        trap_slot: None,
                    });
                }
            }
            if iterations <= 0 {
                return Ok(HashScanEnd {
                    iterations_left: iterations,
                    trap_slot: Some(slot),
                });
            }
        }
    }

    /// One `select` cycle: the results in visit order and where the cycle ended.
    // Port of erts/emulator/beam/erl_db_hash.c, select_chunk_on_match_res,
    // OTP-29.1.1.
    pub fn hash_select_cycle<H: HeapAlloc>(
        &self,
        plan: &HashScanPlan,
        program: &MatchProgram,
        from: usize,
        dst: &mut H,
    ) -> Result<(HashScanEnd, Vec<Term>), EtsError> {
        let mut runner = program.runner();
        let mut results = Vec::new();
        let end = self.hash_scan(plan, from, HASH_SELECT_ITERATIONS, &mut |object| {
            let term = object.term_for_filter(dst)?;
            if let Some(result) = runner.run(term, dst)? {
                results.push(result);
            }
            Ok(())
        })?;
        Ok((end, results))
    }

    /// One `select_count` cycle: the objects the program selected and where the cycle ended.
    // Port of erts/emulator/beam/erl_db_hash.c, select_count_on_match_res,
    // OTP-29.1.1.
    pub fn hash_count_cycle(
        &self,
        plan: &HashScanPlan,
        program: &MatchProgram,
        from: usize,
    ) -> Result<(HashScanEnd, usize), EtsError> {
        let true_atom = Term::atom(global_true());
        let mut scratch = VecHeap::new();
        let mut count = 0;
        let end = self.hash_scan(plan, from, HASH_SELECT_ITERATIONS, &mut |object| {
            let term = object.term_for_filter(&mut scratch)?;
            if program
                .run(term, &mut scratch)?
                .is_some_and(|value| exact_eq(value, true_atom))
            {
                count += 1;
            }
            Ok(())
        })?;
        Ok((end, count))
    }
}
