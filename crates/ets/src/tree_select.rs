//! Budgeted traversal of ordered tables for `select`, `match`, `match_object` and
//! `select_count`.
//!
//! The VM drives one cycle per call of [`Table::tree_scan`] and keeps what a trapped call
//! resumes from: the key of the last object visited, the count and the results so far.

use super::*;
use match_spec::{MatchProgram, TreeKeys, cmp_partly_bound};

/// Objects one traversal cycle visits before the call traps.
// Port of the `sc.max = 1000` in db_select_tree_common, db_select_continue_tree_common and
// db_select_count_tree_common in erts/emulator/beam/erl_db_tree.c, OTP-29.1.1.
pub const TREE_SELECT_ITERATIONS: isize = 1000;

/// A key kept outside the table, where writers cannot free it.
pub struct SavedKey {
    heap: VecHeap,
    term: Term,
}

impl SavedKey {
    /// Copy `key` out of its heap.
    pub fn new(key: Term) -> Result<Self, EtsError> {
        let mut heap = VecHeap::new();
        let term = copy_term(key, &mut heap)?;
        Ok(Self { heap, term })
    }

    /// The key.
    pub fn term(&self) -> Term {
        let _keep_live = &self.heap;
        self.term
    }
}

/// Where a trapped traversal resumes.
pub enum ScanPosition {
    /// The next bucket of a hash table.
    Slot(usize),
    /// The key of the last object an ordered table traversal visited.
    After(SavedKey),
}

/// The keys a traversal of an ordered table visits.
// Port of `struct mp_info` and analyze_pattern in erts/emulator/beam/erl_db_tree.c,
// OTP-29.1.1.
pub struct TreeScanPlan {
    keys: TreeKeys,
}

impl TreeScanPlan {
    /// Whether no clause head can match any object.
    pub fn impossible(&self) -> bool {
        matches!(self.keys, TreeKeys::Impossible)
    }

    /// Whether every clause names the same fully bound key, so one lookup finds the only
    /// candidate and the call never traps.
    pub fn key_bound(&self) -> bool {
        matches!(self.keys, TreeKeys::Bound)
    }

    /// Whether a resumed traversal that stopped on the budget at `key` is done anyway because
    /// `key` lies beyond the range the clause heads name.
    // Port of erts/emulator/beam/erl_db_tree.c, db_select_continue_tree_common and
    // db_select_count_continue_tree_common, OTP-29.1.1.
    pub fn past_end(&self, backwards: bool, key: Term) -> bool {
        self.end_condition(backwards).is_some_and(|end| {
            let order = cmp_partly_bound(end, key);
            (backwards && order > 0) || (!backwards && order < 0)
        })
    }

    /// The key a chunked traversal in the given direction stops beyond, as its continuation
    /// carries it.
    pub fn end_condition_term(&self, backwards: bool) -> Option<Term> {
        self.end_condition(backwards)
    }

    /// Where a traversal in the given direction stops. A traversal that starts at the high
    /// end stops below `least`, one that starts at the low end stops above `most`.
    fn end_condition(&self, backwards: bool) -> Option<Term> {
        match self.keys {
            TreeKeys::Partial { least, most } => Some(if backwards { least } else { most }),
            _ => None,
        }
    }
}

/// Where one traversal cycle ended.
pub struct TreeScanEnd {
    /// Objects left of the budget; zero when the cycle stopped on it.
    pub iterations_left: isize,
    /// The key the next cycle resumes after, when the cycle stopped before the table or the
    /// range ended.
    pub resume_key: Option<SavedKey>,
}

impl TreeScanEnd {
    /// A resumed cycle that stopped on the budget beyond the key range ends the call.
    fn finish_resumed(&mut self, plan: &TreeScanPlan, backwards: bool, resumed: bool) {
        if resumed
            && self
                .resume_key
                .as_ref()
                .is_some_and(|key| plan.past_end(backwards, key.term()))
        {
            self.resume_key = None;
        }
    }
}

impl Table {
    /// Whether the table is an ordered_set, with or without write concurrency.
    pub fn is_ordered(&self) -> bool {
        matches!(self.storage, Storage::Ordered(_) | Storage::CATree(_))
    }

    /// Classify the keys a program's clause heads name.
    // Port of erts/emulator/beam/erl_db_tree.c, analyze_pattern, OTP-29.1.1.
    pub fn tree_scan_plan(&self, program: &MatchProgram) -> TreeScanPlan {
        TreeScanPlan {
            keys: program.tree_keys(self.options.keypos),
        }
    }

    /// One traversal cycle. `visit` returns true to stop after the object it was given (a
    /// chunk is full); the cycle also stops when `max` objects were visited, and, in the first
    /// cycle of a call, before an object outside the key range, which costs nothing. A resumed
    /// cycle (`after` is given) runs on through objects outside the range.
    // Port of erts/emulator/beam/erl_db_tree.c, traverse_backwards, traverse_forward,
    // doit_select, doit_select_count and doit_select_chunk, OTP-29.1.1.
    pub(crate) fn tree_scan(
        &self,
        plan: &TreeScanPlan,
        backwards: bool,
        after: Option<Term>,
        mut max: isize,
        visit: &mut dyn FnMut(&StoredTerm) -> Result<bool, EtsError>,
    ) -> Result<TreeScanEnd, EtsError> {
        let keypos = self.options.keypos;
        let end = plan.end_condition(backwards).filter(|_| after.is_none());
        let start = match (after, &plan.keys) {
            (None, TreeKeys::Partial { least, most }) => {
                Some(if backwards { *most } else { *least })
            }
            _ => None,
        };
        let eligible = |key: Term| -> bool {
            match (after, start) {
                (Some(cursor), _) => {
                    let order = cmp(key, cursor);
                    if backwards {
                        order == Ordering::Less
                    } else {
                        order == Ordering::Greater
                    }
                }
                (None, Some(bound)) => {
                    if backwards {
                        cmp_partly_bound(bound, key) >= 0
                    } else {
                        cmp_partly_bound(bound, key) <= 0
                    }
                }
                (None, None) => true,
            }
        };
        let mut resume_key = None;
        let mut step = |object: &StoredTerm| -> Result<bool, EtsError> {
            let key = object.key(keypos);
            if let Some(end) = end {
                let order = cmp_partly_bound(end, key);
                if (backwards && order > 0) || (!backwards && order < 0) {
                    return Ok(true);
                }
            }
            let full = visit(object)?;
            max -= 1;
            let stop = full || max <= 0;
            if stop {
                resume_key = Some(SavedKey::new(key)?);
            }
            Ok(stop)
        };
        match &self.storage {
            Storage::Ordered(root) => {
                Node::scan_where(root, backwards, &eligible, keypos, &mut step)?;
            }
            Storage::CATree(tree) => {
                tree.scan_where(backwards, &eligible, &mut step)?;
            }
            Storage::Hash(_) => return Err(EtsError::BadArg),
        }
        Ok(TreeScanEnd {
            iterations_left: max,
            resume_key,
        })
    }

    /// One `select` cycle: the results in visit order and where the cycle ended.
    // Port of erts/emulator/beam/erl_db_tree.c, doit_select, OTP-29.1.1.
    pub fn tree_select_cycle<H: HeapAlloc>(
        &self,
        plan: &TreeScanPlan,
        program: &MatchProgram,
        backwards: bool,
        after: Option<Term>,
        dst: &mut H,
    ) -> Result<(TreeScanEnd, Vec<Term>), EtsError> {
        let mut runner = program.runner();
        let mut results = Vec::new();
        let mut end = self.tree_scan(
            plan,
            backwards,
            after,
            TREE_SELECT_ITERATIONS,
            &mut |object| {
                let term = object.term_for_filter(dst)?;
                if let Some(result) = runner.run(term, dst)? {
                    results.push(result);
                }
                Ok(false)
            },
        )?;
        end.finish_resumed(plan, backwards, after.is_some());
        Ok((end, results))
    }

    /// One chunked `select` cycle: the results in visit order, where the cycle ended and how
    /// many results the call holds after it. The cycle stops when the chunk is full, and a
    /// resumed one does not stop at the end of the key range.
    // Port of erts/emulator/beam/erl_db_tree.c, doit_select_chunk, OTP-29.1.1.
    pub fn tree_chunk_cycle<H: HeapAlloc>(
        &self,
        plan: &TreeScanPlan,
        program: &MatchProgram,
        backwards: bool,
        after: Option<Term>,
        chunk: Chunk,
        dst: &mut H,
    ) -> Result<(TreeScanEnd, Vec<Term>, usize), EtsError> {
        let Chunk {
            size: chunk,
            held: got,
        } = chunk;
        let mut runner = program.runner();
        let mut results = Vec::new();
        let mut held = got;
        let end = self.tree_scan(
            plan,
            backwards,
            after,
            TREE_SELECT_ITERATIONS,
            &mut |object| {
                let term = object.term_for_filter(dst)?;
                if let Some(result) = runner.run(term, dst)? {
                    results.push(result);
                    held += 1;
                }
                Ok(held == chunk)
            },
        )?;
        Ok((end, results, held))
    }

    /// One `select_count` cycle: the objects the program selected and where the cycle ended.
    // Port of erts/emulator/beam/erl_db_tree.c, doit_select_count, OTP-29.1.1.
    pub fn tree_count_cycle(
        &self,
        plan: &TreeScanPlan,
        program: &MatchProgram,
        after: Option<Term>,
    ) -> Result<(TreeScanEnd, usize), EtsError> {
        let true_atom = Term::atom(global_true());
        let mut scratch = VecHeap::new();
        let mut count = 0;
        let mut end = self.tree_scan(plan, true, after, TREE_SELECT_ITERATIONS, &mut |object| {
            let term = object.term_for_filter(&mut scratch)?;
            if program
                .run(term, &mut scratch)?
                .is_some_and(|value| exact_eq(value, true_atom))
            {
                count += 1;
            }
            Ok(false)
        })?;
        end.finish_resumed(plan, true, after.is_some());
        Ok((end, count))
    }
}
