//! `binary:compile_pattern/1`, `match/2,3`, `matches/2,3` and `split/2,3` of erl_bif_binary.c.
//!
//! Port of erts/emulator/beam/erl_bif_binary.c (binary_compile_pattern_1, do_binary_find,
//! binary_match, binary_matches, binary_split, binary_find_trap, the Boyer-Moore and
//! Aho-Corasick searches), OTP-29.1.1. Each BIF is `bif_table[].f` with `(c_p, reg, I)`. A
//! search that runs out of loop iterations keeps its context in a magic binary, disables
//! collection and `BIF_TRAP3`s to the hidden `erlang:binary_find_trap/3` export.

use std::ops::Deref;

use crate::bif_traps::TrapContext;
use crate::natives::bif::{badarg, bif_ret};
use crate::natives::erl_bif_lists::bif_trap;
use crate::natives::erl_iolist::charge;
use arinsal_beamasm::ProcessHeader;
use arinsal_bifs::{BifError, ProcessHeapHandle};
use arinsal_term::raw::{BinRef, Cons};
use arinsal_term::{HeapAlloc, MagicBin, Term, TermBuilder, TermKind, global_atoms};

/// The bytes of a byte-sized binary (`erts_get_aligned_binary_bytes`), copied when unaligned.
fn with_binary_input<R>(
    term: Term,
    f: impl FnOnce(&[u8]) -> Result<R, BifError>,
) -> Result<R, BifError> {
    arinsal_term::erl_bits::with_aligned_bytes(term, f).unwrap_or(Err(BifError::BADARG))
}

/// The bytes of a byte-sized binary as an owned vector.
fn binary_bytes(term: Term) -> Result<Vec<u8>, BifError> {
    with_binary_input(term, |bytes| Ok(bytes.to_vec()))
}

fn atom_name(term: Term) -> Option<String> {
    global_atoms()
        .text(term.as_atom()?)
        .map(|name| name.to_string())
}

fn cons_cell(term: Term) -> Option<(Term, Term)> {
    Cons::try_from(term).ok().map(Cons::pair)
}

/// The elements of a proper list.
fn proper_list(term: Term) -> Result<Vec<Term>, BifError> {
    let mut items = Vec::new();
    let mut rest = term;
    while rest != Term::NIL {
        let (head, tail) = cons_cell(rest).ok_or(BifError::BADARG)?;
        items.push(head);
        rest = tail;
    }
    Ok(items)
}

fn tuple_arity(term: Term) -> Result<usize, BifError> {
    arinsal_bifs::tuple_arity(term)
}

fn tuple_element(term: Term, index: usize) -> Result<Term, BifError> {
    arinsal_bifs::tuple_element(term, index)
}

fn iolist_cons(term: Term) -> Result<(Term, Term), BifError> {
    cons_cell(term).ok_or(BifError::BADARG)
}

// Boyer–Moore and Aho–Corasick search used by the `binary` BIFs.

const ALPHABET_SIZE: usize = 256;
const NO_NODE: usize = usize::MAX;
const MC_LOOP_FACTOR: usize = 8;

/// Compiled search data shared by `binary:compile_pattern/1` and search calls.
#[derive(Clone)]
pub(crate) enum SearchPattern {
    BoyerMoore(BoyerMoore),
    AhoCorasick(AhoCorasick),
}

/// Temporary search data belongs to one BIF call; compiled patterns retain their magic owner.
pub(crate) enum SearchPatternHandle {
    Owned(SearchPattern),
    /// The compiled pattern's magic binary (`erts_magic_ref2bin` of the `{bm | ac, Ref}`).
    Shared(arinsal_term::MagicBin),
}

impl Deref for SearchPatternHandle {
    type Target = SearchPattern;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Owned(pattern) => pattern,
            Self::Shared(magic) => magic
                .downcast_ref::<SearchPattern>()
                .expect("a shared pattern handle holds a compiled pattern"),
        }
    }
}

// erl_bif_binary.c: cleanup_my_data_bm / cleanup_my_data_ac are the destructors of the
// compiled pattern binaries.
arinsal_term::magic_payload!(SearchPattern => cleanup_my_data);

impl SearchPattern {
    /// Build the search data selected by OTP from the number of patterns.
    // Port of erts/emulator/beam/erl_bif_binary.c:470-615 (create_bmdata,
    // ac_add_one_pattern, ac_compute_failure_functions), OTP-29.1.1.
    pub(crate) fn compile_single(pattern: &[u8]) -> Result<Self, BifError> {
        if pattern.is_empty() {
            return Err(BifError::BADARG);
        }
        Ok(Self::BoyerMoore(BoyerMoore::new(pattern)?))
    }

    pub(crate) fn compile(patterns: Vec<Vec<u8>>) -> Result<Self, BifError> {
        if patterns.len() == 1 {
            return Self::compile_single(&patterns[0]);
        }
        Ok(Self::AhoCorasick(AhoCorasick::new(&patterns)?))
    }

    pub(crate) fn tag(&self) -> &'static str {
        match self {
            Self::BoyerMoore(_) => "bm",
            Self::AhoCorasick(_) => "ac",
        }
    }

    /// Payload bytes allocated by OTP's `create_bmdata` or `create_acdata`.
    pub(crate) fn erts_payload_size(&self) -> usize {
        match self {
            Self::BoyerMoore(pattern) => pattern.erts_payload_size,
            Self::AhoCorasick(trie) => trie.erts_payload_size,
        }
    }
}

#[derive(Clone)]
pub(crate) struct BoyerMoore {
    data: Vec<[u8; 8]>,
    width: usize,
    pattern_offset: usize,
    good_shift_offset: usize,
    bad_shift_offset: usize,
    erts_payload_size: usize,
}

impl BoyerMoore {
    // Port of erts/emulator/beam/erl_bif_binary.c:385-515 (compute shifts and
    // create_bmdata), OTP-29.1.1.
    fn new(pattern: &[u8]) -> Result<Self, BifError> {
        let width = pattern.len();
        if width == 0 {
            return Err(BifError::BADARG);
        }
        // BMData and its aligned arrays share one magic-binary allocation in ERTS.
        let pattern_offset: usize = 4;
        let pattern_words = width.div_ceil(8);
        let good_shift_offset = pattern_offset
            .checked_add(pattern_words)
            .ok_or(BifError::SystemLimit)?;
        let bad_shift_offset = good_shift_offset
            .checked_add(if width > 1 { width } else { 0 })
            .ok_or(BifError::SystemLimit)?;
        let data_words = bad_shift_offset
            .checked_add(if width > 1 { ALPHABET_SIZE } else { 0 })
            .ok_or(BifError::SystemLimit)?;
        let erts_payload_size = data_words.checked_mul(8).ok_or(BifError::SystemLimit)?;
        let mut data = Vec::new();
        data.try_reserve_exact(data_words)
            .map_err(|_| BifError::SystemLimit)?;
        data.resize(data_words, [0; 8]);
        data[0] = (width as u64).to_ne_bytes();
        data[1] = (pattern_offset as u64).to_ne_bytes();
        data[2] = (good_shift_offset as u64).to_ne_bytes();
        data[3] = (bad_shift_offset as u64).to_ne_bytes();
        for (index, byte) in pattern.iter().copied().enumerate() {
            data[pattern_offset + index / 8][index % 8] = byte;
        }

        if width > 1 {
            for index in 0..width {
                data[good_shift_offset + index] = (width as u64).to_ne_bytes();
            }
            for index in 0..ALPHABET_SIZE {
                data[bad_shift_offset + index] = (width as u64).to_ne_bytes();
            }
            for index in 0..width - 1 {
                data[bad_shift_offset + pattern[index] as usize] =
                    ((width - index - 1) as u64).to_ne_bytes();
            }
            let suffixes = suffixes(pattern)?;
            let mut j = 0;
            for i in (-1_isize..=(width as isize - 1)).rev() {
                if i == -1 || suffixes[i as usize] == i + 1 {
                    while j < width as isize - 1 - i {
                        let slot = good_shift_offset + j as usize;
                        if u64::from_ne_bytes(data[slot]) == width as u64 {
                            data[slot] = ((width as isize - 1 - i) as u64).to_ne_bytes();
                        }
                        j += 1;
                    }
                }
            }
            for i in 0..=(width as isize - 2) {
                data[good_shift_offset + width - 1 - suffixes[i as usize] as usize] =
                    ((width as isize - 1 - i) as u64).to_ne_bytes();
            }
        }

        Ok(Self {
            data,
            width,
            pattern_offset,
            good_shift_offset,
            bad_shift_offset,
            erts_payload_size,
        })
    }

    fn pattern_byte(&self, index: usize) -> u8 {
        self.data[self.pattern_offset + index / 8][index % 8]
    }

    fn good_shift(&self, index: usize) -> usize {
        u64::from_ne_bytes(self.data[self.good_shift_offset + index]) as usize
    }

    fn bad_shift(&self, index: usize) -> usize {
        u64::from_ne_bytes(self.data[self.bad_shift_offset + index]) as usize
    }
}

// Port of erts/emulator/beam/erl_bif_binary.c:413-437 (compute_suffixes), OTP-29.1.1.
fn suffixes(pattern: &[u8]) -> Result<Vec<isize>, BifError> {
    let width = isize::try_from(pattern.len()).map_err(|_| BifError::SystemLimit)?;
    let mut suffixes = Vec::new();
    suffixes
        .try_reserve_exact(pattern.len())
        .map_err(|_| BifError::SystemLimit)?;
    suffixes.resize(pattern.len(), 0);
    suffixes[pattern.len() - 1] = width;

    let mut f = 0_isize;
    let mut g = width - 1;
    for i in (0..width - 1).rev() {
        let reuse = i > g && suffixes[(i + width - 1 - f) as usize] < i - g;
        if reuse {
            suffixes[i as usize] = suffixes[(i + width - 1 - f) as usize];
        } else {
            if i < g {
                g = i;
            }
            f = i;
            while g >= 0 && pattern[g as usize] == pattern[(g + width - 1 - f) as usize] {
                g -= 1;
            }
            suffixes[i as usize] = f - g;
        }
    }
    Ok(suffixes)
}

#[derive(Clone)]
pub(crate) struct AhoCorasick {
    nodes: Vec<Node>,
    erts_payload_size: usize,
}

#[derive(Clone)]
struct Node {
    depth: u32,
    final_pattern: i32,
    failure: usize,
    edges: [usize; ALPHABET_SIZE],
}

impl Node {
    fn new(depth: u32) -> Self {
        Self {
            depth,
            final_pattern: 0,
            failure: NO_NODE,
            edges: [NO_NODE; ALPHABET_SIZE],
        }
    }
}

impl AhoCorasick {
    // Port of erts/emulator/beam/erl_bif_binary.c:518-615
    // (ac_add_one_pattern, ac_compute_failure_functions), OTP-29.1.1.
    fn new(patterns: &[Vec<u8>]) -> Result<Self, BifError> {
        let max_nodes = patterns
            .iter()
            .try_fold(1_usize, |sum, pattern| sum.checked_add(pattern.len()))
            .ok_or(BifError::SystemLimit)?;
        // Port of AC_SIZE: reserve one C ACNode per input byte plus the root and one ACTrie.
        const C_AC_NODE_SIZE: usize = 2064;
        const C_AC_TRIE_SIZE: usize = 16;
        let erts_payload_size = max_nodes
            .checked_mul(C_AC_NODE_SIZE)
            .and_then(|nodes| nodes.checked_add(C_AC_TRIE_SIZE))
            .ok_or(BifError::SystemLimit)?;
        let mut nodes = Vec::new();
        nodes
            .try_reserve_exact(max_nodes)
            .map_err(|_| BifError::SystemLimit)?;
        nodes.push(Node::new(0));

        for (pattern_index, pattern) in patterns.iter().enumerate() {
            let final_pattern =
                i32::try_from(pattern_index + 1).map_err(|_| BifError::SystemLimit)?;
            let mut state = 0;
            for (offset, &byte) in pattern.iter().enumerate() {
                let next = nodes[state].edges[byte as usize];
                if next == NO_NODE {
                    let next = nodes.len();
                    let depth = u32::try_from(offset + 1).map_err(|_| BifError::SystemLimit)?;
                    nodes.push(Node::new(depth));
                    nodes[state].edges[byte as usize] = next;
                    state = next;
                } else {
                    state = next;
                }
            }
            if nodes[state].final_pattern == 0 {
                nodes[state].final_pattern = final_pattern;
            }
        }

        let mut queue = Vec::new();
        queue
            .try_reserve_exact(nodes.len().saturating_sub(1))
            .map_err(|_| BifError::SystemLimit)?;
        for byte in 0..ALPHABET_SIZE {
            let child = nodes[0].edges[byte];
            if child != NO_NODE {
                nodes[child].failure = 0;
                queue.push(child);
            }
        }

        let mut queue_head = 0;
        while queue_head < queue.len() {
            let parent = queue[queue_head];
            queue_head += 1;
            for byte in 0..ALPHABET_SIZE {
                let child = nodes[parent].edges[byte];
                if child == NO_NODE {
                    continue;
                }
                queue.push(child);
                let mut failure = nodes[parent].failure;
                while failure != NO_NODE && nodes[failure].edges[byte] == NO_NODE {
                    failure = nodes[failure].failure;
                }
                let target = if failure == NO_NODE {
                    let root_target = nodes[0].edges[byte];
                    if root_target == NO_NODE {
                        0
                    } else {
                        root_target
                    }
                } else {
                    nodes[failure].edges[byte]
                };
                nodes[child].failure = target;
                if nodes[child].final_pattern == 0 && nodes[target].final_pattern != 0 {
                    nodes[child].final_pattern = -1;
                }
            }
        }
        nodes[0].failure = 0;
        Ok(Self {
            nodes,
            erts_payload_size,
        })
    }
}

enum SearchState {
    BoyerMooreFirst {
        position: usize,
        found: Option<(usize, usize)>,
        done: bool,
    },
    BoyerMooreAll {
        position: usize,
        found: Vec<(usize, usize)>,
        done: bool,
    },
    AhoCorasickFirst {
        state: usize,
        position: usize,
        candidate: Option<(usize, usize)>,
        done: bool,
    },
    AhoCorasickAll {
        state: usize,
        position: usize,
        found: Vec<(usize, usize)>,
        done: bool,
    },
}

/// Resumable OTP binary search state.
pub(crate) struct SearchWalk {
    len: usize,
    scope: (usize, usize),
    pattern: SearchPatternHandle,
    state: SearchState,
}

impl SearchWalk {
    fn pattern_payload_size(&self) -> usize {
        self.pattern.erts_payload_size()
    }

    /// `bf_context_export` of the pattern: the compiled data lives in a magic binary that the
    /// trap's third argument names (`ctx->pat_term`); a pattern that is already compiled
    /// (`{bm | ac, Ref}`) is that binary.
    pub(crate) fn export_pattern(&mut self, orig_size: usize) -> MagicBin {
        if let SearchPatternHandle::Shared(owner) = &self.pattern {
            return owner.clone();
        }
        let bin = MagicBin::with_orig_size_and_refn(
            (*self.pattern).clone(),
            orig_size,
            arinsal_bifs::next_ref_words(),
        );
        self.pattern = SearchPatternHandle::Shared(bin.clone());
        bin
    }

    /// `ctx->pat_bin = pat_bin`: the pattern of the trap's third argument.
    pub(crate) fn set_pattern(&mut self, owner: MagicBin) {
        self.pattern = SearchPatternHandle::Shared(owner);
    }

    /// Start searching at `scope.0` and stop at `scope.1`.
    // Port of erts/emulator/beam/erl_bif_binary.c:624-635, 827-833,
    // 892-900 (search-state initialization), OTP-29.1.1.
    pub(crate) fn new(
        len: usize,
        pattern: SearchPatternHandle,
        scope: (usize, usize),
        first_only: bool,
    ) -> Self {
        let too_short = match &*pattern {
            SearchPattern::BoyerMoore(bm) => bm.width > scope.1 - scope.0,
            SearchPattern::AhoCorasick(_) => false,
        };
        let state = match (&*pattern, first_only) {
            (SearchPattern::BoyerMoore(_), true) => SearchState::BoyerMooreFirst {
                position: scope.0,
                found: None,
                done: too_short,
            },
            (SearchPattern::BoyerMoore(_), false) => SearchState::BoyerMooreAll {
                position: scope.0,
                found: Vec::new(),
                done: too_short,
            },
            (SearchPattern::AhoCorasick(_), true) => SearchState::AhoCorasickFirst {
                state: 0,
                position: scope.0,
                candidate: None,
                done: scope.0 == scope.1,
            },
            (SearchPattern::AhoCorasick(_), false) => SearchState::AhoCorasickAll {
                state: 0,
                position: scope.0,
                found: Vec::new(),
                done: scope.0 == scope.1,
            },
        };
        Self {
            len,
            scope,
            pattern,
            state,
        }
    }

    /// Scan at most `budget` internal OTP search reductions.
    // Port of erts/emulator/beam/erl_bif_binary.c:637-699, 729-824,
    // 834-890, 918-1000 (incremental search loops), OTP-29.1.1.
    pub(crate) fn step(&mut self, bytes: &[u8], budget: usize) -> (bool, usize) {
        if budget == 0 {
            return (self.is_done(), 0);
        }
        match &*self.pattern {
            SearchPattern::BoyerMoore(pattern) => {
                Self::step_boyer_moore(pattern, bytes, self.scope.1, budget, &mut self.state)
            }
            SearchPattern::AhoCorasick(pattern) => match &mut self.state {
                SearchState::AhoCorasickFirst { .. } => Self::step_aho_corasick_first(
                    pattern,
                    bytes,
                    self.scope,
                    budget,
                    &mut self.state,
                ),
                SearchState::AhoCorasickAll { .. } => Self::step_aho_corasick_all(
                    pattern,
                    bytes,
                    self.scope.1,
                    budget,
                    &mut self.state,
                ),
                _ => unreachable!("pattern and search state are constructed together"),
            },
        }
    }

    /// Read one recorded match without copying the search result buffer.
    pub(crate) fn match_at(&self, index: usize) -> Option<(usize, usize)> {
        match &self.state {
            SearchState::BoyerMooreFirst { found, .. } => {
                if index == 0 {
                    *found
                } else {
                    None
                }
            }
            SearchState::BoyerMooreAll { found, .. }
            | SearchState::AhoCorasickAll { found, .. } => found.get(index).copied(),
            SearchState::AhoCorasickFirst { candidate, .. } => {
                if index != 0 {
                    return None;
                }
                let (node, start) = (*candidate)?;
                let SearchPattern::AhoCorasick(pattern) = &*self.pattern else {
                    unreachable!("Aho–Corasick state uses an Aho–Corasick pattern")
                };
                Some((start, pattern.nodes[node].depth as usize))
            }
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// Number of matches recorded so far.
    pub(crate) fn match_count(&self) -> usize {
        match &self.state {
            SearchState::BoyerMooreFirst { found, .. } => usize::from(found.is_some()),
            SearchState::BoyerMooreAll { found, .. }
            | SearchState::AhoCorasickAll { found, .. } => found.len(),
            SearchState::AhoCorasickFirst { candidate, .. } => usize::from(candidate.is_some()),
        }
    }

    pub(crate) fn is_done(&self) -> bool {
        match &self.state {
            SearchState::BoyerMooreFirst { done, .. }
            | SearchState::BoyerMooreAll { done, .. }
            | SearchState::AhoCorasickFirst { done, .. }
            | SearchState::AhoCorasickAll { done, .. } => *done,
        }
    }

    // Port of erts/emulator/beam/erl_bif_binary.c:834-890, 918-1000
    // (bm_find_first_match, bm_find_all_non_overlapping), OTP-29.1.1.
    fn step_boyer_moore(
        pattern: &BoyerMoore,
        bytes: &[u8],
        end: usize,
        budget: usize,
        state: &mut SearchState,
    ) -> (bool, usize) {
        match state {
            SearchState::BoyerMooreFirst {
                position,
                found,
                done,
            } => {
                let mut j = *position;
                let mut result = *found;
                let mut finished = *done;
                let mut work = 0;
                let width = pattern.width;
                let last = width - 1;

                if !finished {
                    let Some(last_byte_start) = j.checked_add(last) else {
                        *done = true;
                        return (true, work);
                    };
                    if last_byte_start >= end {
                        *done = true;
                        return (true, work);
                    }

                    let available = end - last_byte_start;
                    let read_limit = 1_usize
                        .saturating_add(budget.saturating_sub(1).saturating_mul(MC_LOOP_FACTOR));
                    let mem_read = available.min(read_limit);
                    if let Some(offset) = memchr::memchr(
                        pattern.pattern_byte(last),
                        &bytes[last_byte_start..last_byte_start + mem_read],
                    ) {
                        work = work.saturating_add((last + offset) / MC_LOOP_FACTOR);
                        j += offset;
                    } else {
                        work = work.saturating_add(mem_read / MC_LOOP_FACTOR);
                        j = j.saturating_add(mem_read);
                    }

                    loop {
                        if width > end || j > end - width {
                            finished = true;
                            break;
                        }
                        if work.saturating_add(1) >= budget {
                            work = budget;
                            break;
                        }
                        work += 1;
                        let mut index = width;
                        while index > 0 && pattern.pattern_byte(index - 1) == bytes[j + index - 1] {
                            index -= 1;
                        }
                        if index == 0 {
                            result = Some((j, width));
                            finished = true;
                            break;
                        }
                        let index = index - 1;
                        let hay_byte = bytes[j + index] as usize;
                        let bad = pattern.bad_shift(hay_byte) as isize - width as isize
                            + 1
                            + index as isize;
                        let good = pattern.good_shift(index) as isize;
                        j = j.saturating_add(good.max(bad) as usize);
                    }
                }

                *position = j;
                *found = result;
                *done = finished;
                (finished, work)
            }
            SearchState::BoyerMooreAll {
                position,
                found,
                done,
            } => {
                let mut j = *position;
                let mut matches = std::mem::take(found);
                let mut finished = *done;
                let mut work = 0;
                let width = pattern.width;
                let last = width - 1;
                let mut skip_memchr = false;

                while !finished {
                    if !skip_memchr {
                        let Some(last_byte_start) = j.checked_add(last) else {
                            finished = true;
                            break;
                        };
                        if last_byte_start >= end {
                            finished = true;
                            break;
                        }

                        let available = end - last_byte_start;
                        let read_limit = 1_usize.saturating_add(
                            budget
                                .saturating_sub(work)
                                .saturating_sub(1)
                                .saturating_mul(MC_LOOP_FACTOR),
                        );
                        let mem_read = available.min(read_limit);
                        if let Some(offset) = memchr::memchr(
                            pattern.pattern_byte(last),
                            &bytes[last_byte_start..last_byte_start + mem_read],
                        ) {
                            work = work.saturating_add((last + offset) / MC_LOOP_FACTOR);
                            j += offset;
                        } else {
                            work = work.saturating_add(mem_read / MC_LOOP_FACTOR);
                            j = j.saturating_add(mem_read);
                        }
                    }

                    if width > end || j > end - width {
                        finished = true;
                        break;
                    }
                    if work.saturating_add(1) >= budget {
                        work = budget;
                        break;
                    }
                    work += 1;
                    let mut index = width;
                    while index > 0 && pattern.pattern_byte(index - 1) == bytes[j + index - 1] {
                        index -= 1;
                    }
                    if index == 0 {
                        if matches.len() == matches.capacity() {
                            let additional = if matches.capacity() == 0 {
                                10
                            } else {
                                matches.capacity()
                            };
                            matches.reserve_exact(additional);
                        }
                        matches.push((j, width));
                        j += width;
                        skip_memchr = false;
                    } else {
                        let index = index - 1;
                        let hay_byte = bytes[j + index] as usize;
                        let bad = pattern.bad_shift(hay_byte) as isize - width as isize
                            + 1
                            + index as isize;
                        let good = pattern.good_shift(index) as isize;
                        j = j.saturating_add(good.max(bad) as usize);
                        skip_memchr = true;
                    }
                }

                *position = j;
                *found = matches;
                *done = finished;
                (finished, work)
            }
            _ => unreachable!("Boyer–Moore uses a Boyer–Moore state"),
        }
    }

    // Port of erts/emulator/beam/erl_bif_binary.c:637-699 (ac_find_first_match),
    // OTP-29.1.1.
    fn step_aho_corasick_first(
        pattern: &AhoCorasick,
        bytes: &[u8],
        scope: (usize, usize),
        budget: usize,
        state: &mut SearchState,
    ) -> (bool, usize) {
        let SearchState::AhoCorasickFirst {
            state: saved_state,
            position: saved_position,
            candidate: saved_candidate,
            done: saved_done,
        } = state
        else {
            unreachable!("Aho–Corasick first uses a first-match state")
        };
        let mut current = *saved_state;
        let mut position = *saved_position;
        let mut candidate = *saved_candidate;
        let mut done = *saved_done;
        let mut work = 0;
        while !done && position < scope.1 && work < budget {
            let byte = bytes[position] as usize;
            while pattern.nodes[current].edges[byte] == NO_NODE
                && pattern.nodes[current].failure != current
            {
                current = pattern.nodes[current].failure;
            }
            let next = pattern.nodes[current].edges[byte];
            if next != NO_NODE {
                current = next;
            }
            position += 1;
            work += 1;
            if let Some((_, candidate_start)) = candidate
                && (position - pattern.nodes[current].depth as usize) > candidate_start
            {
                done = true;
                break;
            }
            if pattern.nodes[current].final_pattern != 0 {
                let mut result_node = current;
                while pattern.nodes[result_node].final_pattern < 0 {
                    result_node = pattern.nodes[result_node].failure;
                }
                let start = position - pattern.nodes[result_node].depth as usize;
                let replace = candidate.is_none_or(|(old_node, old_start)| {
                    start < old_start
                        || (start == old_start
                            && pattern.nodes[old_node].depth < pattern.nodes[current].depth)
                });
                if replace {
                    candidate = Some((result_node, start));
                }
            }
        }
        done |= position >= scope.1;
        *saved_state = current;
        *saved_position = position;
        *saved_candidate = candidate;
        *saved_done = done;
        (done, work)
    }

    // Port of erts/emulator/beam/erl_bif_binary.c:729-824
    // (ac_find_all_non_overlapping), OTP-29.1.1.
    fn step_aho_corasick_all(
        pattern: &AhoCorasick,
        bytes: &[u8],
        end: usize,
        budget: usize,
        state: &mut SearchState,
    ) -> (bool, usize) {
        let SearchState::AhoCorasickAll {
            state: saved_state,
            position: saved_position,
            found: saved_found,
            done: saved_done,
        } = state
        else {
            unreachable!("Aho–Corasick all uses a match-all state")
        };
        let mut current = *saved_state;
        let mut position = *saved_position;
        let mut found = std::mem::take(saved_found);
        let mut done = *saved_done;
        let mut work = 0;
        // `if (--reds == 0)` before each byte: a call with `budget` left scans `budget - 1`.
        while !done && position < end && work + 1 < budget {
            let byte = bytes[position] as usize;
            while pattern.nodes[current].edges[byte] == NO_NODE
                && pattern.nodes[current].failure != current
            {
                current = pattern.nodes[current].failure;
            }
            let next = pattern.nodes[current].edges[byte];
            if next != NO_NODE {
                current = next;
            }
            position += 1;
            work += 1;
            if pattern.nodes[current].final_pattern != 0 {
                let mut result_node = current;
                while pattern.nodes[result_node].final_pattern != 0 {
                    while pattern.nodes[result_node].final_pattern < 0 {
                        result_node = pattern.nodes[result_node].failure;
                    }
                    let result_start = position - pattern.nodes[result_node].depth as usize;
                    let mut retained = found.len();
                    while retained > 0
                        && (found[retained - 1].0 > result_start
                            || (found[retained - 1].0 == result_start
                                && found[retained - 1].1
                                    < pattern.nodes[result_node].depth as usize))
                    {
                        retained -= 1;
                    }
                    if retained == 0 || {
                        let (last_position, last_len) = found[retained - 1];
                        last_position + last_len <= result_start
                    } {
                        found.truncate(retained);
                        if found.len() == found.capacity() {
                            let additional = if found.capacity() == 0 {
                                10
                            } else {
                                found.capacity()
                            };
                            found.reserve_exact(additional);
                        }
                        found.push((result_start, pattern.nodes[result_node].depth as usize));
                    }
                    result_node = pattern.nodes[result_node].failure;
                }
            }
        }
        done |= position >= end;
        *saved_state = current;
        *saved_position = position;
        *saved_found = found;
        *saved_done = done;
        (done, work)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use similar_asserts::assert_eq;

    fn search(
        bytes: &[u8],
        needle: &[u8],
        scope: (usize, usize),
        first_only: bool,
    ) -> Vec<(usize, usize)> {
        let pattern =
            SearchPatternHandle::Owned(SearchPattern::compile(vec![needle.to_vec()]).unwrap());
        let mut walk = SearchWalk::new(bytes.len(), pattern, scope, first_only);
        let mut steps = 0;
        while !walk.step(bytes, 10).0 {
            steps += 1;
            assert!(steps < bytes.len() + 2, "search made no progress");
        }
        (0..walk.match_count())
            .map(|index| walk.match_at(index).expect("recorded match"))
            .collect()
    }

    #[test]
    fn one_byte_pattern_minimum_search_window_matches_a_full_scan() {
        let bytes = b"zzzzzzzzzzza-z-a";
        for (needle, scope, first_only, expected) in [
            (&b"a"[..], (0, bytes.len()), true, vec![(11, 1)]),
            (&b"z"[..], (0, bytes.len()), true, vec![(0, 1)]),
            (&b"q"[..], (0, bytes.len()), true, vec![]),
            (&b"a"[..], (0, bytes.len()), false, vec![(11, 1), (15, 1)]),
            (&b"-"[..], (0, bytes.len()), false, vec![(12, 1), (14, 1)]),
            (&b"a"[..], (1, 3), true, vec![]),
            (&b"a"[..], (11, 16), false, vec![(11, 1), (15, 1)]),
        ] {
            assert_eq!(
                search(bytes, needle, scope, first_only),
                expected,
                "needle={needle:?} scope={scope:?} first_only={first_only}"
            );
        }
    }
}

fn compile_search_pattern(term: Term) -> Result<SearchPattern, BifError> {
    match term.classify() {
        TermKind::Bitstring => with_binary_input(term, SearchPattern::compile_single),
        TermKind::List => {
            let (head, tail) = iolist_cons(term)?;
            if tail == Term::NIL && head.classify() == TermKind::Bitstring {
                return with_binary_input(head, SearchPattern::compile_single);
            }
            let mut patterns = Vec::new();
            let mut remaining = term;
            while remaining != Term::NIL {
                let Some((candidate, tail)) = cons_cell(remaining) else {
                    return Err(BifError::BADARG);
                };
                let bytes = binary_bytes(candidate)?;
                if bytes.is_empty() {
                    return Err(BifError::BADARG);
                }
                patterns.push(bytes);
                remaining = tail;
            }
            SearchPattern::compile(patterns)
        }
        _ => Err(BifError::BADARG),
    }
}

// Port of erts/emulator/beam/erl_bif_binary.c:1004-1113, 1230-1270 (pattern extraction), OTP-29.1.1.
fn pattern(term: Term) -> Result<SearchPatternHandle, BifError> {
    if tuple_arity(term).ok() == Some(2) {
        let tag =
            atom_name(tuple_element(term, 0)?).filter(|tag| matches!(tag.as_str(), "bm" | "ac"));
        if let Some(tag) = tag {
            let reference = tuple_element(term, 1)?;
            let owner = reference.magic_owner().ok_or(BifError::BADARG)?;
            if owner
                .downcast_ref::<SearchPattern>()
                .is_none_or(|compiled| compiled.tag() != tag.as_str())
            {
                return Err(BifError::BADARG);
            }
            return Ok(SearchPatternHandle::Shared(owner));
        }
    }
    Ok(SearchPatternHandle::Owned(compile_search_pattern(term)?))
}

// Port of erts/emulator/beam/erl_bif_binary.c:1004-1113 (binary_compile_pattern_1), OTP-29.1.1.
fn compile_pattern_result<H: HeapAlloc + ?Sized>(
    heap: &mut H,
    arg: Term,
) -> Result<Term, BifError> {
    let compiled = compile_search_pattern(arg)?;
    let orig_size = arinsal_term::MAGIC_BIN_DATA_OFFSET + compiled.erts_payload_size();
    let tag = Term::atom(global_atoms().intern(compiled.tag()).expect("atom"));
    let reference = TermBuilder::new(heap)
        .magic_ref(MagicBin::with_orig_size_and_refn(
            compiled,
            orig_size,
            arinsal_bifs::next_ref_words(),
        ))
        .map_err(|_| BifError::SystemLimit)?;
    TermBuilder::new(heap)
        .tuple(&[tag, reference])
        .map_err(|_| BifError::SystemLimit)
}

// Port of erts/emulator/beam/erl_bif_binary.c:1273-1344 (parse_match_opts_list), OTP-29.1.1.
fn match_scope(len: usize, options: Term) -> Result<(usize, usize), BifError> {
    let mut scope = (0, len);
    for option in proper_list(options)? {
        scope = scope_option(len, option)?;
    }
    Ok(scope)
}

// Port of erts/emulator/beam/erl_bif_binary.c:1273-1400 (scope option parsing), OTP-29.1.1.
fn scope_option(len: usize, option: Term) -> Result<(usize, usize), BifError> {
    if tuple_arity(option)? != 2 || atom_name(tuple_element(option, 0)?).as_deref() != Some("scope")
    {
        return Err(BifError::BADARG);
    }
    let range = tuple_element(option, 1)?;
    if tuple_arity(range)? != 2 {
        return Err(BifError::BADARG);
    }
    let start = tuple_element(range, 0)?
        .as_small()
        .ok_or(BifError::BADARG)?;
    let length = tuple_element(range, 1)?
        .as_small()
        .ok_or(BifError::BADARG)?;
    let end = start.checked_add(length).ok_or(BifError::BADARG)?;
    let (lo, hi) = if length < 0 {
        (end, start)
    } else {
        (start, end)
    };
    if lo < 0 || hi < 0 || hi as usize > len {
        return Err(BifError::BADARG);
    }
    Ok((lo as usize, hi as usize))
}

/// Search operations supported by the binary BIF continuation.
#[derive(Clone, Copy)]
pub(crate) enum BinarySearchKind {
    /// Return the first matching range.
    Match,
    /// Return all non-overlapping matching ranges.
    Matches,
    /// Split at the first or all matching ranges.
    Split,
}

/// Resumable state for `binary:match/2,3`, `matches/2,3`, and `split/2,3`.
pub(crate) struct BinarySearchWalk {
    subject: Term,
    walk: SearchWalk,
    kind: BinarySearchKind,
    split_trim: bool,
    split_trim_all: bool,
    global: bool,
    result_left: Option<usize>,
}

impl BinarySearchWalk {
    /// `ctx->pat_bin = pat_bin` of `binary_find_trap`.
    fn set_pattern(&mut self, owner: MagicBin) {
        self.walk.set_pattern(owner);
    }

    /// `bf_context_export`'s pattern: see [`SearchWalk::export_pattern`].
    fn export_pattern(&mut self) -> MagicBin {
        let size = arinsal_term::MAGIC_BIN_DATA_OFFSET + self.walk.pattern_payload_size();
        self.walk.export_pattern(size)
    }

    /// Parse BIF options and prepare a Boyer–Moore or Aho–Corasick walk.
    pub fn new(kind: BinarySearchKind, args: &[Term]) -> Result<Self, BifError> {
        let compiled = pattern(args[1])?;
        let (walk, split_trim, split_trim_all, first_only) = with_binary_input(args[0], |bytes| {
            let (scope, first_only, split_trim, split_trim_all) = match kind {
                BinarySearchKind::Match => (
                    if args.len() == 3 {
                        match_scope(bytes.len(), args[2])?
                    } else {
                        (0, bytes.len())
                    },
                    true,
                    false,
                    false,
                ),
                BinarySearchKind::Matches => (
                    if args.len() == 3 {
                        match_scope(bytes.len(), args[2])?
                    } else {
                        (0, bytes.len())
                    },
                    false,
                    false,
                    false,
                ),
                BinarySearchKind::Split => {
                    let (global, trim, trim_all, scope) = if args.len() == 3 {
                        split_options(bytes.len(), args[2])?
                    } else {
                        (false, false, false, (0, bytes.len()))
                    };
                    (scope, !global, trim, trim_all)
                }
            };
            Ok((
                SearchWalk::new(bytes.len(), compiled, scope, first_only),
                split_trim,
                split_trim_all,
                first_only,
            ))
        })?;
        let global = !first_only;
        Ok(Self {
            subject: args[0],
            walk,
            kind,
            split_trim,
            split_trim_all,
            global,
            result_left: None,
        })
    }

    /// Run the search and result loops until completion or reduction exhaustion.
    // Port of erts/emulator/beam/erl_bif_binary.c (do_binary_find) and
    // 1671-1735, 1809-1915 (do_match_global_result, do_split_global_result), OTP-29.1.1.
    pub fn step(&mut self, budget: usize) -> (bool, usize) {
        let mut work = 0;
        if !self.walk.is_done() {
            let (done, used) =
                with_binary_input(self.subject, |bytes| Ok(self.walk.step(bytes, budget)))
                    .expect("search subject remains a live binary");
            if !done {
                return (false, used);
            }
            work = used;
        }
        // Port of do_match_global_result and do_split_global_result: the C callbacks
        // count one or two result-building passes before the final heap construction.
        let mut left = *self.result_left.get_or_insert_with(|| {
            let found = self.walk.match_count();
            match (self.kind, self.global) {
                (BinarySearchKind::Matches, _) => found * 2,
                (BinarySearchKind::Split, true) => found,
                _ => 0,
            }
        });
        // `if (--reds == 0)` before each item: a call with `reds` left builds `reds - 1`
        // items and then traps with none left (and the whole budget charged).
        let reds = budget.saturating_sub(work);
        if left > 0 {
            if left < reds {
                work += left;
                left = 0;
            } else {
                left -= reds.saturating_sub(1);
                work = budget;
            }
        }
        self.result_left = Some(left);
        (left == 0, work)
    }

    /// Build the BIF result after searching completes.
    pub fn finish<H: HeapAlloc + ?Sized>(&self, heap: &mut H) -> Result<Term, BifError> {
        let found_count = self.walk.match_count();
        match self.kind {
            BinarySearchKind::Match => match self.walk.match_at(0) {
                Some((position, length)) => match_result(heap, position, length),
                None => Ok(Term::atom(global_atoms().intern("nomatch").expect("atom"))),
            },
            BinarySearchKind::Matches => {
                let mut builder = TermBuilder::new(heap);
                let mut result = Term::NIL;
                for index in (0..found_count).rev() {
                    let (position, length) = self
                        .walk
                        .match_at(index)
                        .expect("match count matches recorded search results");
                    let position = builder
                        .int_from_i128(position as i128)
                        .map_err(|_| BifError::SystemLimit)?;
                    let length = builder
                        .int_from_i128(length as i128)
                        .map_err(|_| BifError::SystemLimit)?;
                    let tuple = builder
                        .tuple(&[position, length])
                        .map_err(|_| BifError::SystemLimit)?;
                    result = builder
                        .cons(tuple, result)
                        .map_err(|_| BifError::SystemLimit)?;
                }
                Ok(result)
            }
            BinarySearchKind::Split => {
                if found_count == 0 {
                    if (self.split_trim || self.split_trim_all) && self.walk.len() == 0 {
                        return Ok(Term::NIL);
                    }
                    return TermBuilder::new(heap)
                        .cons(self.subject, Term::NIL)
                        .map_err(|_| BifError::SystemLimit);
                }

                let mut builder = TermBuilder::new(heap);
                let mut result = Term::NIL;
                let mut end = self.walk.len();
                let mut trim_tail = self.split_trim;
                for index in (0..found_count).rev() {
                    let (position, length) = self
                        .walk
                        .match_at(index)
                        .expect("match count matches recorded search results");
                    let start = position + length;
                    let segment_len = end - start;
                    if segment_len != 0 || (!self.split_trim_all && !trim_tail) {
                        let segment = builder
                            .sub_binary_bif(self.subject, start * 8, segment_len * 8)
                            .map_err(|_| BifError::SystemLimit)?;
                        result = builder
                            .cons(segment, result)
                            .map_err(|_| BifError::SystemLimit)?;
                        trim_tail = false;
                    }
                    end = position;
                }
                if end != 0 || (!self.split_trim_all && !trim_tail) {
                    let prefix = builder
                        .sub_binary_bif(self.subject, 0, end * 8)
                        .map_err(|_| BifError::SystemLimit)?;
                    result = builder
                        .cons(prefix, result)
                        .map_err(|_| BifError::SystemLimit)?;
                }
                Ok(result)
            }
        }
    }
}

// Port of erts/emulator/beam/erl_bif_binary.c:1840-1850 (match result), OTP-29.1.1.
fn match_result<H: HeapAlloc + ?Sized>(
    heap: &mut H,
    position: usize,
    length: usize,
) -> Result<Term, BifError> {
    let mut builder = TermBuilder::new(heap);
    let position = builder
        .int_from_i128(position as i128)
        .map_err(|_| BifError::SystemLimit)?;
    let length = builder
        .int_from_i128(length as i128)
        .map_err(|_| BifError::SystemLimit)?;
    builder
        .tuple(&[position, length])
        .map_err(|_| BifError::SystemLimit)
}

// Port of erts/emulator/beam/erl_bif_binary.c:1346-1405 (parse_split_opts_list), OTP-29.1.1.
fn split_options(
    len: usize,
    options: Term,
) -> Result<(bool, bool, bool, (usize, usize)), BifError> {
    let mut global = false;
    let mut trim = false;
    let mut trim_all = false;
    let mut scope = (0, len);
    let mut rest = options;
    while rest != Term::NIL {
        let Some((option, tail)) = cons_cell(rest) else {
            return Err(BifError::BADARG);
        };
        rest = tail;
        match atom_name(option).as_deref() {
            Some("global") => global = true,
            Some("trim") => trim = true,
            Some("trim_all") => trim_all = true,
            _ => scope = scope_option(len, option)?,
        }
    }
    Ok((global, trim, trim_all, scope))
}

// ---- BIF entries -------------------------------------------------------------------------

/// `sizeof(BinaryFindContext)` on a 64-bit build: the magic binary's `orig_size`.
// Port of erts/emulator/beam/erl_bif_binary.c (BinaryFindContext), OTP-29.1.1.
const ERTS_BINARY_FIND_CONTEXT_SIZE: usize = 312;

const BINARY_FIND_TRAP: &str = "erlang:binary_find_trap/3";

/// The search loop's iterations per reduction (`ctx->loop_factor`).
const SEARCH_LOOP_FACTOR: usize = 10;

type FindHolder = TrapContext<BinarySearchWalk>;

arinsal_term::magic_payload!(FindHolder => bf_context_destructor);

/// `get_reds`: the loop iterations this call may run.
// Port of erts/emulator/beam/erl_bif_binary.c (get_reds), OTP-29.1.1.
fn get_reds(process: &crate::Process) -> usize {
    let reds = (process.heap.abi.fcalls.max(0) as usize).saturating_mul(SEARCH_LOOP_FACTOR);
    let limit = crate::natives::erts_debug::binary_loop_limit() as usize;
    if limit != 0 && limit < reds {
        return limit;
    }
    reds.max(1)
}

/// `binary:compile_pattern/1`.
// Port of erts/emulator/beam/erl_bif_binary.c (binary_compile_pattern_1), OTP-29.1.1.
pub(crate) extern "C" fn binary_compile_pattern_1(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [pattern] = crate::bif_table::bif_args::<1>(reg);
    let mut heap = ProcessHeapHandle(&mut process.heap);
    match compile_pattern_result(&mut heap, pattern) {
        Ok(result) => crate::native_hooks::raw(result),
        Err(error) => bif_ret(c_p, i, Err(find_error(error))),
    }
}

fn find_error(error: BifError) -> crate::VmError {
    match error {
        BifError::SystemLimit => crate::VmError::Trap(crate::exceptions::Trap::error(Term::atom(
            arinsal_term::atoms::SYSTEM_LIMIT,
        ))),
        _ => badarg(),
    }
}

/// `binary_match`, `binary_split` and the global variants: the search for `kind`, finished in
/// this call or trapped to `binary_find_trap/3` with the context in a magic binary.
// Port of erts/emulator/beam/erl_bif_binary.c (binary_match, binary_split, do_binary_find),
// OTP-29.1.1.
fn binary_find(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
    kind: BinarySearchKind,
    arity: usize,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let args = crate::bif_table::bif_arg_vec(reg, arity);
    let mut search = match BinarySearchWalk::new(kind, &args) {
        Ok(search) => search,
        Err(error) => return bif_ret(c_p, i, Err(find_error(error))),
    };
    let initial = get_reds(process);
    let (done, work) = search.step(initial);
    if !done {
        // The context leaves the stack for a magic binary and collection is disabled while
        // the call is parked.
        // `bf_context_export`: the context and the compiled pattern each get a magic binary,
        // and the trap carries both references (`ctx->trap_term`, `ctx->pat_term`).
        let pat_bin = search.export_pattern();
        let bin = MagicBin::with_erts_payload_size_and_refn(
            FindHolder::new(search),
            ERTS_BINARY_FIND_CONTEXT_SIZE,
            arinsal_bifs::next_ref_words(),
        );
        let refs = {
            let mut heap = ProcessHeapHandle(&mut process.heap);
            let mut builder = TermBuilder::new(&mut heap);
            builder
                .magic_ref(bin)
                .and_then(|mref| builder.magic_ref(pat_bin).map(|pat| (mref, pat)))
        };
        let Ok((mref, pat_term)) = refs else {
            return bif_ret(c_p, i, Err(find_error(BifError::SystemLimit)));
        };
        process.set_gc_enabled(false);
        process.heap.abi.fcalls = 0;
        let trap = bif_trap(process, BINARY_FIND_TRAP, vec![args[0], mref, pat_term]);
        return bif_ret(c_p, i, Err(trap));
    }
    charge(process, work / SEARCH_LOOP_FACTOR);
    find_result(c_p, i, process, &search)
}

/// The result of a finished search (`found` / `not_found` callbacks).
fn find_result(
    c_p: *mut ProcessHeader,
    i: u64,
    process: &mut crate::Process,
    search: &BinarySearchWalk,
) -> u64 {
    let mut heap = ProcessHeapHandle(&mut process.heap);
    match search.finish(&mut heap) {
        Ok(value) => crate::native_hooks::raw(value),
        Err(error) => bif_ret(c_p, i, Err(find_error(error))),
    }
}

/// `binary:match/2`.
pub(crate) extern "C" fn binary_match_2(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    binary_find(c_p, reg, i, BinarySearchKind::Match, 2)
}

/// `binary:match/3`.
pub(crate) extern "C" fn binary_match_3(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    binary_find(c_p, reg, i, BinarySearchKind::Match, 3)
}

/// `binary:matches/2`.
pub(crate) extern "C" fn binary_matches_2(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    binary_find(c_p, reg, i, BinarySearchKind::Matches, 2)
}

/// `binary:matches/3`.
pub(crate) extern "C" fn binary_matches_3(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    binary_find(c_p, reg, i, BinarySearchKind::Matches, 3)
}

/// `binary:split/2`.
pub(crate) extern "C" fn binary_split_2(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    binary_find(c_p, reg, i, BinarySearchKind::Split, 2)
}

/// `binary:split/3`.
pub(crate) extern "C" fn binary_split_3(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    binary_find(c_p, reg, i, BinarySearchKind::Split, 3)
}

/// `erlang:binary_find_trap/3`.
// Port of erts/emulator/beam/erl_bif_binary.c (binary_find_trap), OTP-29.1.1.
pub(crate) extern "C" fn binary_find_trap(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [subject, mref, pattern] = crate::bif_table::bif_args::<3>(reg);
    let initial = get_reds(process);
    let Some(pat_bin) = pattern.magic_owner() else {
        return bif_ret(c_p, i, Err(badarg()));
    };
    let stepped = mref.with_magic_payload::<FindHolder, _>(|holder| {
        let mut search = holder.lock().expect("binary_find context");
        // `ctx->pat_bin = pat_bin`.
        search.set_pattern(pat_bin);
        let (done, work) = search.step(initial);
        if !done {
            return (false, work, None);
        }
        let mut heap = ProcessHeapHandle(&mut process.heap);
        (true, work, Some(search.finish(&mut heap)))
    });
    match stepped {
        Some((true, work, Some(result))) => {
            process.set_gc_enabled(true);
            charge(process, work / SEARCH_LOOP_FACTOR);
            match result {
                Ok(value) => crate::native_hooks::raw(value),
                Err(error) => bif_ret(c_p, i, Err(find_error(error))),
            }
        }
        Some(_) => {
            let trap = bif_trap(process, BINARY_FIND_TRAP, vec![subject, mref, pattern]);
            bif_ret(c_p, i, Err(trap))
        }
        None => bif_ret(c_p, i, Err(badarg())),
    }
}

// ---- first / last / at / referenced_byte_size / longest_common_* / copy / *_unsigned --------

/// `erts_new_binary_from_data`.
fn binary(process: &mut crate::Process, bytes: &[u8]) -> Term {
    TermBuilder::new(&mut ProcessHeapHandle(&mut process.heap))
        .binary(bytes)
        .expect("HAlloc")
}

fn small_term(value: usize) -> Term {
    Term::small(value as i64).expect("a byte or a small length is a small integer")
}

/// A `bitstring`-checked binary's bytes for the one-argument BIFs.
macro_rules! byte_bif {
    ($c_p:ident, $reg:ident, $i:ident, |$bytes:ident, $process:ident| $body:expr) => {{
        let Some($process) = crate::native_hooks::process_from_header($c_p) else {
            return 0;
        };
        $process.heap.note_bif_entry();
        let [bin] = crate::bif_table::bif_args::<1>($reg);
        match with_binary_input(bin, |$bytes| Ok($body)) {
            Ok(Some(value)) => crate::native_hooks::raw(value),
            _ => bif_ret($c_p, $i, Err(badarg())),
        }
    }};
}

/// `binary:first/1`.
// Port of erts/emulator/beam/erl_bif_binary.c (binary_first_1), OTP-29.1.1.
pub(crate) extern "C" fn binary_first_1(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    byte_bif!(c_p, reg, i, |bytes, _process| bytes
        .first()
        .map(|&byte| small_term(usize::from(byte))))
}

/// `binary:last/1`.
// Port of erts/emulator/beam/erl_bif_binary.c (binary_last_1), OTP-29.1.1.
pub(crate) extern "C" fn binary_last_1(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    byte_bif!(c_p, reg, i, |bytes, _process| bytes
        .last()
        .map(|&byte| small_term(usize::from(byte))))
}

/// `binary:at/2`.
// Port of erts/emulator/beam/erl_bif_binary.c (binary_at_2), OTP-29.1.1.
pub(crate) extern "C" fn binary_at_2(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let [bin, position] = crate::bif_table::bif_args::<2>(reg);
    let value = (|| {
        let view = BinRef::try_from(bin).ok()?;
        let index = usize::try_from(position.as_small()?).ok()?;
        if !view.bit_len().is_multiple_of(8) || index >= view.bit_len() / 8 {
            return None;
        }
        let window = view.window();
        let byte_offset = view.start_bit() / 8 + index;
        let shift = view.start_bit() % 8;
        let first = window[byte_offset];
        let byte = if shift == 0 {
            first
        } else {
            (first << shift) | (window[byte_offset + 1] >> (8 - shift))
        };
        Some(small_term(usize::from(byte)))
    })();
    match value {
        Some(value) => crate::native_hooks::raw(value),
        None => bif_ret(c_p, i, Err(badarg())),
    }
}

/// `term_to_Uint`: a non-negative small or big integer that fits a word.
fn term_to_uint(term: Term) -> Option<usize> {
    match term.as_small() {
        Some(n) => usize::try_from(n).ok(),
        None => arinsal_term::raw::big_value(term).and_then(|n| usize::try_from(n).ok()),
    }
}

/// `binary:referenced_byte_size/1`.
// Port of erts/emulator/beam/erl_bif_binary.c (binary_referenced_byte_size_1), OTP-29.1.1.
pub(crate) extern "C" fn binary_referenced_byte_size_1(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [bin] = crate::bif_table::bif_args::<1>(reg);
    let Ok(view) = BinRef::try_from(bin) else {
        return bif_ret(c_p, i, Err(badarg()));
    };
    let size = view.referenced_byte_size();
    let value =
        TermBuilder::new(&mut ProcessHeapHandle(&mut process.heap)).int_from_u64(size as u64);
    match value {
        Ok(value) => crate::native_hooks::raw(value),
        Err(_) => bif_ret(c_p, i, Err(find_error(BifError::SystemLimit))),
    }
}

/// `COMMON_LOOP_FACTOR`.
const COMMON_LOOP_FACTOR: usize = 10;
/// Bits compared per step: one cache line (`NBITS(sizeof(__scratchpad[0]))`).
const COMMON_STRIDE_BITS: usize = 64 * 8;

const BINARY_LONGEST_PREFIX_TRAP: &str = "erlang:binary_longest_prefix_trap/4";
const BINARY_LONGEST_SUFFIX_TRAP: &str = "erlang:binary_longest_suffix_trap/4";

/// `get_reds(p, COMMON_LOOP_FACTOR)`.
fn common_reds(process: &crate::Process) -> usize {
    let reds = (process.heap.abi.fcalls.max(0) as usize).saturating_mul(COMMON_LOOP_FACTOR);
    let limit = crate::natives::erts_debug::binary_loop_limit() as usize;
    if limit != 0 && limit < reds {
        return limit;
    }
    reds.max(1)
}

/// `longest_common_copy_bits`: `stride` bits of `binary` at `position` from its start (prefix)
/// or from its end (suffix), left aligned in `scratch`.
fn longest_common_bits(
    suffix: bool,
    binary: Term,
    scratch: &mut [u8; 64],
    position: usize,
    stride: usize,
) {
    let size = BinRef::try_from(binary).map_or(0, BinRef::bit_len);
    let start = if suffix {
        size - position - stride
    } else {
        position
    };
    let _ = arinsal_term::erl_bits::copy_bitstring_range(binary, start, &mut scratch[..], stride);
}

/// `continue_longest_common`: compare the binaries of the tuple `binaries` stride by stride from
/// `binary_index` at `position` (both counted from the front, or the back for a suffix).
// Port of erts/emulator/beam/erl_bif_binary.c (continue_longest_common), OTP-29.1.1.
#[allow(clippy::too_many_arguments)]
fn continue_longest_common(
    c_p: *mut ProcessHeader,
    i: u64,
    process: &mut crate::Process,
    suffix: bool,
    binaries: Term,
    mut binary_index: usize,
    mut smallest_size: usize,
    mut position: usize,
) -> u64 {
    let count = arinsal_bifs::tuple_arity(binaries).unwrap_or(0);
    let items: Vec<Term> = (0..count)
        .filter_map(|index| arinsal_bifs::tuple_element(binaries, index).ok())
        .collect();
    if items.len() != count || binary_index == 0 || binary_index >= count {
        return bif_ret(c_p, i, Err(badarg()));
    }
    let save_reds = common_reds(process) as i64;
    let mut reds = save_reds;
    loop {
        if reds < 0 {
            process.heap.abi.fcalls = 0;
            let mut handle = ProcessHeapHandle(&mut process.heap);
            let mut builder = TermBuilder::new(&mut handle);
            let index = Term::small(binary_index as i64).expect("a small index");
            let size = builder.int_from_u64(smallest_size as u64).expect("HAlloc");
            let pos = builder.int_from_u64(position as u64).expect("HAlloc");
            let export = if suffix {
                BINARY_LONGEST_SUFFIX_TRAP
            } else {
                BINARY_LONGEST_PREFIX_TRAP
            };
            let trap = bif_trap(process, export, vec![binaries, index, size, pos]);
            return bif_ret(c_p, i, Err(trap));
        }
        let mut stride = (smallest_size - position).min(COMMON_STRIDE_BITS);
        let mut reference = [0u8; 64];
        longest_common_bits(suffix, items[0], &mut reference, position, stride);
        let mut reference_at = 0usize;
        // All other binaries at this position, advancing it iff they all agree.
        while reds >= 0 && position < smallest_size {
            let mut compared = [0u8; 64];
            longest_common_bits(suffix, items[binary_index], &mut compared, position, stride);
            let mut offset = 0;
            while offset < stride {
                let index = if suffix {
                    (stride - offset - 8) / 8
                } else {
                    offset / 8
                };
                if reference[reference_at + index] != compared[index] {
                    smallest_size = position + offset;
                    stride = offset;
                    if suffix {
                        // The next binary is compared with the smaller stride, which places
                        // its tail at another offset: the reference moves with it.
                        reference_at += index + 1;
                    }
                    break;
                }
                offset += 8;
            }
            binary_index += 1;
            reds -= stride as i64;
            if binary_index == count {
                position += stride;
                binary_index = 1;
                break;
            }
        }
        if position >= smallest_size {
            break;
        }
    }
    charge(
        process,
        ((save_reds - reds) / COMMON_LOOP_FACTOR as i64).max(0) as usize,
    );
    crate::native_hooks::raw(small_term(position / 8))
}

/// `start_longest_common`.
// Port of erts/emulator/beam/erl_bif_binary.c (start_longest_common), OTP-29.1.1.
fn longest_common(c_p: *mut ProcessHeader, reg: *mut u64, i: u64, suffix: bool) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [list] = crate::bif_table::bif_args::<1>(reg);
    let mut smallest_size = usize::MAX;
    let mut binaries = Vec::new();
    let mut rest = list;
    while let Some((head, tail)) = cons_cell(rest) {
        let size = match BinRef::try_from(head) {
            Ok(view) if view.bit_len().is_multiple_of(8) => view.bit_len(),
            _ => return bif_ret(c_p, i, Err(badarg())),
        };
        smallest_size = smallest_size.min(size);
        binaries.push(head);
        rest = tail;
    }
    if rest != Term::NIL || binaries.is_empty() {
        return bif_ret(c_p, i, Err(badarg()));
    }
    // Trivial cases are weeded out as they complicate the main loop.
    if smallest_size == 0 || binaries.len() == 1 {
        return crate::native_hooks::raw(small_term(smallest_size / 8));
    }
    let tuple = TermBuilder::new(&mut ProcessHeapHandle(&mut process.heap))
        .tuple(&binaries)
        .expect("HAlloc");
    continue_longest_common(c_p, i, process, suffix, tuple, 1, smallest_size, 0)
}

fn longest_common_trap(c_p: *mut ProcessHeader, reg: *mut u64, i: u64, suffix: bool) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [binaries, index, size, position] = crate::bif_table::bif_args::<4>(reg);
    let to_uint = |term: Term| term.as_small().and_then(|n| usize::try_from(n).ok());
    let (Some(index), Some(size), Some(position)) =
        (to_uint(index), to_uint(size), to_uint(position))
    else {
        return bif_ret(c_p, i, Err(badarg()));
    };
    continue_longest_common(c_p, i, process, suffix, binaries, index, size, position)
}

/// `erlang:binary_longest_prefix_trap/4`.
pub(crate) extern "C" fn binary_longest_prefix_trap(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    longest_common_trap(c_p, reg, i, false)
}

/// `erlang:binary_longest_suffix_trap/4`.
pub(crate) extern "C" fn binary_longest_suffix_trap(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    longest_common_trap(c_p, reg, i, true)
}

/// `binary:longest_common_prefix/1`.
pub(crate) extern "C" fn binary_longest_common_prefix_1(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    longest_common(c_p, reg, i, false)
}

/// `binary:longest_common_suffix/1`.
pub(crate) extern "C" fn binary_longest_common_suffix_1(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    longest_common(c_p, reg, i, true)
}

/// The byte order of `encode_unsigned/2` and `decode_unsigned/2`: `true` for little endian.
fn little_endian(order: Option<Term>) -> Option<bool> {
    let Some(order) = order else {
        return Some(false);
    };
    match atom_name(order)?.as_str() {
        "big" => Some(false),
        "little" => Some(true),
        _ => None,
    }
}

fn encode_unsigned(c_p: *mut ProcessHeader, reg: *mut u64, i: u64, arity: usize) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let args = crate::bif_table::bif_arg_vec(reg, arity);
    let value = args[0]
        .as_small()
        .map(num_bigint::BigInt::from)
        .or_else(|| arinsal_term::raw::big_value(args[0]));
    let (Some(value), Some(little)) = (value, little_endian(args.get(1).copied())) else {
        return bif_ret(c_p, i, Err(badarg()));
    };
    if value.sign() == num_bigint::Sign::Minus {
        return bif_ret(c_p, i, Err(badarg()));
    }
    let mut bytes = value.to_bytes_be().1;
    if bytes.is_empty() {
        bytes.push(0);
    }
    if little {
        bytes.reverse();
    }
    let result = binary(process, &bytes);
    crate::native_hooks::raw(result)
}

/// `binary:encode_unsigned/1`.
pub(crate) extern "C" fn binary_encode_unsigned_1(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    encode_unsigned(c_p, reg, i, 1)
}

/// `binary:encode_unsigned/2`.
pub(crate) extern "C" fn binary_encode_unsigned_2(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    encode_unsigned(c_p, reg, i, 2)
}

fn decode_unsigned(c_p: *mut ProcessHeader, reg: *mut u64, i: u64, arity: usize) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let args = crate::bif_table::bif_arg_vec(reg, arity);
    let Some(little) = little_endian(args.get(1).copied()) else {
        return bif_ret(c_p, i, Err(badarg()));
    };
    let value = with_binary_input(args[0], |bytes| {
        Ok(if little {
            num_bigint::BigInt::from_bytes_le(num_bigint::Sign::Plus, bytes)
        } else {
            num_bigint::BigInt::from_bytes_be(num_bigint::Sign::Plus, bytes)
        })
    });
    let Ok(value) = value else {
        return bif_ret(c_p, i, Err(badarg()));
    };
    match TermBuilder::new(&mut ProcessHeapHandle(&mut process.heap)).int_from_bigint(&value) {
        Ok(term) => crate::native_hooks::raw(term),
        Err(_) => bif_ret(c_p, i, Err(find_error(BifError::SystemLimit))),
    }
}

/// `binary:decode_unsigned/1`.
pub(crate) extern "C" fn binary_decode_unsigned_1(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    decode_unsigned(c_p, reg, i, 1)
}

/// `binary:decode_unsigned/2`.
pub(crate) extern "C" fn binary_decode_unsigned_2(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    decode_unsigned(c_p, reg, i, 2)
}

/// Bits copied per reduction: a cache line (`ERTS_CACHE_LINE_SIZE * 8`).
const BITSTRING_COPY_LOOP_FACTOR: usize = 64 * 8;

const BINARY_COPY_TRAP: &str = "erlang:binary_copy_trap/3";

/// `copy_binary_to_buffer` for a byte-aligned destination: `count` source bytes starting at bit
/// `source_bit` of `window`, shifted when the source starts inside a byte.
// Port of erts/emulator/beam/erl_bits.h (copy_binary_to_buffer), OTP-29.1.1.
pub(crate) fn copy_binary_to_buffer(
    target: &mut [u8],
    window: &[u8],
    source_bit: usize,
    count: usize,
) {
    let from = source_bit / 8;
    let shift = source_bit % 8;
    if shift == 0 {
        target[..count].copy_from_slice(&window[from..from + count]);
        return;
    }
    for (index, byte) in target[..count].iter_mut().enumerate() {
        *byte = (window[from + index] << shift) | (window[from + index + 1] >> (8 - shift));
    }
}

/// `binary_copy_loop`: repeat the source into `target` from `copied_bits` up to `trap_offset`;
/// the bits copied so far. Sizes are whole bytes, so every stride is byte aligned in `target`.
// Port of erts/emulator/beam/erl_bif_binary.c (binary_copy_loop), OTP-29.1.1.
fn binary_copy_loop(
    source: BinRef,
    target: &mut [u8],
    mut copied_bits: usize,
    trap_offset: usize,
) -> usize {
    let source_size = source.bit_len();
    while copied_bits < trap_offset {
        let copy_offset = copied_bits % source_size;
        let copy_stride = (trap_offset - copied_bits).min(source_size - copy_offset);
        copy_binary_to_buffer(
            &mut target[copied_bits / 8..],
            source.window(),
            source.start_bit() + copy_offset,
            copy_stride / 8,
        );
        copied_bits += copy_stride;
    }
    copied_bits
}

/// `binary_copy_loop` into the writable result binary `result`; the bits copied so far.
fn copy_loop(
    input: Term,
    result: Term,
    copied_bits: usize,
    trap_offset: usize,
) -> Result<usize, BifError> {
    let source = BinRef::try_from(input).map_err(|_| BifError::BADARG)?;
    // `binary_copy_trap`: the contents of the unshared result are updated in place.
    let mut target =
        arinsal_term::raw::UninitBitstring::from_term(result).ok_or(BifError::BADARG)?;
    let destination = target.bytes_mut().ok_or(BifError::BADARG)?;
    Ok(binary_copy_loop(
        source,
        destination,
        copied_bits,
        trap_offset,
    ))
}

/// `get_reds` for the copy loops.
fn copy_reds(process: &crate::Process) -> usize {
    let reds = (process.heap.abi.fcalls.max(0) as usize).saturating_mul(BITSTRING_COPY_LOOP_FACTOR);
    let limit = crate::natives::erts_debug::binary_loop_limit() as usize;
    if limit != 0 && limit < reds {
        return limit;
    }
    reds.max(1)
}

/// `do_binary_copy`.
// Port of erts/emulator/beam/erl_bif_binary.c (do_binary_copy), OTP-29.1.1.
fn do_binary_copy(c_p: *mut ProcessHeader, reg: *mut u64, i: u64, arity: usize) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let (bin, count) = if arity == 1 {
        let [bin] = crate::bif_table::bif_args::<1>(reg);
        (bin, Some(1))
    } else {
        let [bin, count] = crate::bif_table::bif_args::<2>(reg);
        (bin, term_to_uint(count))
    };
    let (Ok(view), Some(count)) = (BinRef::try_from(bin), count) else {
        return bif_ret(c_p, i, Err(badarg()));
    };
    let bits = view.bit_len();
    if !bits.is_multiple_of(8) {
        return bif_ret(c_p, i, Err(badarg()));
    }
    let source_len = bits / 8;
    if count == 0 || source_len == 0 {
        let empty = binary(process, &[]);
        return crate::native_hooks::raw(empty);
    }
    if count >= usize::MAX / bits {
        return bif_ret(c_p, i, Err(find_error(BifError::SystemLimit)));
    }
    let length = source_len * count;
    let target_bits = length * 8;
    let max_copy_bits = copy_reds(process);
    if max_copy_bits >= target_bits {
        // One slice: the whole result is built in place.
        let built = TermBuilder::new(&mut ProcessHeapHandle(&mut process.heap)).binary_from_fn(
            length,
            |destination| {
                binary_copy_loop(view, destination, 0, target_bits);
            },
        );
        return match built {
            Ok(value) => {
                charge(process, target_bits / BITSTRING_COPY_LOOP_FACTOR);
                crate::native_hooks::raw(value)
            }
            Err(_) => bif_ret(c_p, i, Err(find_error(BifError::SystemLimit))),
        };
    }
    // `erts_new_bitstring`: an uninitialized off-heap binary (the target is above one slice, so
    // beyond the on-heap limit).
    let Ok(output) = arinsal_term::raw::UninitBitstring::allocate(
        &mut ProcessHeapHandle(&mut process.heap),
        length,
    ) else {
        return bif_ret(c_p, i, Err(find_error(BifError::SystemLimit)));
    };
    let result = output.term();
    let Ok(copied) = copy_loop(bin, result, 0, max_copy_bits.min(target_bits)) else {
        return bif_ret(c_p, i, Err(badarg()));
    };
    // `ERTS_BIF_YIELD3(binary_copy_trap_export, bin, result, copied_bits)`.
    crate::bif_traps::vbump_all_reds(process);
    let copied_term = TermBuilder::new(&mut ProcessHeapHandle(&mut process.heap))
        .int_from_u64(copied as u64)
        .expect("HAlloc");
    let trap = bif_trap(process, BINARY_COPY_TRAP, vec![bin, result, copied_term]);
    bif_ret(c_p, i, Err(trap))
}

/// `binary:copy/1`.
pub(crate) extern "C" fn binary_copy_1(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    do_binary_copy(c_p, reg, i, 1)
}

/// `binary:copy/2`.
pub(crate) extern "C" fn binary_copy_2(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    do_binary_copy(c_p, reg, i, 2)
}

/// `erlang:binary_copy_trap/3`.
// Port of erts/emulator/beam/erl_bif_binary.c (binary_copy_trap), OTP-29.1.1.
pub(crate) extern "C" fn binary_copy_trap(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [bin, result, copied_term] = crate::bif_table::bif_args::<3>(reg);
    let (Some(copied_bits), Ok(target)) = (
        copied_term.as_small().and_then(|n| usize::try_from(n).ok()),
        BinRef::try_from(result),
    ) else {
        return bif_ret(c_p, i, Err(badarg()));
    };
    let target_size = target.bit_len();
    let max_copy_bits = copy_reds(process);
    let initial_target_offset = copied_bits;
    let mut trap_offset = target_size;
    if (usize::MAX - max_copy_bits) < initial_target_offset
        && initial_target_offset.saturating_add(max_copy_bits) < trap_offset
    {
        trap_offset = initial_target_offset + max_copy_bits;
    }
    let Ok(copied) = copy_loop(bin, result, copied_bits, trap_offset) else {
        return bif_ret(c_p, i, Err(badarg()));
    };
    if copied == target_size {
        charge(
            process,
            (copied - initial_target_offset) / BITSTRING_COPY_LOOP_FACTOR,
        );
        return crate::native_hooks::raw(result);
    }
    crate::bif_traps::vbump_all_reds(process);
    let copied_term = TermBuilder::new(&mut ProcessHeapHandle(&mut process.heap))
        .int_from_u64(copied as u64)
        .expect("HAlloc");
    let trap = bif_trap(process, BINARY_COPY_TRAP, vec![bin, result, copied_term]);
    bif_ret(c_p, i, Err(trap))
}

/// `binary_part/2,3` and `binary:part/2,3`.
// Port of erts/emulator/beam/erl_bif_binary.c (erts_binary_part, binary_part_2, binary_part_3),
// OTP-29.1.1.
fn binary_part(c_p: *mut ProcessHeader, reg: *mut u64, i: u64, arity: usize) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let (bin, mut position, mut length) = if arity == 2 {
        let [bin, range] = crate::bif_table::bif_args::<2>(reg);
        let pair = arinsal_bifs::tuple_arity(range)
            .ok()
            .filter(|arity| *arity == 2)
            .and_then(|_| {
                let position = arinsal_bifs::tuple_element(range, 0).ok()?.as_small()?;
                let length = arinsal_bifs::tuple_element(range, 1).ok()?.as_small()?;
                Some((position, length))
            });
        match pair {
            Some((position, length)) => (bin, position, length),
            None => return bif_ret(c_p, i, Err(badarg())),
        }
    } else {
        let [bin, position, length] = crate::bif_table::bif_args::<3>(reg);
        match (position.as_small(), length.as_small()) {
            (Some(position), Some(length)) => (bin, position, length),
            _ => return bif_ret(c_p, i, Err(badarg())),
        }
    };
    if length < 0 {
        length = match length.checked_neg() {
            Some(length) if length <= position => length,
            _ => return bif_ret(c_p, i, Err(badarg())),
        };
        position -= length;
    }
    if position < 0 || length < 0 || position.checked_add(length).is_none() {
        return bif_ret(c_p, i, Err(badarg()));
    }
    let (Some(start), Some(length)) = (
        usize::try_from(position)
            .ok()
            .and_then(|n| n.checked_mul(8)),
        usize::try_from(length).ok().and_then(|n| n.checked_mul(8)),
    ) else {
        return bif_ret(c_p, i, Err(badarg()));
    };
    let result = TermBuilder::new(&mut ProcessHeapHandle(&mut process.heap))
        .sub_binary_bif(bin, start, length);
    match result {
        Ok(value) => crate::native_hooks::raw(value),
        Err(arinsal_term::TermError::BadArg) => bif_ret(c_p, i, Err(badarg())),
        Err(_) => bif_ret(c_p, i, Err(find_error(BifError::SystemLimit))),
    }
}

/// `binary_part/2` and `binary:part/2`.
pub(crate) extern "C" fn binary_part_2(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    binary_part(c_p, reg, i, 2)
}

/// `binary_part/3` and `binary:part/3`.
pub(crate) extern "C" fn binary_part_3(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    binary_part(c_p, reg, i, 3)
}
