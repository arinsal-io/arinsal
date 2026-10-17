//! Boyer–Moore and Aho–Corasick search used by the `binary` BIFs.

use std::sync::Arc;

use crate::BifError;

const ALPHABET_SIZE: usize = 256;
const NO_NODE: usize = usize::MAX;
const MC_LOOP_FACTOR: usize = 8;

/// Compiled search data shared by `binary:compile_pattern/1` and search calls.
pub(super) enum SearchPattern {
    BoyerMoore(BoyerMoore),
    AhoCorasick(AhoCorasick),
}

impl SearchPattern {
    /// Build the search data selected by OTP from the number of patterns.
    // Port of erts/emulator/beam/erl_bif_binary.c:470-615 (create_bmdata,
    // ac_add_one_pattern, ac_compute_failure_functions), OTP-29.1.1.
    pub(super) fn compile(patterns: &[Vec<u8>]) -> Result<Self, BifError> {
        if patterns.len() == 1 {
            return Ok(Self::BoyerMoore(BoyerMoore::new(patterns[0].clone())?));
        }
        Ok(Self::AhoCorasick(AhoCorasick::new(patterns)?))
    }

    pub(super) fn tag(&self) -> &'static str {
        match self {
            Self::BoyerMoore(_) => "bm",
            Self::AhoCorasick(_) => "ac",
        }
    }
}

pub(crate) struct BoyerMoore {
    pattern: Vec<u8>,
    good_shift: Vec<usize>,
    bad_shift: Vec<usize>,
}

impl BoyerMoore {
    // Port of erts/emulator/beam/erl_bif_binary.c:385-515 (compute shifts and
    // create_bmdata), OTP-29.1.1.
    fn new(pattern: Vec<u8>) -> Result<Self, BifError> {
        let width = pattern.len();
        let mut bad_shift = Vec::new();
        bad_shift
            .try_reserve_exact(ALPHABET_SIZE)
            .map_err(|_| BifError::SystemLimit)?;
        bad_shift.resize(ALPHABET_SIZE, width);
        if width > 1 {
            for index in 0..width - 1 {
                bad_shift[pattern[index] as usize] = width - index - 1;
            }
        }

        let mut good_shift = Vec::new();
        if width > 1 {
            good_shift
                .try_reserve_exact(width)
                .map_err(|_| BifError::SystemLimit)?;
            good_shift.resize(width, width);
            let suffixes = suffixes(&pattern)?;
            let mut j = 0;
            for i in (-1_isize..=(width as isize - 1)).rev() {
                if i == -1 || suffixes[i as usize] == i + 1 {
                    while j < width as isize - 1 - i {
                        if good_shift[j as usize] == width {
                            good_shift[j as usize] = (width as isize - 1 - i) as usize;
                        }
                        j += 1;
                    }
                }
            }
            for i in 0..=(width as isize - 2) {
                good_shift[width - 1 - suffixes[i as usize] as usize] =
                    (width as isize - 1 - i) as usize;
            }
        }

        Ok(Self {
            pattern,
            good_shift,
            bad_shift,
        })
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

pub(crate) struct AhoCorasick {
    nodes: Vec<Node>,
}

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
        Ok(Self { nodes })
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
pub(super) struct SearchWalk {
    len: usize,
    scope: (usize, usize),
    pattern: Arc<SearchPattern>,
    state: SearchState,
}

impl SearchWalk {
    /// Start searching at `scope.0` and stop at `scope.1`.
    // Port of erts/emulator/beam/erl_bif_binary.c:624-635, 827-833,
    // 892-900 (search-state initialization), OTP-29.1.1.
    pub(super) fn new(
        len: usize,
        pattern: Arc<SearchPattern>,
        scope: (usize, usize),
        first_only: bool,
    ) -> Self {
        let too_short = match pattern.as_ref() {
            SearchPattern::BoyerMoore(bm) => bm.pattern.len() > scope.1 - scope.0,
            SearchPattern::AhoCorasick(_) => false,
        };
        let state = match (pattern.as_ref(), first_only) {
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
    pub(super) fn step(&mut self, bytes: &[u8], budget: usize) -> (bool, usize) {
        if budget == 0 {
            return (self.is_done(), 0);
        }
        match self.pattern.as_ref() {
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

    /// Return recorded matches in the order produced by the OTP search.
    // Port of erts/emulator/beam/erl_bif_binary.c:637-699, 729-824,
    // 834-890, 918-1000 (match result collection), OTP-29.1.1.
    pub(super) fn finish(&self) -> Vec<(usize, usize)> {
        match &self.state {
            SearchState::BoyerMooreFirst { found, .. } => found.iter().copied().collect(),
            SearchState::BoyerMooreAll { found, .. }
            | SearchState::AhoCorasickAll { found, .. } => found.clone(),
            SearchState::AhoCorasickFirst { candidate, .. } => {
                let SearchPattern::AhoCorasick(pattern) = self.pattern.as_ref() else {
                    unreachable!("Aho–Corasick state uses an Aho–Corasick pattern")
                };
                candidate
                    .map(|(node, start)| (start, pattern.nodes[node].depth as usize))
                    .into_iter()
                    .collect()
            }
        }
    }

    pub(super) fn len(&self) -> usize {
        self.len
    }

    /// Number of matches recorded so far.
    pub(super) fn match_count(&self) -> usize {
        match &self.state {
            SearchState::BoyerMooreFirst { found, .. } => usize::from(found.is_some()),
            SearchState::BoyerMooreAll { found, .. }
            | SearchState::AhoCorasickAll { found, .. } => found.len(),
            SearchState::AhoCorasickFirst { candidate, .. } => usize::from(candidate.is_some()),
        }
    }

    pub(super) fn is_done(&self) -> bool {
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
            } => Self::step_boyer_moore_loop(
                pattern,
                bytes,
                end,
                budget,
                position,
                done,
                |result, _, done| {
                    *found = Some(result);
                    *done = true;
                },
            ),
            SearchState::BoyerMooreAll {
                position,
                found,
                done,
            } => Self::step_boyer_moore_loop(
                pattern,
                bytes,
                end,
                budget,
                position,
                done,
                |result, position, _| {
                    if found.len() == found.capacity() {
                        let additional = if found.capacity() == 0 {
                            10
                        } else {
                            found.capacity()
                        };
                        found.reserve_exact(additional);
                    }
                    found.push(result);
                    *position += result.1;
                },
            ),
            _ => unreachable!("Boyer–Moore uses a Boyer–Moore state"),
        }
    }

    fn step_boyer_moore_loop(
        pattern: &BoyerMoore,
        bytes: &[u8],
        end: usize,
        budget: usize,
        position: &mut usize,
        done: &mut bool,
        mut on_match: impl FnMut((usize, usize), &mut usize, &mut bool),
    ) -> (bool, usize) {
        let width = pattern.pattern.len();
        let last = width - 1;
        let mut work = 0;
        while !*done && work < budget {
            let Some(last_byte_start) = position.checked_add(last) else {
                *done = true;
                break;
            };
            if last_byte_start >= end {
                *done = true;
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
            let haystack = &bytes[last_byte_start..last_byte_start + mem_read];
            if let Some(offset) = memchr::memchr(pattern.pattern[last], haystack) {
                work = work.saturating_add((last + offset) / MC_LOOP_FACTOR);
                *position += offset;
            } else {
                // Port of bm_find_first_match (erl_bif_binary.c:862-874): a memchr
                // miss never reaches the shift. create_bmdata leaves goodshift and
                // badshift unallocated when the pattern length is 1, so the search
                // is memchr only (erl_bif_binary.c:467-497).
                work = work.saturating_add(mem_read / MC_LOOP_FACTOR);
                *position = position.saturating_add(mem_read);
                if width > end || *position > end - width {
                    *done = true;
                }
                break;
            }
            if *position > end - width {
                *done = true;
                break;
            }
            if work >= budget {
                break;
            }
            work += 1;
            let mismatch = pattern
                .pattern
                .iter()
                .zip(bytes[*position..*position + width].iter())
                .rposition(|(needle, hay)| needle != hay);
            if let Some(index) = mismatch {
                let index = index as isize;
                let hay_byte = bytes[*position + index as usize] as usize;
                let bad = pattern.bad_shift[hay_byte] as isize - width as isize + 1 + index;
                let good = pattern.good_shift[index as usize] as isize;
                *position = position.saturating_add(good.max(bad) as usize);
            } else {
                let result = (*position, width);
                on_match(result, position, done);
            }
        }
        (*done, work)
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
            state: current,
            position,
            candidate,
            done,
        } = state
        else {
            unreachable!("Aho–Corasick first uses a first-match state")
        };
        let mut work = 0;
        while !*done && *position < scope.1 && work < budget {
            let byte = bytes[*position] as usize;
            while pattern.nodes[*current].edges[byte] == NO_NODE
                && pattern.nodes[*current].failure != *current
            {
                *current = pattern.nodes[*current].failure;
            }
            let next = pattern.nodes[*current].edges[byte];
            if next != NO_NODE {
                *current = next;
            }
            *position += 1;
            work += 1;
            if let Some((_, candidate_start)) = *candidate
                && (*position - pattern.nodes[*current].depth as usize) > candidate_start
            {
                *done = true;
                break;
            }
            if pattern.nodes[*current].final_pattern != 0 {
                let mut result_node = *current;
                while pattern.nodes[result_node].final_pattern < 0 {
                    result_node = pattern.nodes[result_node].failure;
                }
                let start = *position - pattern.nodes[result_node].depth as usize;
                let replace = candidate.is_none_or(|(old_node, old_start)| {
                    start < old_start
                        || (start == old_start
                            && pattern.nodes[old_node].depth < pattern.nodes[*current].depth)
                });
                if replace {
                    *candidate = Some((result_node, start));
                }
            }
        }
        if *position >= scope.1 {
            *done = true;
        }
        (*done, work)
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
            state: current,
            position,
            found,
            done,
        } = state
        else {
            unreachable!("Aho–Corasick all uses a match-all state")
        };
        let mut work = 0;
        while !*done && *position < end && work < budget {
            let byte = bytes[*position] as usize;
            while pattern.nodes[*current].edges[byte] == NO_NODE
                && pattern.nodes[*current].failure != *current
            {
                *current = pattern.nodes[*current].failure;
            }
            let next = pattern.nodes[*current].edges[byte];
            if next != NO_NODE {
                *current = next;
            }
            *position += 1;
            work += 1;
            if pattern.nodes[*current].final_pattern != 0 {
                let mut result_node = *current;
                while pattern.nodes[result_node].final_pattern != 0 {
                    while pattern.nodes[result_node].final_pattern < 0 {
                        result_node = pattern.nodes[result_node].failure;
                    }
                    let result_start = *position - pattern.nodes[result_node].depth as usize;
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
        if *position >= end {
            *done = true;
        }
        (*done, work)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn search(
        bytes: &[u8],
        needle: &[u8],
        scope: (usize, usize),
        first_only: bool,
    ) -> Vec<(usize, usize)> {
        let pattern = Arc::new(SearchPattern::compile(&[needle.to_vec()]).unwrap());
        let mut walk = SearchWalk::new(bytes.len(), pattern, scope, first_only);
        let mut steps = 0;
        while !walk.step(bytes, 1).0 {
            steps += 1;
            assert!(steps < bytes.len() + 2, "search made no progress");
        }
        walk.finish()
    }

    #[test]
    fn one_byte_pattern_one_reduction_window_matches_a_full_scan() {
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
