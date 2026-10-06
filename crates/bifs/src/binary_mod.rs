//! Search kernels for `binary:match`, `matches`, and `split`.

use std::collections::{HashMap, VecDeque};

/// Resumable Boyer-Moore or Aho-Corasick search state.
pub(super) struct SearchWalk {
    bytes: Vec<u8>,
    scope: (usize, usize),
    first_only: bool,
    cursor: usize,
    engine: SearchEngine,
}

enum SearchEngine {
    BoyerMoore {
        pattern: Vec<u8>,
        shifts: Box<[usize; 256]>,
        matches: Vec<(usize, usize)>,
        done: bool,
    },
    AhoCorasick {
        nodes: Vec<Node>,
        roots: Vec<u8>,
        max_width: usize,
        state: usize,
        longest: Vec<usize>,
        best: Option<(usize, usize)>,
        done: bool,
    },
}

impl SearchWalk {
    pub(super) fn new(
        bytes: &[u8],
        patterns: &[Vec<u8>],
        scope: (usize, usize),
        first_only: bool,
    ) -> Self {
        let engine = if patterns.len() == 1 {
            let pattern = patterns[0].clone();
            let width = pattern.len();
            let mut shifts = Box::new([width; 256]);
            for (index, byte) in pattern[..width - 1].iter().enumerate() {
                shifts[*byte as usize] = width - 1 - index;
            }
            SearchEngine::BoyerMoore {
                pattern,
                shifts,
                matches: Vec::new(),
                done: width > scope.1 - scope.0,
            }
        } else {
            let mut nodes = vec![Node::default()];
            for pattern in patterns {
                let mut state = 0;
                for &byte in pattern {
                    state = if let Some(&next) = nodes[state].edges.get(&byte) {
                        next
                    } else {
                        nodes.push(Node::default());
                        let next = nodes.len() - 1;
                        nodes[state].edges.insert(byte, next);
                        next
                    };
                }
                nodes[state].outputs.push(pattern.len());
            }
            let mut queue = VecDeque::new();
            for &next in nodes[0].edges.values() {
                queue.push_back(next);
            }
            while let Some(state) = queue.pop_front() {
                let edges = nodes[state]
                    .edges
                    .iter()
                    .map(|(&byte, &next)| (byte, next))
                    .collect::<Vec<_>>();
                for (byte, next) in edges {
                    queue.push_back(next);
                    let mut failure = nodes[state].failure;
                    while failure != 0 && !nodes[failure].edges.contains_key(&byte) {
                        failure = nodes[failure].failure;
                    }
                    let fallback = nodes[failure].edges.get(&byte).copied().unwrap_or(0);
                    nodes[next].failure = fallback;
                    let inherited = nodes[fallback].outputs.clone();
                    nodes[next].outputs.extend(inherited);
                }
            }
            SearchEngine::AhoCorasick {
                roots: nodes[0].edges.keys().copied().collect(),
                max_width: patterns.iter().map(Vec::len).max().unwrap_or(0),
                nodes,
                state: 0,
                longest: vec![0; scope.1 - scope.0],
                best: None,
                done: scope.0 == scope.1,
            }
        };
        Self {
            bytes: bytes.to_vec(),
            scope,
            first_only,
            cursor: scope.0,
            engine,
        }
    }

    /// Process at most `budget` subject bytes; return whether scanning finished.
    pub(super) fn step(&mut self, budget: usize) -> (bool, usize) {
        let limit = self.scope.1;
        let mut work = 0;
        match &mut self.engine {
            SearchEngine::BoyerMoore {
                pattern,
                shifts,
                matches,
                done,
            } => {
                let width = pattern.len();
                while !*done && work < budget.max(1) {
                    if self.cursor > limit - width {
                        *done = true;
                        break;
                    }
                    let at = self.cursor;
                    let tail = self.bytes[at + width - 1];
                    work += 1;
                    if tail == pattern[width - 1] && self.bytes[at..at + width] == *pattern {
                        matches.push((at, width));
                        if self.first_only {
                            *done = true;
                        } else {
                            self.cursor += width;
                        }
                    } else {
                        self.cursor += shifts[tail as usize];
                    }
                }
                (*done, work)
            }
            SearchEngine::AhoCorasick {
                nodes,
                roots,
                max_width,
                state,
                longest,
                best,
                done,
            } => {
                while !*done && self.cursor < limit && work < budget.max(1) {
                    if *state == 0 {
                        let byte = self.bytes[self.cursor];
                        if !roots.contains(&byte) {
                            self.cursor += 1;
                            work += 1;
                            continue;
                        }
                    }
                    let byte = self.bytes[self.cursor];
                    while *state != 0 && !nodes[*state].edges.contains_key(&byte) {
                        *state = nodes[*state].failure;
                    }
                    *state = nodes[*state].edges.get(&byte).copied().unwrap_or(0);
                    for &length in &nodes[*state].outputs {
                        if length <= self.cursor - self.scope.0 + 1 {
                            let start = self.cursor + 1 - length;
                            if self.first_only {
                                if best.is_none_or(|(old, old_len)| {
                                    start < old || (start == old && length > old_len)
                                }) {
                                    *best = Some((start, length));
                                }
                            } else {
                                longest[start] = longest[start].max(length);
                            }
                        }
                    }
                    self.cursor += 1;
                    work += 1;
                    if let Some((start, _)) = best
                        && self.cursor >= self.scope.0 + start.saturating_add(*max_width)
                    {
                        *done = true;
                    }
                }
                if self.cursor >= limit {
                    *done = true;
                }
                (*done, work)
            }
        }
    }

    pub(super) fn finish(&self) -> Vec<(usize, usize)> {
        match &self.engine {
            SearchEngine::BoyerMoore { matches, .. } => matches.clone(),
            SearchEngine::AhoCorasick { best, longest, .. } => {
                if self.first_only {
                    return best
                        .map_or_else(Vec::new, |(start, len)| vec![(self.scope.0 + start, len)]);
                }
                let mut out = Vec::new();
                let mut at = 0;
                while at < longest.len() {
                    let len = longest[at];
                    if len == 0 {
                        at += 1;
                    } else {
                        out.push((self.scope.0 + at, len));
                        at += len;
                    }
                }
                out
            }
        }
    }
}

#[derive(Default)]
struct Node {
    edges: HashMap<u8, usize>,
    failure: usize,
    outputs: Vec<usize>,
}
