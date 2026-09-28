//! Search kernels for `binary:match`, `matches`, and `split`.

use std::collections::{HashMap, VecDeque};

pub(super) fn matches_in(
    bytes: &[u8],
    patterns: &[Vec<u8>],
    scope: (usize, usize),
    first_only: bool,
) -> Vec<(usize, usize)> {
    if patterns.len() == 1 {
        return boyer_moore(bytes, &patterns[0], scope, first_only);
    }
    aho_corasick(bytes, patterns, scope, first_only)
}

fn boyer_moore(
    bytes: &[u8],
    pattern: &[u8],
    scope: (usize, usize),
    first_only: bool,
) -> Vec<(usize, usize)> {
    // `erts/emulator/beam/erl_bif_binary.c:47` selects Boyer-Moore for one
    // pattern, OTP-29.1.1. This is the bad-character variant.
    let width = pattern.len();
    if width > scope.1 - scope.0 {
        return Vec::new();
    }
    let sample = &bytes[scope.0..scope.1.min(scope.0 + 4096)];
    if sample
        .iter()
        .filter(|&&byte| byte == pattern[width - 1])
        .count()
        * 16
        < sample.len()
    {
        let mut out = Vec::new();
        let mut at = scope.0;
        while at <= scope.1 - width {
            let Some(offset) = memchr::memchr(pattern[width - 1], &bytes[at + width - 1..scope.1])
            else {
                break;
            };
            at += offset;
            if bytes[at..at + width] == *pattern {
                out.push((at, width));
                if first_only {
                    break;
                }
                at += width;
            } else {
                at += 1;
            }
        }
        return out;
    }
    let mut shifts = [width; 256];
    for (index, byte) in pattern[..width - 1].iter().enumerate() {
        shifts[*byte as usize] = width - 1 - index;
    }
    let mut at = scope.0;
    let mut out = Vec::new();
    while at <= scope.1 - width {
        let tail = bytes[at + width - 1];
        if tail == pattern[width - 1] && bytes[at..at + width] == *pattern {
            out.push((at, width));
            if first_only {
                break;
            }
            at += width;
        } else {
            at += shifts[tail as usize];
        }
    }
    out
}

#[derive(Default)]
struct Node {
    edges: HashMap<u8, usize>,
    failure: usize,
    outputs: Vec<usize>,
}

fn aho_corasick(
    bytes: &[u8],
    patterns: &[Vec<u8>],
    scope: (usize, usize),
    first_only: bool,
) -> Vec<(usize, usize)> {
    // `erts/emulator/beam/erl_bif_binary.c:47` selects Aho-Corasick for
    // pattern lists, OTP-29.1.1.
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
    let mut longest = if first_only {
        Vec::new()
    } else {
        vec![0_usize; scope.1 - scope.0]
    };
    let max_width = patterns.iter().map(Vec::len).max().unwrap_or(0);
    let roots = nodes[0].edges.keys().copied().collect::<Vec<_>>();
    let mut best: Option<(usize, usize)> = None;
    let mut state = 0;
    let mut index = 0;
    while index < scope.1 - scope.0 {
        if state == 0 {
            let remaining = &bytes[scope.0 + index..scope.1];
            let next = match roots.as_slice() {
                [one] => memchr::memchr(*one, remaining),
                [one, two] => memchr::memchr2(*one, *two, remaining),
                [one, two, three] => memchr::memchr3(*one, *two, *three, remaining),
                _ => Some(0),
            };
            let Some(skipped) = next else {
                break;
            };
            index += skipped;
        }
        let byte = bytes[scope.0 + index];
        while state != 0 && !nodes[state].edges.contains_key(&byte) {
            state = nodes[state].failure;
        }
        state = nodes[state].edges.get(&byte).copied().unwrap_or(0);
        for &length in &nodes[state].outputs {
            if length <= index + 1 {
                let start = index + 1 - length;
                if first_only {
                    if best.is_none_or(|(old_start, old_len)| {
                        start < old_start || (start == old_start && length > old_len)
                    }) {
                        best = Some((start, length));
                    }
                } else {
                    longest[start] = longest[start].max(length);
                }
            }
        }
        index += 1;
        if let Some((start, _)) = best
            && index >= start.saturating_add(max_width)
        {
            break;
        }
    }
    if first_only {
        return best.map_or_else(Vec::new, |(start, length)| vec![(scope.0 + start, length)]);
    }
    let mut out = Vec::new();
    let mut at = 0;
    while at < longest.len() {
        let length = longest[at];
        if length == 0 {
            at += 1;
        } else {
            out.push((scope.0 + at, length));
            if first_only {
                break;
            }
            at += length;
        }
    }
    out
}
