//! Build generated BeamAsm operations and apply the OTP 29 direct rewrite rules.

#![forbid(unsafe_code)]

use arinsal_beam::{BeamFile, Instr, Operand};
use arinsal_etf::OwnedTerm;
use arinsal_spec::BifKind;
use std::{collections::HashMap, sync::OnceLock};

/// A typed operand accepted by a BeamAsm-specific operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpecificOperand {
    /// X register index.
    X(u32),
    /// Y stack slot index.
    Y(u32),
    /// Float register index.
    FloatRegister(u32),
    /// Label index.
    Label(u32),
    /// Atom table index.
    Atom(u32),
    /// Export-table entry index.
    Export(u32),
    /// Literal table index.
    Literal(u32),
    /// Small signed immediate.
    SmallInt(i64),
    /// Unsigned immediate.
    Unsigned(u64),
    /// Nil operand.
    Nil,
    /// Integer outside `i64`, as decimal text; the loader turns it into a literal.
    BigInt(String),
    /// Variable-length operand sequence.
    List(Vec<SpecificOperand>),
    /// Allocation descriptor list.
    Allocations(Vec<(u8, u64)>),
    /// Operand forms without a specific BeamAsm representation yet.
    Other,
}

include!(concat!(env!("OUT_DIR"), "/specific_ops.rs"));

/// Rewrites one function's generic instruction slice into specific operations.
pub fn transform_function(instructions: &[Instr]) -> Vec<SpecificOp> {
    transform_with_context(instructions, None)
}

/// Rewrites one function with module metadata needed by OTP predicates.
pub fn transform_function_in_module(instructions: &[Instr], beam: &BeamFile) -> Vec<SpecificOp> {
    transform_with_context(instructions, Some(beam))
}

/// Splits a module at `func_info` boundaries and rewrites each function.
pub fn transform_module(beam: &BeamFile) -> Vec<Vec<SpecificOp>> {
    let transformed = transform_function_in_module(&beam.code.instructions, beam);
    let mut functions = Vec::new();
    let mut current = Vec::new();
    for op in transformed {
        if op.name() == "i_func_label" && !current.is_empty() {
            functions.push(std::mem::take(&mut current));
        }
        current.push(op);
    }
    if !current.is_empty() {
        functions.push(current);
    }
    functions
}

fn transform_with_context(instructions: &[Instr], beam: Option<&BeamFile>) -> Vec<SpecificOp> {
    let rules = rules();
    let raw = instructions
        .iter()
        .map(|instruction| Node {
            name: instruction.op.name().to_owned(),
            args: instruction.args.iter().map(allocation_as_words).collect(),
            offset: instruction.offset,
        })
        .collect::<Vec<_>>();
    let mut code = inject_function_starts(raw);
    let max_pattern = rules
        .values()
        .flatten()
        .map(|rule| rule.patterns.len())
        .max()
        .unwrap_or(1);
    // OTP rules are ordered, greedy peephole rewrites. Re-scan after a rewrite
    // because a later rule can expose an earlier multi-instruction pattern.
    // Like erts' loader (beam_load.c, transform_engine), generated instructions are put
    // back in front of the remaining stream and retried, so a rewrite costs only its
    // own instructions instead of moving the rest of the module.
    loop {
        let mut changed = false;
        let mut out = Vec::with_capacity(code.len());
        let mut front: std::collections::VecDeque<Node> = std::collections::VecDeque::new();
        let mut index = 0;
        while !front.is_empty() || index < code.len() {
            let window;
            let (stream, at): (&[Node], usize) = if front.is_empty() {
                (&code, index)
            } else {
                let end = code.len().min(index + max_pattern);
                window = front
                    .iter()
                    .chain(&code[index..end])
                    .cloned()
                    .collect::<Vec<_>>();
                (&window, 0)
            };
            let mut replacement = None;
            for rule in rules.get(&stream[at].name).into_iter().flatten() {
                if let Some((consumed, produced)) = apply_rule(rule, stream, at, beam) {
                    replacement = Some((consumed, produced));
                    break;
                }
            }
            let Some((consumed, produced)) = replacement else {
                if front.is_empty() {
                    out.push(std::mem::replace(&mut code[index], Node::empty()));
                    index += 1;
                } else {
                    out.extend(front.pop_front());
                }
                continue;
            };
            let is_unchanged = consumed == produced.len()
                && stream[at..at + consumed]
                    .iter()
                    .zip(&produced)
                    .all(|(old, new)| node_equal(old, new));
            let same_opcode =
                consumed == 1 && produced.len() == 1 && stream[at].name == produced[0].name;
            changed |= !is_unchanged;
            let from_front = consumed.min(front.len());
            front.drain(..from_front);
            index += consumed - from_front;
            let mut produced = produced.into_iter();
            if (same_opcode || is_unchanged)
                && let Some(first) = produced.next()
            {
                out.push(first);
            }
            for node in produced.rev() {
                front.push_front(node);
            }
        }
        code = out;
        if !changed {
            break;
        }
    }
    code.iter()
        .map(|instruction| {
            if instruction.name == "has_map_fields" {
                map_fields_to_elements(instruction)
            } else {
                make_op(
                    &instruction.name,
                    instruction.args.iter().map(operand).collect(),
                )
            }
        })
        .collect()
}

// Port of erts/emulator/beam/generators.tab:230-254, OTP-29.1.1.
fn map_fields_to_elements(instruction: &Node) -> SpecificOp {
    let [fail, source, size, rest @ ..] = instruction.args.as_slice() else {
        return make_op(
            &instruction.name,
            instruction.args.iter().map(operand).collect(),
        );
    };
    let keys = match rest {
        [Operand::List(keys)] => keys.as_slice(),
        keys => keys,
    };
    let Some(count) = operand_integer(size).and_then(|count| usize::try_from(count).ok()) else {
        return make_op(
            &instruction.name,
            instruction.args.iter().map(operand).collect(),
        );
    };
    if keys.len() != count {
        return make_op(
            &instruction.name,
            instruction.args.iter().map(operand).collect(),
        );
    }
    let mut args = Vec::with_capacity(3 + count * 2);
    args.push(operand(fail));
    args.push(operand(source));
    args.push(SpecificOperand::Unsigned((count * 2) as u64));
    for key in keys {
        args.push(operand(key));
        args.push(SpecificOperand::X(1023));
    }
    make_op("get_map_elements", args)
}

#[derive(Clone, Debug)]
struct Node {
    name: String,
    args: Vec<Operand>,
    offset: usize,
}

impl Node {
    // A moved-out stream slot.
    fn empty() -> Self {
        Self {
            name: String::new(),
            args: Vec::new(),
            offset: 0,
        }
    }
}

fn node_equal(a: &Node, b: &Node) -> bool {
    a.name == b.name
        && a.offset == b.offset
        && a.args.len() == b.args.len()
        && a.args.iter().zip(&b.args).all(|(x, y)| operand_equal(x, y))
}

#[derive(Clone, Debug)]
struct Rule {
    patterns: Vec<Pattern>,
    predicates: Vec<Predicate>,
    outputs: Vec<Output>,
}

#[derive(Clone, Debug)]
struct Pattern {
    op: String,
    args: Vec<PatArg>,
}
#[derive(Clone, Debug)]
struct PatArg {
    name: Option<String>,
    ty: Option<String>,
    restriction: Option<Restriction>,
    eq: Option<i64>,
    eq_atom: Option<String>,
    rest: bool,
}
#[derive(Clone, Debug)]
enum Restriction {
    IsBif,
    IsNotBif,
    Mfa {
        module: String,
        function: String,
        arity: u32,
    },
    Bif {
        module: String,
        function: String,
        arity: u32,
    },
}
#[derive(Clone, Debug)]
enum Predicate {
    Equal(String, String),
    Distinct(String, String),
    Consecutive(String, String, bool),
    Never,
    Call(String, Vec<String>),
}
#[derive(Clone, Debug)]
struct Output {
    op: String,
    args: Vec<String>,
    function: bool,
}

fn rules() -> &'static HashMap<String, Vec<Rule>> {
    static RULES: OnceLock<HashMap<String, Vec<Rule>>> = OnceLock::new();
    RULES.get_or_init(|| {
        let parsed_rules = parse_rules();
        let mut buckets: HashMap<String, Vec<Rule>> = HashMap::new();
        for rule in parsed_rules {
            buckets
                .entry(rule.patterns[0].op.clone())
                .or_default()
                .push(rule);
        }
        buckets
    })
}

fn inject_function_starts(raw: Vec<Node>) -> Vec<Node> {
    let mut code = Vec::with_capacity(raw.len() + raw.len() / 20);
    let mut index = 0;
    while index < raw.len() {
        if index + 2 < raw.len()
            && raw[index].name == "label"
            && raw[index + 1].name == "line"
            && raw[index + 2].name == "func_info"
            && raw[index].args.len() == 1
            && raw[index + 1].args.len() == 1
            && raw[index + 2].args.len() == 3
        {
            let mut args = raw[index].args.clone();
            args.extend(raw[index + 1].args.clone());
            args.extend(raw[index + 2].args.clone());
            code.push(Node {
                name: "int_func_start".into(),
                args,
                offset: raw[index].offset,
            });
            index += 3;
        } else {
            code.push(raw[index].clone());
            index += 1;
        }
    }
    let mut with_ends = Vec::with_capacity(code.len() + code.len() / 20);
    let mut current_function = None;
    let mut entry_label = None;
    for node in code {
        if node.name == "int_func_start" {
            if let (Some(function), Some(entry)) = (current_function.take(), entry_label.take()) {
                with_ends.push(Node {
                    name: "int_func_end".into(),
                    args: vec![function, entry],
                    offset: node.offset,
                });
            }
            current_function = node.args.first().cloned();
        } else if current_function.is_some() && entry_label.is_none() && node.name == "label" {
            entry_label = node.args.first().cloned();
        }
        with_ends.push(node);
    }
    if let (Some(function), Some(entry)) = (current_function, entry_label) {
        with_ends.push(Node {
            name: "int_func_end".into(),
            args: vec![function, entry],
            offset: with_ends.last().map_or(0, |node| node.offset),
        });
    }
    with_ends
}

fn parse_rules() -> Vec<Rule> {
    let source = include_str!("../tab/ops.tab");
    let mut result = Vec::new();
    let mut pending = String::new();
    let mut has_arrow = false;
    for raw in source.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('%') {
            continue;
        }
        if pending.is_empty() && !line.contains("=>") && !line.ends_with('|') {
            continue;
        }
        if !pending.is_empty() {
            pending.push(' ');
        }
        pending.push_str(line);
        if !has_arrow && pending.contains("=>") {
            has_arrow = true;
        }
        if has_arrow {
            let rhs = pending.split_once("=>").map_or("", |(_, rhs)| rhs.trim());
            if !rhs.is_empty() && !rhs.ends_with('|') {
                if let Some((lhs, rhs)) = pending.split_once("=>")
                    && let Some(rule) = parse_rule(lhs.trim(), rhs.trim())
                {
                    result.push(rule);
                }
                pending.clear();
                has_arrow = false;
            }
        } else if !line.ends_with('|') {
            // A non-rule declaration ends any incomplete/commented candidate.
            if !pending.contains('|') {
                pending.clear();
            }
        }
    }
    result
}

fn parse_rule(lhs: &str, rhs: &str) -> Option<Rule> {
    let mut patterns = Vec::new();
    let mut predicates = Vec::new();
    for segment in split_pipes(lhs) {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }
        if segment.ends_with(')') && segment.contains('(') {
            let (name, args) = segment.split_once('(')?;
            let args = args
                .trim_end_matches(')')
                .split(',')
                .map(str::trim)
                .collect::<Vec<_>>();
            let predicate = match (name.trim(), args.as_slice()) {
                ("equal", [a, b]) => Predicate::Equal((*a).into(), (*b).into()),
                ("distinct", [a, b]) => Predicate::Distinct((*a).into(), (*b).into()),
                ("consecutive_words", [a, b]) => {
                    Predicate::Consecutive((*a).into(), (*b).into(), false)
                }
                ("consecutive_xregs", [a, b]) => {
                    Predicate::Consecutive((*a).into(), (*b).into(), true)
                }
                ("never", _) => Predicate::Never,
                (name, args) => Predicate::Call(
                    name.trim().to_owned(),
                    args.iter().map(|arg| (*arg).to_owned()).collect(),
                ),
            };
            predicates.push(predicate);
            continue;
        }
        let mut words = segment.split_whitespace();
        let op = words.next()?.to_owned();
        if !op.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return None;
        }
        let args = words.map(parse_pat_arg).collect::<Option<Vec<_>>>()?;
        patterns.push(Pattern { op, args });
    }
    let mut outputs = Vec::new();
    for segment in split_pipes(rhs) {
        let segment = segment.trim();
        if segment.is_empty() || segment == "_" {
            continue;
        }
        let (op, args, function) = if let Some((name, rest)) = segment.split_once('(') {
            let close = rest.strip_suffix(')')?;
            (
                name.to_owned(),
                close.split(',').map(|arg| arg.trim().to_owned()).collect(),
                true,
            )
        } else {
            let words = segment.split_whitespace().collect::<Vec<_>>();
            (
                words[0].to_owned(),
                words[1..].iter().map(|s| (*s).to_owned()).collect(),
                false,
            )
        };
        outputs.push(Output { op, args, function });
    }
    if patterns.is_empty() {
        return None;
    }
    Some(Rule {
        patterns,
        predicates,
        outputs,
    })
}

fn split_pipes(s: &str) -> Vec<&str> {
    s.split('|').collect()
}
fn parse_pat_arg(token: &str) -> Option<PatArg> {
    if token == "*" {
        return Some(PatArg {
            name: Some("*".into()),
            ty: None,
            restriction: None,
            eq: None,
            eq_atom: None,
            rest: true,
        });
    }
    let mut remainder = token;
    let var_len = remainder
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .count();
    let candidate = &remainder[..var_len];
    let is_variable = candidate
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_uppercase() || c == '_');
    let name = if is_variable {
        remainder = &remainder[var_len..];
        (!candidate.starts_with('_')).then(|| candidate.to_owned())
    } else {
        None
    };
    if remainder.starts_with('=') && !remainder.starts_with("==") {
        remainder = &remainder[1..];
    }
    let type_len = remainder
        .chars()
        .take_while(|c| c.is_ascii_lowercase() || *c == '*')
        .count();
    let types = &remainder[..type_len];
    remainder = &remainder[type_len..];
    let ty = (!types.is_empty()).then(|| types.to_owned());
    if ty
        .as_deref()
        .is_some_and(|types| types != "*" && !is_type_set(types))
    {
        return None;
    }
    if types == "*" {
        if !remainder.is_empty() {
            return None;
        }
        return Some(PatArg {
            name: name.or_else(|| Some("*".into())),
            ty: None,
            restriction: None,
            eq: None,
            eq_atom: None,
            rest: true,
        });
    }
    let mut restriction = None;
    if let Some(value) = remainder.strip_prefix("$is_bif") {
        if !value.is_empty() {
            return None;
        }
        restriction = Some(Restriction::IsBif);
        remainder = "";
    } else if let Some(value) = remainder.strip_prefix("$is_not_bif") {
        if !value.is_empty() {
            return None;
        }
        restriction = Some(Restriction::IsNotBif);
        remainder = "";
    } else if remainder.starts_with("$func:") {
        restriction = Some(parse_mfa_restriction(remainder, false)?);
        remainder = "";
    } else if remainder.starts_with("$bif:") {
        restriction = Some(parse_mfa_restriction(remainder, true)?);
        remainder = "";
    }
    let mut eq = None;
    let mut eq_atom = None;
    if let Some(value) = remainder.strip_prefix("==") {
        if let Ok(integer) = value.parse() {
            eq = Some(integer);
        } else {
            eq_atom = Some(value.to_owned());
        }
        remainder = "";
    }
    if !remainder.is_empty() || (name.is_none() && ty.is_none() && !candidate.starts_with('_')) {
        return None;
    }
    Some(PatArg {
        name,
        ty,
        restriction,
        eq,
        eq_atom,
        rest: false,
    })
}

fn parse_mfa_restriction(value: &str, bif: bool) -> Option<Restriction> {
    let value = value.split_once(':')?.1;
    let (module, rest) = value.split_once(':')?;
    let (function, arity) = rest.rsplit_once('/')?;
    let arity = arity.parse().ok()?;
    Some(if bif {
        Restriction::Bif {
            module: module.to_owned(),
            function: function.trim_matches('\'').to_owned(),
            arity,
        }
    } else {
        Restriction::Mfa {
            module: module.to_owned(),
            function: function.trim_matches('\'').to_owned(),
            arity,
        }
    })
}

fn import_mfa<'a>(value: &Operand, beam: &'a BeamFile) -> Option<(&'a str, &'a str, u32)> {
    let Operand::U(index) = value else {
        return None;
    };
    let import = beam.imports.get(usize::try_from(*index).ok()?)?;
    let module = beam
        .atoms
        .get(import.module_atom.checked_sub(1)? as usize)?;
    let function = beam
        .atoms
        .get(import.function_atom.checked_sub(1)? as usize)?;
    Some((module, function, import.arity))
}

fn mfa_is_bif(module: &str, function: &str, arity: u32) -> bool {
    arinsal_spec::BIFS
        .iter()
        .any(|bif| bif.module == module && bif.name == function && u32::from(bif.arity) == arity)
}

fn restriction_matches(
    restriction: &Restriction,
    value: &Operand,
    beam: Option<&BeamFile>,
) -> bool {
    let Some(beam) = beam else { return false };
    let Some((module, function, arity)) = import_mfa(value, beam) else {
        return false;
    };
    match restriction {
        Restriction::IsBif => mfa_is_bif(module, function, arity),
        // Port of erts/emulator/utils/beam_makeops:2835-2873 (is_not_bif), OTP-29.1.1:
        // erlang:apply/2,3 are special and never count as plain functions.
        Restriction::IsNotBif => {
            !mfa_is_bif(module, function, arity)
                && !(module == "erlang" && function == "apply" && matches!(arity, 2 | 3))
        }
        Restriction::Mfa {
            module: expected_module,
            function: expected_function,
            arity: expected_arity,
        } => module == expected_module && function == expected_function && arity == *expected_arity,
        Restriction::Bif {
            module: expected_module,
            function: expected_function,
            arity: expected_arity,
        } => {
            if module != expected_module || arity != *expected_arity {
                return false;
            }
            let Some(bif) = arinsal_spec::bif_lookup(module, function, arity as u8) else {
                return false;
            };
            // beam_makeops resolves `$bif:` operands through the C function name from bif.tab
            // (`'div'` is `intdiv_2`, `'/'` is `div_2`); a BIF without one uses its own name.
            match bif.c_name {
                Some(c_name) => c_name
                    .strip_suffix(&format!("_{arity}"))
                    .is_some_and(|name| name == expected_function),
                None => function == expected_function,
            }
        }
    }
}

#[allow(clippy::chunks_exact_to_as_chunks)]
fn apply_rule(
    rule: &Rule,
    code: &[Node],
    at: usize,
    beam: Option<&BeamFile>,
) -> Option<(usize, Vec<Node>)> {
    if at + rule.patterns.len() > code.len() {
        return None;
    }
    let mut bindings: Vec<(String, Operand)> = Vec::new();
    for (pattern, instruction) in rule.patterns.iter().zip(&code[at..]) {
        if pattern.op != instruction.name {
            return None;
        }
        // Most patterns match the operands as they are; only a rest list without its
        // length operand needs a rewritten copy.
        let mut expanded_args = std::borrow::Cow::Borrowed(instruction.args.as_slice());
        let expected = pattern.args.len();
        if expected == expanded_args.len() + 1
            && pattern.args.last().is_some_and(|arg| arg.rest)
            && let Some(Operand::List(rest)) = expanded_args.last()
        {
            let length = Operand::U(rest.len() as u64);
            let rest_index = expanded_args.len() - 1;
            expanded_args.to_mut().insert(rest_index, length);
        }
        let rest = pattern.args.last().is_some_and(|arg| arg.rest);
        let fixed = pattern.args.len() - usize::from(rest);
        if expanded_args.len() < fixed || (!rest && expanded_args.len() != fixed) {
            return None;
        }
        for (pat, value) in pattern.args.iter().take(fixed).zip(expanded_args.iter()) {
            let exact_x0 = pat.ty.as_deref() == Some("x")
                && pat.eq == Some(0)
                && register_index(value) == Some(('x', 0));
            if !(type_matches(pat.ty.as_deref(), value) || exact_x0)
                || pat.eq.is_some_and(|n| operand_integer(value) != Some(n))
                || pat
                    .eq_atom
                    .as_ref()
                    .is_some_and(|atom| !operand_is_atom(value, atom, beam))
                || pat
                    .restriction
                    .as_ref()
                    .is_some_and(|restriction| !restriction_matches(restriction, value, beam))
            {
                return None;
            }
            if let Some(name) = &pat.name {
                if let Some((_, previous)) = bindings.iter().find(|(key, _)| key == name) {
                    if !operand_equal(previous, value) {
                        return None;
                    }
                } else {
                    bindings.push((name.clone(), value.clone()));
                }
            }
        }
        if rest {
            let values = if expanded_args.len() == fixed + 1 {
                match &expanded_args[fixed] {
                    Operand::List(values) => values.clone(),
                    value => vec![value.clone()],
                }
            } else {
                expanded_args[fixed..].to_vec()
            };
            let name = pattern
                .args
                .last()
                .and_then(|arg| arg.name.clone())
                .unwrap_or_else(|| "*".into());
            bindings.push((name, Operand::List(values)));
        }
    }
    for pred in &rule.predicates {
        if !eval_predicate(pred, &bindings, beam) {
            return None;
        }
    }
    let mut produced = Vec::new();
    for output in &rule.outputs {
        let mut args = Vec::new();
        for token in &output.args {
            if let Some((_, value)) = bindings.iter().find(|(name, _)| name == token) {
                if !output.function {
                    if let Operand::List(rest) = value {
                        args.extend(rest.clone());
                    } else {
                        args.push(value.clone());
                    }
                } else {
                    args.push(value.clone());
                }
            } else if token == "*" {
                if let Some((_, Operand::List(rest))) =
                    bindings.iter().find(|(name, _)| name == "*")
                {
                    if output.function {
                        args.push(Operand::List(rest.clone()));
                    } else {
                        args.extend(rest.clone());
                    }
                }
            } else {
                args.push(output_constant(token)?);
            }
        }
        // Ports of OTP-29.1.1 loader generators: beam/generators.tab:87,128,176,202
        // and beam/jit/arm/generators.tab:375. These generate operations using
        // lambda metadata, map-key hashes, and normalized variable operands.
        match output.op.as_str() {
            "get_utf16" => {
                if args.len() != 4 {
                    return None;
                }
                produced.push(Node {
                    name: "i_bs_get_utf16".into(),
                    args: vec![
                        args[1].clone(),
                        args[0].clone(),
                        args[2].clone(),
                        args[3].clone(),
                    ],
                    offset: code[at].offset,
                });
            }
            "skip_utf16" => {
                if args.len() != 3 {
                    return None;
                }
                produced.push(Node {
                    name: "i_bs_skip_utf16".into(),
                    args: vec![args[1].clone(), args[0].clone(), args[2].clone()],
                    offset: code[at].offset,
                });
            }
            "init_yregs_move" => {
                if args.len() != 2 {
                    return None;
                }
                let Operand::List(rest) = &args[1] else {
                    return None;
                };
                let value = rest.first()?;
                produced.push(Node {
                    name: "move".into(),
                    args: vec![Operand::Nil, value.clone()],
                    offset: code[at].offset,
                });
            }
            "select_val" => {
                if args.len() != 4 {
                    return None;
                }
                let pairs = usize::try_from(operand_integer(&args[2])?).ok()? / 2;
                let Operand::List(rest) = &args[3] else {
                    return None;
                };
                let mut specific_args = vec![args[0].clone(), args[1].clone(), args[2].clone()];
                specific_args.extend(rest.clone());
                produced.push(Node {
                    name: if pairs <= 10 {
                        "i_select_val_lins".into()
                    } else {
                        "i_select_val_bins".into()
                    },
                    args: specific_args,
                    offset: code[at].offset,
                });
            }
            "select_tuple_arity" => {
                if args.len() != 4 {
                    return None;
                }
                let Operand::List(rest) = &args[3] else {
                    return None;
                };
                let mut specific_args = vec![args[0].clone(), args[1].clone(), args[2].clone()];
                specific_args.extend(rest.clone());
                produced.push(Node {
                    name: "i_select_tuple_arity".into(),
                    args: specific_args,
                    offset: code[at].offset,
                });
            }
            "jump_tab" => {
                if args.len() != 4 {
                    return None;
                }
                let Operand::List(rest) = &args[3] else {
                    return None;
                };
                let min = rest.iter().step_by(2).filter_map(operand_integer).min()?;
                let max = rest.iter().step_by(2).filter_map(operand_integer).max()?;
                let table_size = usize::try_from(max.checked_sub(min)?.checked_add(1)?).ok()?;
                let mut specific_args = vec![
                    args[0].clone(),
                    args[1].clone(),
                    Operand::U(min as u64),
                    Operand::U(table_size as u64),
                ];
                specific_args.extend(std::iter::repeat_n(args[1].clone(), table_size));
                for pair in rest.chunks_exact(2) {
                    let slot =
                        usize::try_from(operand_integer(&pair[0])?.checked_sub(min)?).ok()?;
                    if slot >= table_size {
                        return None;
                    }
                    specific_args[4 + slot] = pair[1].clone();
                }
                produced.push(Node {
                    name: "i_jump_on_val".into(),
                    args: specific_args,
                    offset: code[at].offset,
                });
            }
            "select_literals" => {
                if args.len() != 4 {
                    return None;
                }
                let Operand::List(rest) = &args[3] else {
                    return None;
                };
                for pair in rest.chunks_exact(2) {
                    produced.push(Node {
                        name: "is_ne_exact".into(),
                        args: vec![pair[1].clone(), args[0].clone(), pair[0].clone()],
                        offset: code[at].offset,
                    });
                }
                produced.push(Node {
                    name: "jump".into(),
                    args: vec![args[1].clone()],
                    offset: code[at].offset,
                });
            }
            "bs_match" => {
                if args.len() != 4 {
                    return None;
                }
                let Operand::List(rest) = &args[3] else {
                    return None;
                };
                let mut specific_args = vec![args[0].clone(), args[1].clone()];
                specific_args.extend(rest.clone());
                produced.push(Node {
                    name: "i_bs_match".into(),
                    args: specific_args,
                    offset: code[at].offset,
                });
            }
            "new_small_map_lit" => {
                if args.len() != 4 {
                    return None;
                }
                let Operand::List(rest) = &args[3] else {
                    return None;
                };
                let mut specific_args = vec![args[0].clone(), args[1].clone(), args[2].clone()];
                specific_args.extend(rest.clone());
                produced.push(Node {
                    name: "i_new_small_map_lit".into(),
                    args: specific_args,
                    offset: code[at].offset,
                });
            }
            "create_bin" => {
                // Port of erts/emulator/beam/jit/arm/generators.tab:441-530 (gen.create_bin),
                // OTP-29.1.1.
                if args.len() != 7 {
                    return None;
                }
                let Operand::List(segments) = &args[6] else {
                    return None;
                };
                if !segments.len().is_multiple_of(6) {
                    return None;
                }
                let atom_index = |name: &str| {
                    beam.and_then(|beam| beam.atoms.iter().position(|atom| atom == name))
                        .and_then(|position| u32::try_from(position + 1).ok())
                };
                let mut alloc = args[1].clone();
                let mut specific_args = vec![
                    args[0].clone(),
                    args[1].clone(),
                    args[2].clone(),
                    args[4].clone(),
                ];
                for segment in segments.chunks_exact(6) {
                    let mut segment = segment.to_vec();
                    // Translate the flags list to the BSF_* bit mask (ARM is little endian).
                    let mut flags = 0u64;
                    if let Operand::Literal(index) = &segment[3]
                        && let Some(beam) = beam
                        && let Ok(term) = beam.literal(*index)
                    {
                        let mut current = &term;
                        while let OwnedTerm::List { elems, tail } = current {
                            for elem in elems {
                                if let OwnedTerm::Atom(name) = elem
                                    && matches!(name.as_str(), "little" | "native")
                                {
                                    flags |= 2;
                                }
                            }
                            current = tail;
                        }
                    }
                    segment[3] = Operand::U(flags);
                    // Short string segments become integer segments.
                    if operand_is_atom(&segment[0], "string", beam)
                        && let Some(count) = operand_integer(&segment[5])
                        && (0..=4).contains(&count)
                        && let Some(index) = operand_integer(&segment[4])
                        && let Some(beam) = beam
                        && let Some(integer) = atom_index("integer")
                        && let Some(bytes) = usize::try_from(index)
                            .ok()
                            .and_then(|start| beam.strings.get(start..start + count as usize))
                    {
                        let value = bytes
                            .iter()
                            .fold(0i64, |acc, byte| acc << 8 | i64::from(*byte));
                        segment[0] = Operand::Atom(integer);
                        segment[2] = Operand::U(8);
                        segment[4] = Operand::Int(value);
                    }
                    specific_args.extend(segment);
                }
                if operand_is_atom(&segments[0], "private_append", beam)
                    && operand_integer(&alloc).is_some_and(|words| words != 0)
                {
                    produced.push(Node {
                        name: "test_heap".into(),
                        args: vec![alloc.clone(), args[2].clone()],
                        offset: code[at].offset,
                    });
                    alloc = Operand::U(0);
                    specific_args[1] = alloc;
                }
                produced.push(Node {
                    name: "i_bs_create_bin".into(),
                    args: specific_args,
                    offset: code[at].offset,
                });
            }
            "get_map_element" => {
                if args.len() != 4 {
                    return None;
                }
                let Operand::List(rest) = &args[3] else {
                    return None;
                };
                if rest.len() != 2 {
                    return None;
                }
                let key = rest[0].clone();
                let dst = rest[1].clone();
                if matches!(
                    key,
                    Operand::Atom(_)
                        | Operand::Int(_)
                        | Operand::U(_)
                        | Operand::Nil
                        | Operand::Literal(_)
                ) {
                    produced.push(Node {
                        name: "i_get_map_element_hash".into(),
                        args: vec![args[0].clone(), args[1].clone(), key, Operand::U(0), dst],
                        offset: code[at].offset,
                    });
                } else {
                    produced.push(Node {
                        name: "i_get_map_element".into(),
                        args: vec![args[0].clone(), args[1].clone(), key, dst],
                        offset: code[at].offset,
                    });
                }
            }
            "get_map_elements" => {
                if args.len() != 4 {
                    return None;
                }
                let Operand::List(rest) = &args[3] else {
                    return None;
                };
                let mut specific_args = vec![
                    args[0].clone(),
                    args[1].clone(),
                    // Port of erts/emulator/beam/generators.tab:202-227 (gen.get_map_elements).
                    Operand::U(3 * (rest.len() as u64 / 2)),
                ];
                for pair in rest.chunks_exact(2) {
                    specific_args.push(pair[0].clone());
                    specific_args.push(pair[1].clone());
                    specific_args.push(Operand::U(0));
                }
                produced.push(Node {
                    name: "i_get_map_elements".into(),
                    args: specific_args,
                    offset: code[at].offset,
                });
            }
            "make_fun3" => {
                if args.len() != 4 {
                    return None;
                }
                let beam = beam?;
                let (Operand::U(index), Operand::U(num_free)) = (&args[0], &args[2]) else {
                    return None;
                };
                let Some(lambda) = beam
                    .lambdas
                    .iter()
                    .find(|lambda| u64::from(lambda.index) == *index)
                else {
                    produced.push(Node {
                        name: "i_lambda_error".into(),
                        args: vec![Operand::U(0)],
                        offset: code[at].offset,
                    });
                    continue;
                };
                if u64::from(lambda.num_free) != *num_free {
                    produced.push(Node {
                        name: "i_lambda_error".into(),
                        args: vec![Operand::U(0)],
                        offset: code[at].offset,
                    });
                    continue;
                }
                if lambda.num_free == 0 {
                    produced.push(Node {
                        name: "i_move".into(),
                        // Keep zero-capture fun references distinct from BEAM literal 0.
                        // The high index range is reserved for this internal bridge.
                        args: vec![Operand::Literal(u32::MAX - lambda.index), args[1].clone()],
                        offset: code[at].offset,
                    });
                    continue;
                }
                let Operand::List(env) = &args[3] else {
                    return None;
                };
                let mut specific_args = args[..3].to_vec();
                specific_args[2] = Operand::U(u64::from(lambda.arity - lambda.num_free));
                specific_args.push(Operand::U(env.len() as u64));
                specific_args.extend(env.clone());
                produced.push(Node {
                    name: "i_make_fun3".into(),
                    args: specific_args,
                    offset: code[at].offset,
                });
            }
            "func_end" => {
                if args.len() != 2 {
                    return None;
                }
                let beam = beam?;
                let entry_label = operand_label(&args[1])?;
                if let Some(lambda) = beam
                    .lambdas
                    .iter()
                    .find(|lambda| lambda.label == entry_label && lambda.num_free > 0)
                {
                    produced.push(Node {
                        name: "i_lambda_trampoline".into(),
                        args: vec![
                            Operand::U(u64::from(lambda.index)),
                            Operand::U(u64::from(entry_label)),
                            Operand::U(u64::from(lambda.arity)),
                            Operand::U(u64::from(lambda.num_free)),
                        ],
                        offset: code[at].offset,
                    });
                }
            }
            _ => produced.push(Node {
                name: output.op.clone(),
                args,
                offset: code[at].offset,
            }),
        }
    }
    Some((rule.patterns.len(), produced))
}

fn output_constant(token: &str) -> Option<Operand> {
    match token {
        "n" => return Some(Operand::Nil),
        "u" | "t" | "I" | "W" | "A" | "P" | "Q" | "b" | "F" | "e" | "L" | "M" | "H" => {
            return Some(Operand::U(0));
        }
        "i" => return Some(Operand::Int(0)),
        "f" | "j" | "p" => return Some(Operand::Label(0)),
        "x" => return Some(Operand::X(1023)),
        "y" => return Some(Operand::Y(0)),
        "l" => return Some(Operand::FR(0)),
        "q" => return Some(Operand::Literal(0)),
        _ => {}
    }
    let (ty, value) = token.split_once('=')?;
    match ty {
        "u" | "t" | "I" | "W" | "A" | "P" | "Q" => Some(Operand::U(value.parse().ok()?)),
        "i" => Some(Operand::Int(value.parse().ok()?)),
        "n" if value == "0" => Some(Operand::Nil),
        _ => None,
    }
}

fn eval_predicate(
    pred: &Predicate,
    bindings: &[(String, Operand)],
    beam: Option<&BeamFile>,
) -> bool {
    let get = |name: &str| {
        bindings
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value)
    };
    match pred {
        Predicate::Equal(a, b) => get(a).zip(get(b)).is_some_and(|(x, y)| operand_equal(x, y)),
        Predicate::Distinct(a, b) => get(a)
            .zip(get(b))
            .is_some_and(|(x, y)| !operand_equal(x, y)),
        Predicate::Consecutive(a, b, xregs) => get(a).zip(get(b)).is_some_and(|(x, y)| {
            if *xregs && (!matches!(x, Operand::X(_)) || !matches!(y, Operand::X(_))) {
                return false;
            }
            // Port of predicates.tab:86-90; OTP reserves X0..X5 in its ARM64 register cache.
            if *xregs && operand_integer(x).is_none_or(|index| index < 6) {
                return false;
            }
            if std::mem::discriminant(x) != std::mem::discriminant(y) {
                return false;
            }
            operand_integer(y) == operand_integer(x).and_then(|v| v.checked_add(1))
        }),
        Predicate::Never => false,
        Predicate::Call(name, args) => eval_c_predicate(name, args, bindings, beam),
    }
}

#[allow(clippy::chunks_exact_to_as_chunks)]
fn eval_c_predicate(
    name: &str,
    args: &[String],
    bindings: &[(String, Operand)],
    beam: Option<&BeamFile>,
) -> bool {
    // Ports of erts/emulator/beam/predicates.tab:24-166, OTP-29.1.1. These inspect
    // the module's import and atom tables, so rules without module context fail closed.
    let Some(beam) = beam else { return false };
    let get = |arg: &str| {
        bindings
            .iter()
            .find(|(key, _)| key == arg)
            .map(|(_, value)| value)
    };
    let integer = |arg: &str| {
        arg.parse::<i64>()
            .ok()
            .or_else(|| get(arg).and_then(operand_integer))
    };
    let imported = |arg: &str| -> Option<(&str, &str, u32)> {
        let index = match get(arg)? {
            Operand::U(index) => usize::try_from(*index).ok()?,
            _ => return None,
        };
        let import = beam.imports.get(index)?;
        let module = beam
            .atoms
            .get(import.module_atom.checked_sub(1)? as usize)?;
        let function = beam
            .atoms
            .get(import.function_atom.checked_sub(1)? as usize)?;
        Some((module, function, import.arity))
    };
    match name {
        "instrumenting_line_breakpoints" => false,
        "use_jump_tab" if args.len() == 3 => {
            let size = integer(&args[0]).unwrap_or_default();
            let min_size = integer(&args[2]).unwrap_or_default();
            let Some(Operand::List(rest)) = get(&args[1]) else {
                return false;
            };
            if size < 2 * min_size
                || size % 2 != 0
                || usize::try_from(size).ok() != Some(rest.len())
            {
                return false;
            }
            let mut keys = Vec::new();
            for pair in rest.chunks_exact(2) {
                let (Operand::Int(key), Operand::Label(_)) = (&pair[0], &pair[1]) else {
                    return false;
                };
                keys.push(*key);
            }
            keys.iter()
                .max()
                .zip(keys.iter().min())
                .is_some_and(|(max, min)| max.saturating_sub(*min) <= size)
        }
        "floats_or_bignums" if args.len() == 2 => {
            let size = get(&args[0]).and_then(operand_integer).unwrap_or_default();
            let Some(Operand::List(rest)) = get(&args[1]) else {
                return false;
            };
            size >= 2
                && size % 2 == 0
                && usize::try_from(size).ok() == Some(rest.len())
                && rest.chunks_exact(2).all(|pair| {
                    matches!(pair[0], Operand::Literal(_)) && matches!(pair[1], Operand::Label(_))
                })
        }
        "fixed_size_values" if args.len() == 2 => {
            let size = get(&args[0]).and_then(operand_integer).unwrap_or_default();
            let Some(Operand::List(rest)) = get(&args[1]) else {
                return false;
            };
            size >= 2
                && size % 2 == 0
                && usize::try_from(size).ok() == Some(rest.len())
                && rest.chunks_exact(2).all(|pair| {
                    matches!(pair[1], Operand::Label(_))
                        && match pair[0] {
                            Operand::Atom(_) | Operand::Int(_) | Operand::U(_) | Operand::Nil => {
                                true
                            }
                            Operand::Literal(index) => beam
                                .literal(index)
                                .is_ok_and(|term| !matches!(term, OwnedTerm::Float(_))),
                            _ => false,
                        }
                })
        }
        "mixed_types" if args.len() == 2 => {
            let size = get(&args[0]).and_then(operand_integer).unwrap_or_default();
            let Some(Operand::List(rest)) = get(&args[1]) else {
                return false;
            };
            size >= 2
                && size % 2 == 0
                && usize::try_from(size).ok() == Some(rest.len())
                && rest
                    .chunks_exact(2)
                    .map(|pair| operand_tag(&pair[0]))
                    .any(|tag| {
                        rest.chunks_exact(2)
                            .map(|pair| operand_tag(&pair[0]))
                            .any(|other| other != tag)
                    })
        }
        "is_heavy_bif" if args.len() == 1 => {
            imported(&args[0]).is_some_and(|(module, function, arity)| {
                arinsal_spec::bif_lookup(module, function, arity as u8)
                    .is_some_and(|bif| bif.kind == BifKind::Hbif)
            })
        }
        "is_small_map_literal_keys" if args.len() == 2 => {
            let size = get(&args[0]).and_then(operand_integer).unwrap_or_default();
            let Some(Operand::List(rest)) = get(&args[1]) else {
                return false;
            };
            if size < 0 || size % 2 != 0 || usize::try_from(size).ok() != Some(rest.len()) {
                return false;
            }
            let pair_count = size / 2;
            pair_count <= 32
                && (pair_count != 1
                    || matches!(
                        rest.first(),
                        Some(
                            Operand::Atom(_)
                                | Operand::Int(_)
                                | Operand::U(_)
                                | Operand::Nil
                                | Operand::Literal(_)
                        )
                    ))
        }
        "is_empty_map" if args.len() == 1 => {
            let Some(Operand::Literal(index)) = get(&args[0]) else {
                return false;
            };
            matches!(beam.literal(*index), Ok(OwnedTerm::Map(ref entries)) if entries.is_empty())
        }
        "smp_mark_target_label" | "map_key_sort" => true,
        "smp_already_locked" => false,
        "is_mfa_bif" if args.len() == 3 => {
            let atom = |arg: &str| -> Option<&str> {
                let index = match get(arg)? {
                    Operand::Atom(index) => *index,
                    _ => return None,
                };
                beam.atoms
                    .get(index.checked_sub(1)? as usize)
                    .map(String::as_str)
            };
            let arity = get(&args[2])
                .and_then(operand_integer)
                .and_then(|n| u8::try_from(n).ok());
            atom(&args[0]).zip(atom(&args[1])).zip(arity).is_some_and(
                |((module, function), arity)| {
                    arinsal_spec::BIFS.iter().any(|bif| {
                        bif.module == module && bif.name == function && bif.arity == arity
                    })
                },
            )
        }
        "never_fails" | "is_eq_exact_bif" | "is_ne_exact_bif" | "is_ge_bif" | "is_lt_bif"
        | "is_exit_bif"
            if !args.is_empty() =>
        {
            let Some((module, function, arity)) = imported(&args[0]) else {
                return false;
            };
            if module != "erlang" {
                return false;
            }
            match name {
                "is_eq_exact_bif" => function == "=:=" && arity == 2,
                "is_ne_exact_bif" => function == "=/=" && arity == 2,
                "is_ge_bif" => function == ">=" && arity == 2,
                "is_lt_bif" => function == "<" && arity == 2,
                "is_exit_bif" => matches!(
                    (function, arity),
                    ("error", 1..=3) | ("exit", 1) | ("throw", 1) | ("nif_error", 1..=2)
                ),
                "never_fails" => {
                    if function == "is_function" {
                        arity == 1
                    } else {
                        matches!(
                            function,
                            "/=" | "=/="
                                | "=="
                                | "=:="
                                | "<"
                                | "/"
                                | "=<"
                                | ">"
                                | ">="
                                | "is_atom"
                                | "is_boolean"
                                | "is_binary"
                                | "is_bitstring"
                                | "is_float"
                                | "is_integer"
                                | "is_list"
                                | "is_map"
                                | "is_number"
                                | "is_pid"
                                | "is_port"
                                | "is_reference"
                                | "is_tuple"
                        )
                    }
                }
                _ => false,
            }
        }
        _ => false,
    }
}

fn is_type_set(value: &str) -> bool {
    !value.is_empty()
        && value.chars().all(|ch| {
            matches!(
                ch,
                'r' | 'x'
                    | 'y'
                    | 'a'
                    | 'n'
                    | 'c'
                    | 's'
                    | 'S'
                    | 'd'
                    | 'f'
                    | 'j'
                    | 'e'
                    | 'L'
                    | 't'
                    | 'I'
                    | 'W'
                    | 'b'
                    | 'F'
                    | 'A'
                    | 'P'
                    | 'Q'
                    | 'h'
                    | 'l'
                    | 'q'
                    | 'M'
                    | 'H'
                    | 'u'
                    | 'i'
                    | 'o'
                    | 'p'
            )
        })
}

fn operand_tag(value: &Operand) -> u8 {
    match value {
        Operand::X(_) => 1,
        Operand::Y(_) => 2,
        Operand::FR(_) => 3,
        Operand::Label(_) => 4,
        Operand::Atom(_) => 5,
        Operand::Literal(_) => 6,
        Operand::Int(_) => 7,
        Operand::U(_) => 8,
        Operand::Nil => 9,
        Operand::Char(_) => 10,
        Operand::List(_) => 11,
        Operand::Alloc(_) => 12,
        _ => 13,
    }
}

fn type_matches(ty: Option<&str>, value: &Operand) -> bool {
    ty.is_none_or(|types| {
        (types.contains('x')
            && types.contains('y')
            && matches!(register_index(value), Some(('x' | 'y', _))))
            || types.chars().any(|ty| type_matches_one(ty, value))
    })
}

fn type_matches_one(ty: char, value: &Operand) -> bool {
    match ty {
        'x' => register_index(value).is_some_and(|(kind, _)| kind == 'x'),
        'r' => register_index(value).is_some_and(|(kind, index)| kind == 'x' && index == 0),
        'y' => register_index(value).is_some_and(|(kind, _)| kind == 'y'),
        'f' => matches!(value, Operand::Label(label) if *label != 0),
        'j' | 'L' | 'H' => matches!(value, Operand::Label(_) | Operand::U(_)),
        'a' => matches!(value, Operand::Atom(_)),
        'n' => matches!(value, Operand::Nil),
        'i' => matches!(value, Operand::Int(_) | Operand::U(_) | Operand::Char(_)),
        'u' | 't' | 'I' | 'W' | 'A' | 'P' | 'Q' | 'b' | 'F' | 'e' | 'M' => {
            matches!(value, Operand::U(_) | Operand::Int(_))
        }
        'd' | 'S' => register_index(value).is_some(),
        's' => {
            matches!(
                value,
                Operand::X(_)
                    | Operand::Y(_)
                    | Operand::Int(_)
                    | Operand::U(_)
                    | Operand::BigInt(_)
                    | Operand::Char(_)
                    | Operand::Atom(_)
                    | Operand::Literal(_)
                    | Operand::Nil
            ) || matches!(value, Operand::TypedReg { .. })
        }
        'c' => matches!(
            value,
            Operand::Int(_)
                | Operand::U(_)
                | Operand::BigInt(_)
                | Operand::Char(_)
                | Operand::Atom(_)
                | Operand::Literal(_)
                | Operand::Nil
        ),
        'q' => matches!(value, Operand::Literal(_)),
        'p' => matches!(value, Operand::Label(0)),
        'l' => matches!(value, Operand::FR(_)),
        'h' => matches!(value, Operand::Char(_)),
        'o' => matches!(value, Operand::List(_)),
        _ => true,
    }
}
fn register_index(value: &Operand) -> Option<(char, u32)> {
    match value {
        Operand::X(index) => Some(('x', *index)),
        Operand::Y(index) => Some(('y', *index)),
        Operand::TypedReg { reg, .. } => register_index(reg),
        _ => None,
    }
}
fn operand_integer(value: &Operand) -> Option<i64> {
    match value {
        Operand::TypedReg { reg, .. } => operand_integer(reg),
        Operand::Int(v) => Some(*v),
        Operand::U(v) => i64::try_from(*v).ok(),
        Operand::X(v)
        | Operand::Y(v)
        | Operand::Label(v)
        | Operand::Atom(v)
        | Operand::Literal(v)
        | Operand::FR(v) => Some(i64::from(*v)),
        Operand::Char(v) => Some(i64::from(*v)),
        _ => None,
    }
}
fn operand_label(value: &Operand) -> Option<u32> {
    match value {
        Operand::Label(value) => Some(*value),
        Operand::U(value) => u32::try_from(*value).ok(),
        _ => None,
    }
}
fn operand_is_atom(value: &Operand, expected: &str, beam: Option<&BeamFile>) -> bool {
    let (Some(beam), Operand::Atom(index)) = (beam, value) else {
        return false;
    };
    let expected = expected.strip_prefix("am_").unwrap_or(expected);
    beam.atoms
        .get(index.saturating_sub(1) as usize)
        .is_some_and(|atom| atom == expected)
}
fn operand_equal(a: &Operand, b: &Operand) -> bool {
    match (a, b) {
        (Operand::TypedReg { reg, .. }, value) | (value, Operand::TypedReg { reg, .. }) => {
            operand_equal(reg, value)
        }
        (Operand::Nil, Operand::Nil) => true,
        (Operand::X(a), Operand::X(b)) | (Operand::Y(a), Operand::Y(b)) => a == b,
        (Operand::U(a), Operand::U(b)) => a == b,
        (Operand::Int(a), Operand::Int(b)) => a == b,
        (Operand::BigInt(a), Operand::BigInt(b)) => a == b,
        (Operand::Atom(a), Operand::Atom(b))
        | (Operand::FR(a), Operand::FR(b))
        | (Operand::Label(a), Operand::Label(b))
        | (Operand::Char(a), Operand::Char(b))
        | (Operand::Literal(a), Operand::Literal(b)) => a == b,
        (Operand::List(a), Operand::List(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(x, y)| operand_equal(x, y))
        }
        (Operand::Alloc(a), Operand::Alloc(b)) => a
            .iter()
            .map(|allocation| (allocation.kind, allocation.count))
            .eq(b
                .iter()
                .map(|allocation| (allocation.kind, allocation.count))),
        _ => false,
    }
}

/// Sums an allocation list into heap words, as the loader does when it reads the operand.
// Port of erts/emulator/beam/beam_file.c:2234-2280 (marshal_allocation_list), OTP-29.1.1:
// floats take FLOAT_SIZE_OBJECT (2) words each and funs ERL_FUN_SIZE (2) words each.
fn allocation_as_words(value: &Operand) -> Operand {
    let Operand::Alloc(items) = value else {
        return value.clone();
    };
    let words = items.iter().fold(0_u64, |total, item| {
        total.saturating_add(match item.kind {
            arinsal_beam::AllocKind::Words => item.count,
            arinsal_beam::AllocKind::Floats | arinsal_beam::AllocKind::Funs => {
                item.count.saturating_mul(2)
            }
        })
    });
    Operand::U(words)
}

fn operand(value: &Operand) -> SpecificOperand {
    match value {
        Operand::X(value) => SpecificOperand::X(*value),
        Operand::Y(value) => SpecificOperand::Y(*value),
        Operand::FR(value) => SpecificOperand::FloatRegister(*value),
        Operand::Label(value) => SpecificOperand::Label(*value),
        Operand::Atom(value) => SpecificOperand::Atom(*value),
        Operand::Literal(value) => SpecificOperand::Literal(*value),
        Operand::Int(value) => SpecificOperand::SmallInt(*value),
        Operand::U(value) => i64::try_from(*value)
            .map_or(SpecificOperand::Unsigned(*value), SpecificOperand::SmallInt),
        Operand::Nil => SpecificOperand::Nil,
        Operand::Char(value) => SpecificOperand::SmallInt(i64::from(*value)),
        Operand::BigInt(value) => SpecificOperand::BigInt(value.to_string()),
        Operand::TypedReg { reg, .. } => operand(reg),
        Operand::List(values) => SpecificOperand::List(values.iter().map(operand).collect()),
        Operand::Alloc(values) => SpecificOperand::Allocations(
            values
                .iter()
                .map(|allocation| {
                    let kind = match allocation.kind {
                        arinsal_beam::AllocKind::Words => 0,
                        arinsal_beam::AllocKind::Floats => 1,
                        arinsal_beam::AllocKind::Funs => 2,
                    };
                    (kind, allocation.count)
                })
                .collect(),
        ),
    }
}

fn make_op(name: &str, args: Vec<SpecificOperand>) -> SpecificOp {
    SpecificOp::from_name(name, args)
}

#[cfg(test)]
mod tests {
    use super::*;
    use arinsal_spec::Opcode;

    #[test]
    fn move_rewrites_to_i_move_without_losing_register_kinds() {
        let input = [Instr {
            op: Opcode::Move,
            args: vec![Operand::Y(3), Operand::X(1)],
            offset: 0,
        }];
        assert!(matches!(
            transform_function(&input).as_slice(),
            [SpecificOp::OpIMove(args)]
                if args == &[SpecificOperand::Y(3), SpecificOperand::X(1)]
        ));
    }

    #[test]
    fn has_map_fields_rewrites_to_get_map_elements_with_ignored_destinations() {
        let input = [Instr {
            op: Opcode::HasMapFields,
            args: vec![
                Operand::Label(9),
                Operand::X(0),
                Operand::U(2),
                Operand::List(vec![Operand::Atom(4), Operand::Literal(7)]),
            ],
            offset: 0,
        }];
        let output = transform_function(&input);
        assert_eq!(output.len(), 1);
        assert_eq!(output[0].name(), "get_map_elements");
        assert_eq!(
            output[0].operands(),
            &[
                SpecificOperand::Label(9),
                SpecificOperand::X(0),
                SpecificOperand::Unsigned(4),
                SpecificOperand::Atom(4),
                SpecificOperand::X(1023),
                SpecificOperand::Literal(7),
                SpecificOperand::X(1023),
            ]
        );
    }

    #[test]
    fn adjacent_move_trim_uses_a_multi_instruction_rule() {
        let input = [
            Instr {
                op: Opcode::Move,
                args: vec![Operand::X(2), Operand::Y(1)],
                offset: 0,
            },
            Instr {
                op: Opcode::Trim,
                args: vec![Operand::U(3), Operand::U(1)],
                offset: 2,
            },
        ];
        let result = transform_function(&input);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name(), "move_trim");
        assert!(
            matches!(&result[0], SpecificOp::OpMoveTrim(args) if args == &[
                SpecificOperand::X(2), SpecificOperand::Y(1), SpecificOperand::SmallInt(3),
            ])
        );
    }

    #[test]
    fn copied_otp_tables_contain_otp29_specific_operations() {
        assert!(
            DIRECT_RULES
                .iter()
                .any(|rule| rule.input == "move" && rule.output == "i_move")
        );
        assert!(
            SpecificOp::from_name("i_bs_get_utf8", Vec::new())
                != SpecificOp::Unknown {
                    name: "i_bs_get_utf8".to_owned(),
                    operands: Vec::new()
                }
        );
    }
}
