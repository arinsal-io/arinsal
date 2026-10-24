//! The syntax of `ops.tab` rules, shared by the build script and the runtime.
#![allow(dead_code)]

/// A rule of `ops.tab` after parsing: its patterns, predicates, outputs, variable slots and match
/// program. Shared by the build script, which turns the program into straight-line code
/// (`beam_makeops`), and by the runtime, which keeps the outputs.
#[derive(Clone, Debug)]
pub struct RuleSyntax {
    pub patterns: Vec<Pattern>,
    pub predicates: Vec<Predicate>,
    pub outputs: Vec<OutputSyntax>,
    /// The variables of the left-hand side in order of first binding: the variable slots of
    /// the rule's program (erts `v0..vN` of the generated engine).
    pub slot_names: Vec<String>,
    /// The left-hand side as a flat program, as `beam_makeops` compiles it (`gen_transform`).
    pub program: Vec<Top>,
}

/// An instruction the right-hand side of a rule generates.
#[derive(Clone, Debug)]
pub struct OutputSyntax {
    pub op: &'static str,
    pub args: Vec<String>,
    pub function: bool,
}

/// One step of a rule's match program: the `TOP_*` instructions of `beam_makeops`.
#[derive(Clone, Debug)]
pub enum Top {
    /// `next_instr`: the next instruction must have this generic opcode and the arity the
    /// pattern states (`fixed` operands, plus a rest list when `rest`); argument pointer back
    /// to the first operand.
    NextInstr {
        op: &'static str,
        fixed: usize,
        rest: bool,
    },
    /// `is_type`: the operand's type bits meet the mask; `exact_x0` accepts x(0) for a pattern
    /// `x=0`.
    IsType { mask: Option<u64>, exact_x0: bool },
    /// `is_eq`: the operand equals this integer.
    IsEq(i64),
    /// The operand is this atom.
    IsAtom(String),
    /// `is_bif`, `is_not_bif`, `is_func`: a restriction on an import operand.
    Restriction(Restriction),
    /// `set_var`: bind the operand to a slot, or compare it with the value already there.
    SetVar(usize),
    /// `next_arg`.
    NextArg,
    /// `rest_args`: bind the remaining operands as a list to a slot.
    RestArgs { slot: Option<usize>, fixed: usize },
}

#[derive(Clone, Debug)]
pub struct Pattern {
    pub op: &'static str,
    pub args: Vec<PatArg>,
}
#[derive(Clone, Debug)]
pub struct PatArg {
    pub name: Option<String>,
    pub ty: Option<String>,
    /// `ty` as a bit set over the type letters, tested against `type_bits` of the operand
    /// (erts `TOP_is_type`: `((1 << tag) & mask)`); `None` when the argument has no type.
    pub ty_mask: Option<u64>,
    /// The slot of the variable this argument binds or compares with.
    pub slot: Option<usize>,
    pub restriction: Option<Restriction>,
    pub eq: Option<i64>,
    pub eq_atom: Option<String>,
    pub rest: bool,
}
#[derive(Clone, Debug)]
pub enum Restriction {
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
pub enum Predicate {
    Equal(String, String),
    Distinct(String, String),
    Consecutive(String, String, bool),
    Never,
    Call(String, Vec<String>),
}

pub fn parse_rules(source: &'static str) -> Vec<RuleSyntax> {
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
                // Rule text is process-lifetime, like erts' generated op tables.
                let owned = std::mem::take(&mut pending);
                let static_rule: &'static str = Box::leak(owned.into_boxed_str());
                if let Some((lhs, rhs)) = static_rule.split_once("=>")
                    && let Some(rule) = parse_rule(lhs.trim(), rhs.trim())
                {
                    result.push(rule);
                }
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

pub fn parse_rule(lhs: &'static str, rhs: &'static str) -> Option<RuleSyntax> {
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
        let op = words.next()?;
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
                name,
                close.split(',').map(|arg| arg.trim().to_owned()).collect(),
                true,
            )
        } else {
            let words = segment.split_whitespace().collect::<Vec<_>>();
            (
                words[0],
                words[1..].iter().map(|s| (*s).to_owned()).collect(),
                false,
            )
        };
        outputs.push(OutputSyntax { op, args, function });
    }
    if patterns.is_empty() {
        return None;
    }
    // Compile the variables to slots (the numbering of `set_var`/`store_var` in the engine).
    let mut slot_names: Vec<String> = Vec::new();
    for pattern in &mut patterns {
        for arg in &mut pattern.args {
            if let Some(name) = &arg.name {
                arg.slot = Some(match slot_names.iter().position(|known| known == name) {
                    Some(slot) => slot,
                    None => {
                        slot_names.push(name.clone());
                        slot_names.len() - 1
                    }
                });
            }
        }
    }
    let mut program = Vec::new();
    for pattern in &patterns {
        let rest = pattern.args.last().is_some_and(|arg| arg.rest);
        let fixed = pattern.args.len() - usize::from(rest);
        program.push(Top::NextInstr {
            op: pattern.op,
            fixed,
            rest,
        });
        for arg in pattern.args.iter().take(fixed) {
            program.push(Top::IsType {
                mask: arg.ty_mask,
                exact_x0: arg.ty.as_deref() == Some("x") && arg.eq == Some(0),
            });
            if let Some(n) = arg.eq {
                program.push(Top::IsEq(n));
            }
            if let Some(atom) = &arg.eq_atom {
                program.push(Top::IsAtom(atom.clone()));
            }
            if let Some(restriction) = &arg.restriction {
                program.push(Top::Restriction(restriction.clone()));
            }
            if let Some(slot) = arg.slot {
                program.push(Top::SetVar(slot));
            }
            program.push(Top::NextArg);
        }
        if rest {
            program.push(Top::RestArgs {
                slot: pattern.args.last().and_then(|arg| arg.slot),
                fixed,
            });
        }
    }
    Some(RuleSyntax {
        patterns,
        predicates,
        outputs,
        slot_names,
        program,
    })
}

pub fn split_pipes(s: &str) -> Vec<&str> {
    s.split('|').collect()
}
pub fn parse_pat_arg(token: &str) -> Option<PatArg> {
    if token == "*" {
        return Some(PatArg {
            name: Some("*".to_owned()),
            ty: None,
            ty_mask: None,
            slot: None,
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
            name: name.or_else(|| Some("*".to_owned())),
            ty: None,
            ty_mask: None,
            slot: None,
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
        ty_mask: ty.as_deref().map(type_mask),
        slot: None,
        ty,
        restriction,
        eq,
        eq_atom,
        rest: false,
    })
}

pub fn parse_mfa_restriction(value: &str, bif: bool) -> Option<Restriction> {
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

pub fn is_type_set(value: &str) -> bool {
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

/// Bit of a type letter in a type set: `a`..`z` then `A`..`Z`.
pub const fn type_bit(letter: u8) -> u64 {
    match letter {
        b'a'..=b'z' => 1 << (letter - b'a'),
        b'A'..=b'Z' => 1 << (26 + letter - b'A'),
        _ => 0,
    }
}

pub const fn letters(set: &str) -> u64 {
    let bytes = set.as_bytes();
    let mut mask = 0;
    let mut index = 0;
    while index < bytes.len() {
        mask |= type_bit(bytes[index]);
        index += 1;
    }
    mask
}

/// The set of a pattern's type letters.
pub fn type_mask(types: &str) -> u64 {
    types
        .bytes()
        .fold(0, |mask, letter| mask | type_bit(letter))
}
