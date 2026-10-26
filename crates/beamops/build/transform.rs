//! Port of the transformation half of erts/emulator/utils/beam_makeops (OTP-29.1.1): the compiled
//! programs of the transformation rules, as `tr_gen` leaves them before it prints the engine.
//!
//! Perl subs ported here: `tr_gen` (the part before the printing), `tr_gen_from`, `tr_gen_to`,
//! `chain_instructions`, `group_tr`, `tr_maybe_keep`, `tr_maybe_rename`, `combine_commit`,
//! `tr_remove_unused`, `make_op`, `op_slot_usage`, `is_instr`, `get_comment`.

use crate::makeops::*;
use std::collections::{BTreeMap, HashMap, HashSet};

/// `make_op`: one step of a rule's program, `[size, [op, args...], comment, [slots]]`.
#[derive(Clone, Debug)]
pub struct Step {
    pub op: String,
    pub args: Vec<String>,
    pub comment: String,
    /// `op_slot_usage`: the variable slots the step reads.
    pub slots: Vec<usize>,
}

fn make_op(comment: &str, op: &str, args: &[&str]) -> Step {
    Step {
        op: op.to_owned(),
        args: args.iter().map(|a| (*a).to_owned()).collect(),
        comment: comment.to_owned(),
        slots: Vec::new(),
    }
}

fn is_instr(step: Option<&Step>, op: &str) -> bool {
    step.is_some_and(|s| s.op == op)
}

/// An element of `$gen_transform{$first}`: `[$first, $second, $cannot_fail, $comment, @code]`.
#[derive(Clone, Debug)]
pub struct Rule {
    pub first: String,
    /// `None` is Perl's undefined; the rules `group_tr` inserts have `Some("")`.
    pub second: Option<String>,
    pub cannot_fail: bool,
    pub comment: String,
    pub steps: Vec<Step>,
}

/// What `tr_gen` knows after it compiled and grouped every transformation.
pub struct Programs {
    /// `%gen_transform` after `group_tr`, keyed `name/arity` (sorted like Perl's `sort keys`).
    pub rules: BTreeMap<String, Vec<Rule>>,
    /// `$te_max_vars`.
    pub te_max_vars: usize,
    /// The predicates (`pred.*`) and generators (`gen.*`) the programs call, with their
    /// parameter types (`%c_param_types`).
    pub c_param_types: BTreeMap<String, Vec<&'static str>>,
}

/// What `$var{$var}` holds in `tr_gen_from`.
#[derive(Clone, Copy)]
enum VarRef {
    Slot(usize),
    Unnumbered,
}

struct From {
    var: HashMap<String, VarRef>,
    unused: HashSet<String>,
    var_type: HashMap<String, &'static str>,
    instrs: Vec<String>,
    code: Vec<Step>,
}

impl Makeops {
    /// `tr_gen`: compile every transformation, chain them by first instruction and group them.
    pub fn tr_gen(&self) -> Programs {
        let mut programs = Programs {
            rules: BTreeMap::new(),
            te_max_vars: 0,
            c_param_types: BTreeMap::new(),
        };
        for transformation in &self.transformations {
            let from = self.tr_gen_from(&transformation.loc, &transformation.from, &mut programs);
            self.tr_gen_to(transformation, from, &mut programs);
        }
        // Group instructions.
        let keys: Vec<String> = programs.rules.keys().cloned().collect();
        for key in keys {
            let list = programs.rules.remove(&key).unwrap();
            let grouped = self.group_tr(list);
            programs.rules.insert(key, grouped);
        }
        programs
    }

    fn tr_gen_from(&self, line: &str, items: &[TrItem], programs: &mut Programs) -> From {
        let where_ = format!("{line}: (left of =>): ");
        let mut var: HashMap<String, VarRef> = HashMap::new();
        let mut unused: HashSet<String> = HashSet::new();
        let mut var_type: HashMap<String, &'static str> = HashMap::new();
        let mut var_num = 0usize;
        let mut code: Vec<Step> = Vec::new();
        let mut may_fail = false;
        let mut is_first = true;
        let mut instrs: Vec<String> = Vec::new();

        for item in items {
            if !is_first {
                may_fail = true;
            }
            is_first = false;

            // A name starting with a period is a C pred function to be called.
            if let Some(name) = item.name.strip_prefix('.') {
                may_fail = true;
                let mut args: Vec<String> = Vec::new();
                let mut vars: Vec<&str> = Vec::new();
                let mut param_types: Vec<&'static str> = Vec::new();
                for v in &item.call_args {
                    if is_number(v) {
                        args.push(v.clone());
                        param_types.push("Uint");
                        continue;
                    }
                    let Some(slot) = var.get(v) else {
                        panic!("{where_}'{v}' unbound");
                    };
                    unused.remove(v);
                    vars.push(v);
                    match (var_type.get(v).copied(), slot) {
                        (Some("scalar"), VarRef::Slot(n)) => {
                            args.push(format!("v{n}"));
                            param_types.push("BeamOpArg");
                        }
                        _ => {
                            args.push("rest_args".to_owned());
                            param_types.push("BeamOpArg*");
                        }
                    }
                }
                programs
                    .c_param_types
                    .insert(format!("pred.{name}"), param_types);
                let mut op = make_op(
                    &format!("{name}()"),
                    "pred",
                    &std::iter::once(name)
                        .chain(args.iter().map(String::as_str))
                        .collect::<Vec<_>>(),
                );
                op.slots = vars
                    .iter()
                    .filter_map(|v| match var.get(*v) {
                        Some(VarRef::Slot(n)) => Some(*n),
                        _ => None,
                    })
                    .collect();
                code.push(op);
                continue;
            }

            // Check that $name/$arity refers to a valid generic instruction.
            let key = format!("{}/{}", item.name, item.arity);
            let Some(opnum) = self.gen_opnum.get(&(item.name.clone(), item.arity)) else {
                panic!("{where_}invalid generic op {key}");
            };
            code.push(make_op(&key, "next_instr", &[&opnum.to_string()]));
            instrs.push(key);
            let mut arg = 0;
            for op in &item.ops {
                if !op.ty.is_empty() && op.ty != "*" {
                    may_fail = true;
                    // The is_bif, is_not_bif, and is_func instructions have their own built-in
                    // type test and don't need to be guarded with a type test instruction.
                    if !matches!(op.cond.as_str(), "is_bif" | "is_not_bif" | "is_func") {
                        let mut types = String::new();
                        let mut type_mask = 0u64;
                        for letter in op.ty.chars() {
                            types.push(letter);
                            types.push(' ');
                            type_mask |= type_bit(letter).expect("a pattern type");
                        }
                        code.push(make_op(&types, "is_type", &[&type_mask.to_string()]));
                    }
                }
                arg += 1;
                let var_comment = if op.var.is_empty() {
                    format!("argument {arg}")
                } else {
                    format!("variable {}", op.var)
                };
                if op.cond == "is_func" {
                    let mut parts = op.cond_val.split(':');
                    let (m, f, a) = (
                        parts.next().unwrap(),
                        parts.next().unwrap(),
                        parts.next().unwrap(),
                    );
                    may_fail = true;
                    code.push(make_op(
                        &var_comment,
                        &op.cond,
                        &[&format!("am_{m}"), &format!("am_{f}"), a],
                    ));
                } else if !op.cond.is_empty() {
                    may_fail = true;
                    code.push(make_op(&var_comment, &op.cond, &[&op.cond_val]));
                }
                if !op.var.is_empty() {
                    if var.contains_key(&op.var) {
                        panic!(
                            "{where_}variable {} used more than once\n   (repeated variables in matching is not supported;\n   use the predicate equal(Var1, Var2) to compare variables)",
                            op.var
                        );
                    } else if op.ty == "*" {
                        if var_type.values().any(|t| *t == "array") {
                            panic!(
                                "{where_}only one use of a '*' variable is allowed on the left hand side of a transformation"
                            );
                        }
                        var.insert(op.var.clone(), VarRef::Unnumbered);
                        var_type.insert(op.var.clone(), "array");
                        code.push(make_op(&op.var, "rest_args", &[&item.arity.to_string()]));
                    } else {
                        var_type.insert(op.var.clone(), "scalar");
                        var.insert(op.var.clone(), VarRef::Slot(var_num));
                        code.push(make_op(&op.var, "set_var", &[&var_num.to_string()]));
                        var_num += 1;
                    }
                    unused.insert(op.var.clone());
                }
                code.push(make_op("", "next_arg", &[]));
            }
            // Remove redundant 'next_arg' instructions before the end of the instruction.
            while is_instr(code.last(), "next_arg") {
                code.pop();
            }
        }

        // Insert the commit operation.
        code.push(make_op(
            if may_fail {
                "This rule succeeds"
            } else {
                "This rule always succeeds"
            },
            "commit",
            &[],
        ));
        programs.te_max_vars = programs.te_max_vars.max(var_num);
        From {
            var,
            unused,
            var_type,
            instrs,
            code,
        }
    }

    fn tr_gen_to(&self, transformation: &Transformation, from: From, programs: &mut Programs) {
        let line = &transformation.loc;
        let From {
            var,
            mut unused,
            var_type,
            instrs,
            mut code,
        } = from;
        let where_ = format!("{line}: (right of =>): ");
        let cannot_fail = is_instr(code.last(), "commit")
            && code.last().is_some_and(|s| s.comment.starts_with("always"));

        for item in &transformation.to {
            // A name starting with a period is a C function to be called.
            if let Some(name) = item.name.strip_prefix('.') {
                let mut args: Vec<String> = Vec::new();
                let mut param_types: Vec<&'static str> = Vec::new();
                for v in &item.call_args {
                    let Some(slot) = var.get(v) else {
                        panic!("{where_}variable '{v}' unbound");
                    };
                    unused.remove(v);
                    match (var_type.get(v).copied(), slot) {
                        (Some("scalar"), VarRef::Slot(n)) => {
                            args.push(format!("v{n}"));
                            param_types.push("BeamOpArg");
                        }
                        _ => {
                            args.push("rest_args".to_owned());
                            param_types.push("BeamOpArg*");
                        }
                    }
                }
                programs
                    .c_param_types
                    .insert(format!("gen.{name}"), param_types);
                code.pop(); // Get rid of 'commit' instruction
                let mut op = make_op(
                    &format!("{name}()"),
                    "call",
                    &std::iter::once(name)
                        .chain(args.iter().map(String::as_str))
                        .collect::<Vec<_>>(),
                );
                op.slots = item
                    .call_args
                    .iter()
                    .filter_map(|v| match var.get(v) {
                        Some(VarRef::Slot(n)) => Some(*n),
                        _ => None,
                    })
                    .collect();
                code.push(op);
                break;
            }

            // Check that $name/$arity refers to a valid generic instruction.
            let key = format!("{}/{}", item.name, item.arity);
            let Some(opnum) = self.gen_opnum.get(&(item.name.clone(), item.arity)) else {
                panic!("{where_}invalid generic op {key}");
            };

            // Create code to build the generic instruction.
            code.push(make_op(&key, "new_instr", &[&opnum.to_string()]));
            for op in &item.ops {
                if op.ty == "*" {
                    code.push(make_op(&op.var, "store_rest_args", &[]));
                } else if !op.var.is_empty() {
                    if op.var.starts_with('_') {
                        panic!(
                            "{where_}using explicitly unused variable '{}'. Remove the '_' prefix if this is intentional.",
                            op.var
                        );
                    }
                    let Some(VarRef::Slot(n)) = var.get(&op.var) else {
                        panic!("{where_}variable '{}' unbound", op.var);
                    };
                    let mut store = make_op(&op.var, "store_var", &[&n.to_string()]);
                    store.slots = vec![*n];
                    code.push(store);
                    code.push(make_op("", "next_arg", &[]));
                } else if !op.ty.is_empty() {
                    let val = if op.type_val.is_empty() || op.type_val == "0" {
                        "0"
                    } else {
                        op.type_val.as_str()
                    };
                    let comment = format!("{}={val}", op.ty);
                    code.push(make_op(
                        &comment,
                        "store_val",
                        &[&format!("TAG_{}", op.ty), val],
                    ));
                    code.push(make_op("", "next_arg", &[]));
                }
                unused.remove(&op.var);
            }
            if is_instr(code.last(), "next_arg") {
                code.pop();
            }
        }

        for name in &unused {
            if !name.starts_with('_') {
                panic!(
                    "{where_}variable '{name}' is unused. Prefix with '_' if this is intentional"
                );
            }
        }

        code.push(make_op("", "end", &[]));

        self.tr_maybe_keep(&mut code);
        self.tr_maybe_rename(&mut code);
        combine_commit(&mut code);
        tr_remove_unused(&mut code);

        // chain_instructions
        let first = instrs[0].clone();
        let second = instrs.get(1).cloned();
        let list = programs.rules.entry(first.clone()).or_default();
        if let Some(last) = list.last()
            && last.cannot_fail
        {
            {
                panic!(
                    "Line {line}: A previous transformation shadows '{}'",
                    transformation.orig
                );
            }
        }
        code.remove(0);
        let comment = format!(
            "\n/*\n * Line {line}:\n *   {}\n */\n\n",
            transformation.orig
        );
        list.push(Rule {
            first,
            second,
            cannot_fail,
            comment,
            steps: code,
        });
    }

    fn tr_maybe_keep(&self, code: &mut Vec<Step>) {
        let mut ap = 1usize;
        let mut last_instr: Vec<Option<String>> =
            vec![Some("unknown".into()), Some("ignored".into())];
        let mut pos: Option<usize> = None;
        let mut reused_instr: Option<usize> = None;
        let set = |v: &mut Vec<Option<String>>, at: usize, value: Option<String>| {
            if v.len() <= at {
                v.resize(at + 1, None);
            }
            v[at] = value;
        };
        for i in 0..code.len() {
            let step = &code[i];
            match step.op.as_str() {
                "next_instr" => {
                    last_instr = vec![Some(step.args[0].clone()), Some("ignored".into())];
                    ap = 1;
                }
                "next_arg" => {
                    ap += 1;
                    if pos.is_none() {
                        set(&mut last_instr, ap, Some("ignored".into()));
                    }
                }
                "set_var" => set(&mut last_instr, ap, Some(step.args[0].clone())),
                "new_instr" => match pos {
                    None => {
                        // 'new_instr' immediately after 'commit'.
                        let reused: usize = step.args[0].parse().unwrap();
                        reused_instr = Some(reused);
                        let known: Option<usize> =
                            last_instr[0].as_ref().and_then(|s| s.parse().ok());
                        if known != Some(reused) {
                            return;
                        }
                        pos = Some(i - 1);
                        ap = 1;
                    }
                    Some(start) => {
                        // Second 'new_instr' after 'commit'. The instructions from $pos up to
                        // and including $i - 1 rebuilds the existing instruction exactly.
                        let reused = reused_instr.unwrap();
                        let name = self.gen_opname[reused].clone().unwrap();
                        let arity = self.gen_arity[reused];
                        let reuse = make_op(&format!("{name}/{arity}"), "keep", &[]);
                        code.splice(start..i, [reuse]);
                        return;
                    }
                },
                "store_var" => {
                    let current = last_instr.get(ap).cloned().flatten();
                    if current.as_deref() != Some(step.args[0].as_str()) {
                        return;
                    }
                }
                _ => {
                    if pos.is_some() {
                        return;
                    }
                }
            }
        }
    }

    fn tr_maybe_rename(&self, code: &mut Vec<Step>) {
        #[derive(PartialEq)]
        enum State {
            Left,
            Committed,
            Right,
        }
        let mut state = State::Left;
        let mut a = 0usize;
        let num_args = 0usize;
        let mut new_instr = 0usize;
        let mut first = 0usize;
        for i in 1..code.len() {
            let step = &code[i];
            match state {
                State::Left => match step.op.as_str() {
                    "next_arg" => a += 1,
                    "commit" => {
                        a = 0;
                        first = i;
                        state = State::Committed;
                    }
                    "next_instr" => return,
                    _ => {}
                },
                State::Committed => {
                    if step.op == "new_instr" {
                        new_instr = step.args[0].parse().unwrap();
                        a = 0;
                        state = State::Right;
                    } else {
                        return;
                    }
                }
                State::Right => {
                    if step.op == "end" && a <= num_args {
                        let name = self.gen_opname[new_instr].clone().unwrap();
                        let arity = self.gen_arity[new_instr];
                        let new_op = make_op(
                            &format!("{name}/{arity}"),
                            "rename",
                            &[&new_instr.to_string()],
                        );
                        code.splice(first..=i, [new_op]);
                        return;
                    }
                    return;
                }
            }
        }
    }

    /// `group_tr`.
    fn group_tr(&self, mut list: Vec<Rule>) -> Vec<Rule> {
        // Group transformations (while keeping the order) that all match the same second
        // instruction.
        let mut i = 0;
        while i < list.len() {
            if let Some(current) = list[i].second.clone() {
                // Find the next instruction that as the same second instruction.
                for j in i + 1..list.len() {
                    let Some(other) = list[j].second.clone() else {
                        // If this instruction does not match a second instruction, we must not
                        // continue the search.
                        break;
                    };
                    if other == current {
                        // Found an instruction. If it is already the very next instruction,
                        // place it directly after the current instruction.
                        if j > i + 1 {
                            let element = list.remove(j);
                            list.insert(i, element);
                        }
                        break;
                    }
                }
            }
            i += 1;
        }

        // Add 'try_me_else' instructions to try the next transformation when the current
        // transformation fails.
        let count = list.len();
        for (i, rule) in list.iter_mut().enumerate() {
            if !rule.cannot_fail {
                let op = if i == count - 1 {
                    make_op("", "try_me_else_fail", &[])
                } else {
                    make_op("", "try_me_else", &[])
                };
                rule.steps.insert(0, op);
            }
        }

        // Find consecutive runs of at least two transformation matching the same second
        // instruction. When a run is found, add a 'skip_unless' instruction that will skip all
        // of the instructions in the run when the second instruction is wrong.
        let mut i = 0;
        while i < list.len() {
            let Some(current) = list[i].second.clone() else {
                i += 1;
                continue;
            };
            let mut skip_len = 0;
            let mut j = i;
            while j < list.len() {
                match &list[j].second {
                    Some(other) if *other == current => skip_len += 1,
                    _ => break,
                }
                j += 1;
            }
            if j > i + 1 {
                let num_rules_skipped = j - i;
                let comment = format!(
                    "\n/*\n * Skip {num_rules_skipped} rules unless the second instruction is {current}.\n */\n\n"
                );
                let (name, arity) = current.split_once('/').unwrap();
                let opnum = self.gen_opnum[&(name.to_owned(), arity.parse().unwrap())];
                let op = make_op(
                    "",
                    "skip_unless",
                    &[&opnum.to_string(), &skip_len.to_string()],
                );
                list.insert(
                    i,
                    Rule {
                        first: String::new(),
                        second: Some(String::new()),
                        cannot_fail: true,
                        comment,
                        steps: vec![op],
                    },
                );
                i = j + 1;
                if j == list.len() - 1 {
                    list.push(Rule {
                        first: String::new(),
                        second: Some(String::new()),
                        cannot_fail: false,
                        comment: String::new(),
                        steps: vec![make_op("wrong second instruction", "fail", &[])],
                    });
                }
            }
            i += 1;
        }
        list
    }

    /// The programs as text, one step per line: the format of the dump that a patched
    /// `beam_makeops` prints after `group_tr` (see `tests/erts_transform_programs.rs`).
    pub fn dump_programs(programs: &Programs) -> String {
        let mut out = String::new();
        for (key, rules) in &programs.rules {
            out.push_str(&format!("KEY {key}\n"));
            for rule in rules {
                out.push_str(&format!(
                    "RULE first={} second={} cannot_fail={}\n",
                    rule.first,
                    rule.second.as_deref().unwrap_or("undef"),
                    u8::from(rule.cannot_fail)
                ));
                for step in &rule.steps {
                    out.push_str(&format!("  {} {}\n", step.op, step.args.join(" ")));
                }
            }
        }
        out
    }
}

fn is_number(text: &str) -> bool {
    let digits = text.strip_prefix('-').unwrap_or(text);
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
}

/// `combine_commit`.
fn combine_commit(code: &mut Vec<Step>) {
    let mut i = 1;
    while i < code.len() {
        let step = &code[i];
        if step.op == "rest_args" {
            return;
        } else if step.op == "new_instr" && is_instr(code.get(i - 1), "commit") {
            let comment = code[i - 1].comment.clone();
            let args = code[i].args.clone();
            let mut op = make_op(&comment, "commit_new_instr", &[]);
            op.args = args;
            code.splice(i - 1..=i, [op]);
        }
        i += 1;
    }
}

/// `tr_remove_unused`.
fn tr_remove_unused(code: &mut Vec<Step>) {
    // Collect all used variables.
    let mut used: HashSet<usize> = HashSet::new();
    for step in code.iter() {
        for slot in &step.slots {
            used.insert(*slot);
        }
    }

    // If a variable is not used, don't store the variable.
    for step in code.iter_mut() {
        if step.op == "set_var" {
            let var: usize = step.args[0].parse().unwrap();
            if used.contains(&var) {
                continue;
            }
            *step = make_op(
                &format!("(ignoring unused variable {})", step.comment),
                "nop",
                &[],
            );
        }
    }

    // Delete a sequence of 'next_arg' instructions when they are redundant before
    // instructions such as 'commit'. `@opcode` is not spliced, as in Perl.
    let ending = ["call_end", "commit", "next_instr", "pred", "rename", "keep"];
    let mut opcode: Vec<String> = Vec::new();
    let mut i: isize = 0;
    while (i as usize) < code.len() {
        let op = code[i as usize].op.clone();
        if ending.contains(&op.as_str()) {
            let mut first = i;
            while first > 0
                && opcode
                    .get(first as usize - 1)
                    .is_some_and(|o| o == "next_arg")
            {
                first -= 1;
            }
            let n = i - first;
            code.drain(first as usize..(first + n) as usize);
            i -= n;
        }
        let at = i as usize;
        if opcode.len() <= at {
            opcode.resize(at + 1, String::new());
        }
        opcode[at] = op;
        i += 1;
    }
}
