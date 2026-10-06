//! `beam_disasm` shaped rendering for the operand cross-check.

use arinsal_beam::{AllocKind, BeamFile, Instr, Operand};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};

#[derive(Clone, Debug)]
enum Term {
    Atom(String),
    Number(String),
    Tuple(Vec<Term>),
    List(Vec<Term>),
    Binary(Vec<u8>),
}

fn atom(name: &str) -> Term {
    Term::Atom(name.into())
}
fn num(value: impl ToString) -> Term {
    Term::Number(value.to_string())
}
fn tuple(items: Vec<Term>) -> Term {
    Term::Tuple(items)
}
fn tagged(name: &str, value: Term) -> Term {
    tuple(vec![atom(name), value])
}
fn instruction(name: &str, args: Vec<Term>) -> Term {
    if args.is_empty() {
        atom(name)
    } else {
        let mut items = vec![atom(name)];
        items.extend(args);
        tuple(items)
    }
}
fn u(arg: &Operand) -> Result<u64, String> {
    match arg {
        Operand::U(n) => Ok(*n),
        _ => Err(format!("expected unsigned operand: {arg:?}")),
    }
}
fn list(arg: &Operand) -> Result<&[Operand], String> {
    match arg {
        Operand::List(items) => Ok(items),
        _ => Err(format!("expected list operand: {arg:?}")),
    }
}
fn operand(arg: &Operand, beam: &BeamFile) -> Result<Term, String> {
    Ok(match arg {
        Operand::U(n) => num(n),
        Operand::Int(n) => tagged("integer", num(n)),
        Operand::BigInt(n) => tagged("integer", num(n)),
        Operand::Atom(n) => tagged("atom", atom(beam.atom(*n).ok_or("atom index missing")?)),
        Operand::Nil => atom("nil"),
        Operand::X(n) => tagged("x", num(n)),
        Operand::Y(n) => tagged("y", num(n)),
        Operand::FR(n) => tagged("fr", num(n)),
        Operand::Label(n) => tagged("f", num(n)),
        Operand::Char(n) => tagged("integer", num(n)),
        Operand::Literal(n) => {
            let bytes = &beam
                .literals
                .get(*n as usize)
                .ok_or("literal index missing")?
                .0;
            tuple(vec![
                atom("literal_etf"),
                num(n),
                Term::Binary(bytes.clone()),
            ])
        }
        Operand::List(items) => tagged("list", Term::List(operands(items, beam)?)),
        Operand::Alloc(items) => tagged(
            "alloc",
            Term::List(
                items
                    .iter()
                    .map(|item| {
                        let kind = match item.kind {
                            AllocKind::Words => "words",
                            AllocKind::Floats => "floats",
                            AllocKind::Funs => "funs",
                        };
                        tuple(vec![atom(kind), num(item.count)])
                    })
                    .collect(),
            ),
        ),
        Operand::TypedReg { reg, type_index } => tuple(vec![
            atom("tr"),
            operand(reg, beam)?,
            tagged("type_index", num(type_index)),
        ]),
    })
}
fn operands(args: &[Operand], beam: &BeamFile) -> Result<Vec<Term>, String> {
    args.iter().map(|arg| operand(arg, beam)).collect()
}
fn extfunc(index: u64, beam: &BeamFile) -> Result<Term, String> {
    let import = beam
        .imports
        .get(index as usize)
        .ok_or(format!("import {index} missing"))?;
    Ok(tuple(vec![
        atom("extfunc"),
        atom(
            beam.atom(import.module_atom)
                .ok_or("import module missing")?,
        ),
        atom(
            beam.atom(import.function_atom)
                .ok_or("import function missing")?,
        ),
        num(import.arity),
    ]))
}
fn flags(value: u64) -> Term {
    let mut names = Vec::new();
    for (bit, name) in [(2, "little"), (4, "signed"), (16, "native")] {
        if value & bit != 0 {
            names.push(atom(name));
        }
    }
    tagged("field_flags", Term::List(names))
}
fn string(beam: &BeamFile, off: u64, len: u64) -> Result<Term, String> {
    let start = off as usize;
    let end = start
        .checked_add(len as usize)
        .ok_or("string range overflow")?;
    let bytes = beam
        .strings
        .get(start..end)
        .ok_or("string range outside StrT")?;
    Ok(tagged(
        "string",
        Term::List(bytes.iter().map(num).collect()),
    ))
}
fn binary_string(beam: &BeamFile, off: u64, len: u64) -> Result<Term, String> {
    let start = off as usize;
    let end = start
        .checked_add(len as usize)
        .ok_or("string range overflow")?;
    let bytes = beam
        .strings
        .get(start..end)
        .ok_or("string range outside StrT")?;
    Ok(tagged("string", Term::Binary(bytes.to_vec())))
}
fn bs_create_bin_items(items: &[Operand], beam: &BeamFile) -> Result<Term, String> {
    if !items.len().is_multiple_of(6) {
        return Err("bs_create_bin item count is not divisible by six".into());
    }
    let mut out = Vec::new();
    for part in items.as_chunks::<6>().0 {
        let kind = operand(&part[0], beam)?;
        let value = if matches!(&kind, Term::Tuple(v) if matches!(v.as_slice(), [Term::Atom(tag), Term::Atom(name)] if tag == "atom" && name == "string"))
        {
            let Operand::Int(len) = &part[5] else {
                return Err("string segment length is not integer".into());
            };
            binary_string(beam, u(&part[4])?, *len as u64)?
        } else {
            operand(&part[4], beam)?
        };
        out.extend([
            kind,
            operand(&part[1], beam)?,
            operand(&part[2], beam)?,
            operand(&part[3], beam)?,
            value,
            operand(&part[5], beam)?,
        ]);
    }
    Ok(tagged("list", Term::List(out)))
}
fn bs_match_commands(items: &[Operand], beam: &BeamFile) -> Result<Term, String> {
    let mut out = Vec::new();
    let mut rest = items;
    while let Some((first, tail)) = rest.split_first() {
        let Operand::Atom(index) = first else {
            return Err("bs_match command is not atom".into());
        };
        let name = beam.atom(*index).ok_or("bs_match command atom missing")?;
        let width = match name {
            "ensure_at_least" => 2,
            "ensure_exactly" | "skip" => 1,
            "integer" | "binary" => 5,
            "=:=" => 3,
            "get_tail" => 3,
            _ => return Err(format!("unknown bs_match command {name}")),
        };
        let args = tail.get(..width).ok_or("short bs_match command")?;
        let mut values = operands(args, beam)?;
        if matches!(name, "integer" | "binary") && matches!(args[1], Operand::Nil) {
            values[1] = tagged("literal", Term::List(vec![]));
        }
        let mut command = vec![atom(name)];
        command.extend(values);
        out.push(tuple(command));
        rest = &tail[width..];
    }
    Ok(tagged("commands", Term::List(out)))
}

// Port of lib/compiler/src/beam_disasm.erl:834-1416 (resolve_inst), OTP-29.1.1.
fn resolve(
    ins: &Instr,
    beam: &BeamFile,
    labels: &HashMap<u32, Term>,
    source: &str,
) -> Result<Term, String> {
    let name = ins.op.name();
    let a = &ins.args;
    let r = || operands(a, beam);
    let at =
        |i: usize| -> Result<Term, String> { operand(a.get(i).ok_or("missing operand")?, beam) };
    let n = |i: usize| -> Result<u64, String> { u(a.get(i).ok_or("missing operand")?) };
    let list_at =
        |i: usize| -> Result<Term, String> { operand(a.get(i).ok_or("missing list")?, beam) };
    let call_label = |i: usize| -> Result<Term, String> {
        let Operand::Label(label) = a.get(i).ok_or("missing call label")? else {
            return Err("expected call label".into());
        };
        labels
            .get(label)
            .cloned()
            .ok_or(format!("local call label {label} missing"))
    };
    Ok(match name {
        "label" => instruction(name, vec![at(0)?]),
        "func_info" => instruction(name, r()?),
        "call" | "call_only" => instruction(name, vec![at(0)?, call_label(1)?]),
        "call_last" => instruction(name, vec![at(0)?, call_label(1)?, at(2)?]),
        "call_ext" | "call_ext_only" => instruction(name, vec![at(0)?, extfunc(n(1)?, beam)?]),
        "call_ext_last" => instruction(name, vec![at(0)?, extfunc(n(1)?, beam)?, at(2)?]),
        "bif0" | "bif1" | "bif2" | "bif3" => {
            let arity = name[3..].parse::<usize>().map_err(|e| e.to_string())?;
            let bif_pos = usize::from(arity != 0);
            let import = beam
                .imports
                .get(n(bif_pos)? as usize)
                .ok_or("BIF import missing")?;
            let bif_name = atom(beam.atom(import.function_atom).ok_or("BIF name missing")?);
            let fail = if arity == 0 { atom("nofail") } else { at(0)? };
            let args = (bif_pos + 1..bif_pos + 1 + arity)
                .map(at)
                .collect::<Result<Vec<_>, _>>()?;
            instruction(
                "bif",
                vec![bif_name, fail, Term::List(args), at(a.len() - 1)?],
            )
        }
        "gc_bif1" | "gc_bif2" | "gc_bif3" => {
            let arity = name[6..].parse::<usize>().map_err(|e| e.to_string())?;
            let import = beam
                .imports
                .get(n(2)? as usize)
                .ok_or("GC BIF import missing")?;
            let bif_name = atom(
                beam.atom(import.function_atom)
                    .ok_or("GC BIF name missing")?,
            );
            let args = (3..3 + arity).map(at).collect::<Result<Vec<_>, _>>()?;
            instruction(
                "gc_bif",
                vec![bif_name, at(0)?, at(1)?, Term::List(args), at(a.len() - 1)?],
            )
        }
        "make_fun2" => {
            let old = n(0)? as usize;
            let fun = beam.lambdas.get(old).ok_or("lambda missing")?;
            instruction(
                name,
                vec![
                    tuple(vec![
                        atom(&beam.module),
                        atom(beam.atom(fun.function_atom).ok_or("lambda atom missing")?),
                        num(fun.arity),
                    ]),
                    num(old),
                    num(fun.old_uniq),
                    num(fun.num_free),
                ],
            )
        }
        "make_fun3" => {
            let old = n(0)? as usize;
            let fun = beam.lambdas.get(old).ok_or("lambda missing")?;
            instruction(
                name,
                vec![
                    tuple(vec![
                        atom(&beam.module),
                        atom(beam.atom(fun.function_atom).ok_or("lambda atom missing")?),
                        num(fun.arity),
                    ]),
                    num(old),
                    num(fun.old_uniq),
                    at(1)?,
                    list_at(2)?,
                ],
            )
        }
        "call_fun2" => {
            let tag = match &a[0] {
                Operand::U(old) => {
                    let fun = beam.lambdas.get(*old as usize).ok_or("lambda missing")?;
                    tagged("f", num(fun.label))
                }
                _ => at(0)?,
            };
            instruction(name, vec![tag, at(1)?, at(2)?])
        }
        "line" => {
            let index = n(0)?;
            let items = beam.lines.as_ref().and_then(|lines| {
                index
                    .checked_sub(1)
                    .and_then(|i| lines.items.get(i as usize))
            });
            match items {
                Some(item) => {
                    let file = if item.name_index == 0 {
                        source
                    } else {
                        beam.lines
                            .as_ref()
                            .and_then(|lines| lines.names.get(item.name_index as usize - 1))
                            .map(String::as_str)
                            .ok_or("line name missing")?
                    };
                    instruction(
                        name,
                        vec![Term::List(vec![tuple(vec![
                            atom("location"),
                            Term::List(file.chars().map(|c| num(c as u32)).collect()),
                            num(item.line),
                        ])])],
                    )
                }
                None => instruction(name, vec![Term::List(vec![])]),
            }
        }
        "select_val" | "select_tuple_arity" => instruction(name, vec![at(0)?, at(1)?, list_at(2)?]),
        "put_map_assoc" | "put_map_exact" => {
            instruction(name, vec![at(0)?, at(1)?, at(2)?, at(3)?, list_at(4)?])
        }
        "has_map_fields" => instruction("test", vec![atom(name), at(0)?, at(1)?, list_at(2)?]),
        "get_map_elements" | "get_record_elements" => {
            instruction(name, vec![at(0)?, at(1)?, list_at(2)?])
        }
        "put_tuple2" => instruction(name, vec![at(0)?, list_at(1)?]),
        "init_yregs" => instruction(name, vec![list_at(0)?]),
        "update_record" => instruction(name, vec![at(0)?, at(1)?, at(2)?, at(3)?, list_at(4)?]),
        "put_record" => instruction(name, vec![at(0)?, at(1)?, at(2)?, at(3)?, list_at(5)?]),
        "bs_put_string" => instruction(name, vec![at(0)?, string(beam, n(1)?, n(0)?)?]),
        "bs_match_string" => instruction(
            "test",
            vec![
                atom(name),
                at(0)?,
                Term::List(vec![
                    at(1)?,
                    at(2)?,
                    binary_string(beam, n(3)?, n(2)?.div_ceil(8))?,
                ]),
            ],
        ),
        "is_any_native_record" => instruction("test", vec![atom("is_record"), at(0)?, at(1)?]),
        "is_native_record" => instruction(
            "test",
            vec![atom("is_record"), at(0)?, at(1)?, at(2)?, at(3)?],
        ),
        "is_record_accessible" => instruction("test", vec![atom(name), at(0)?, at(1)?, at(2)?]),
        "get_record_field" => instruction(
            "test",
            vec![atom(name), at(0)?, at(1)?, at(2)?, at(3)?, at(4)?],
        ),
        "raise" => instruction(
            "bif",
            vec![
                atom("raise"),
                tagged("f", num(0)),
                Term::List(r()?),
                tagged("x", num(0)),
            ],
        ),
        "fadd" | "fsub" | "fmul" | "fdiv" | "fnegate" => {
            let mut args = vec![atom(name), at(0)?];
            args.push(Term::List(
                (1..a.len() - 1).map(at).collect::<Result<Vec<_>, _>>()?,
            ));
            args.push(at(a.len() - 1)?);
            instruction("bif", args)
        }
        "bs_put_integer" | "bs_put_binary" | "bs_put_float" => {
            instruction(name, vec![at(0)?, at(1)?, at(2)?, flags(n(3)?), at(4)?])
        }
        "bs_init2" | "bs_init_bits" => instruction(
            name,
            vec![at(0)?, at(1)?, at(2)?, at(3)?, flags(n(4)?), at(5)?],
        ),
        "bs_append" => instruction(
            name,
            vec![
                at(0)?,
                at(1)?,
                at(2)?,
                at(3)?,
                at(4)?,
                at(5)?,
                flags(n(6)?),
                at(7)?,
            ],
        ),
        "bs_private_append" => instruction(
            name,
            vec![at(0)?, at(1)?, at(2)?, at(3)?, flags(n(4)?), at(5)?],
        ),
        "bs_add" => instruction(
            name,
            vec![at(0)?, Term::List(vec![at(1)?, at(2)?, at(3)?]), at(4)?],
        ),
        "bs_start_match2" => instruction(
            "test",
            vec![
                atom(name),
                at(0)?,
                Term::List(vec![at(1)?, at(2)?, at(3)?, at(4)?]),
            ],
        ),
        "bs_start_match3" => instruction(
            "test",
            vec![atom(name), at(0)?, at(2)?, Term::List(vec![at(1)?]), at(3)?],
        ),
        "bs_get_integer2" | "bs_get_binary2" | "bs_get_float2" => instruction(
            "test",
            vec![
                atom(name),
                at(0)?,
                at(2)?,
                Term::List(vec![at(1)?, at(3)?, at(4)?, flags(n(5)?)]),
                at(6)?,
            ],
        ),
        "bs_skip_bits2" => instruction(
            "test",
            vec![
                atom(name),
                at(0)?,
                Term::List(vec![at(1)?, at(2)?, at(3)?, flags(n(4)?)]),
            ],
        ),
        "bs_test_tail2" | "bs_test_unit" => instruction(
            "test",
            vec![atom(name), at(0)?, Term::List(vec![at(1)?, at(2)?])],
        ),
        "bs_get_utf8" | "bs_get_utf16" | "bs_get_utf32" => instruction(
            "test",
            vec![
                atom(name),
                at(0)?,
                Term::List(vec![at(1)?, at(2)?, flags(n(3)?), at(4)?]),
            ],
        ),
        "bs_skip_utf8" | "bs_skip_utf16" | "bs_skip_utf32" => instruction(
            "test",
            vec![
                atom(name),
                at(0)?,
                Term::List(vec![at(1)?, at(2)?, flags(n(3)?)]),
            ],
        ),
        "bs_put_utf8" | "bs_put_utf16" | "bs_put_utf32" => {
            instruction(name, vec![at(0)?, flags(n(1)?), at(2)?])
        }
        "bs_match" => instruction(
            name,
            vec![at(0)?, at(1)?, bs_match_commands(list(&a[2])?, beam)?],
        ),
        "bs_create_bin" => instruction(
            name,
            vec![
                at(0)?,
                at(1)?,
                at(2)?,
                at(3)?,
                at(4)?,
                bs_create_bin_items(list(&a[5])?, beam)?,
            ],
        ),
        "is_lt" | "is_ge" | "is_eq" | "is_ne" | "is_eq_exact" | "is_ne_exact" | "is_integer"
        | "is_float" | "is_number" | "is_atom" | "is_pid" | "is_reference" | "is_port"
        | "is_nil" | "is_binary" | "is_list" | "is_nonempty_list" | "is_tuple" | "test_arity"
        | "is_tagged_tuple" | "is_function" | "is_boolean" | "is_function2" | "is_bitstr"
        | "is_map" => instruction(
            "test",
            vec![
                atom(name),
                at(0)?,
                Term::List((1..a.len()).map(at).collect::<Result<Vec<_>, _>>()?),
            ],
        ),
        "return" | "send" | "remove_message" | "timeout" | "if_end" | "fclearerror"
        | "bs_init_writable" | "on_load" | "build_stacktrace" | "raw_raise" | "nif_start" => {
            atom(name)
        }
        "allocate"
        | "allocate_heap"
        | "allocate_zero"
        | "allocate_heap_zero"
        | "test_heap"
        | "init"
        | "deallocate"
        | "loop_rec"
        | "loop_rec_end"
        | "wait"
        | "wait_timeout"
        | "jump"
        | "catch"
        | "catch_end"
        | "move"
        | "get_list"
        | "get_tuple_element"
        | "set_tuple_element"
        | "put_list"
        | "put_tuple"
        | "put"
        | "badmatch"
        | "case_end"
        | "call_fun"
        | "fcheckerror"
        | "fmove"
        | "fconv"
        | "try"
        | "try_end"
        | "try_case"
        | "try_case_end"
        | "apply"
        | "apply_last"
        | "bs_save2"
        | "bs_restore2"
        | "bs_context_to_binary"
        | "trim"
        | "bs_utf8_size"
        | "bs_utf16_size"
        | "recv_mark"
        | "recv_set"
        | "get_hd"
        | "get_tl"
        | "bs_get_tail"
        | "bs_get_position"
        | "bs_set_position"
        | "bs_start_match4"
        | "swap"
        | "recv_marker_bind"
        | "recv_marker_clear"
        | "recv_marker_reserve"
        | "recv_marker_use"
        | "badrecord"
        | "executable_line"
        | "debug_line" => instruction(name, r()?),
        _ => {
            return Err(format!(
                "unsupported opcode {name} at code offset {}",
                ins.offset
            ));
        }
    })
}

fn source_name(beam: &BeamFile) -> String {
    let Some(info) = &beam.compile_info else {
        return String::new();
    };
    let needle = b"source";
    for i in 0..info.len().saturating_sub(needle.len()) {
        if &info[i..i + needle.len()] == needle {
            let at = i + needle.len();
            if info.get(at) == Some(&107) && at + 3 <= info.len() {
                let len = u16::from_be_bytes([info[at + 1], info[at + 2]]) as usize;
                if let Some(bytes) = info.get(at + 3..at + 3 + len) {
                    let path = String::from_utf8_lossy(bytes);
                    return Path::new(path.as_ref())
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .into_owned();
                }
            }
        }
    }
    String::new()
}

fn escape_atom(value: &str) -> String {
    let mut out = String::from("'");
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out.push('\'');
    out
}
fn render(t: &Term) -> String {
    match t {
        Term::Atom(a) => escape_atom(a),
        Term::Number(n) => n.clone(),
        Term::Tuple(items) => format!(
            "{{{}}}",
            items.iter().map(render).collect::<Vec<_>>().join(",")
        ),
        Term::List(items) => format!(
            "[{}]",
            items.iter().map(render).collect::<Vec<_>>().join(",")
        ),
        Term::Binary(bytes) => format!(
            "<<{}>>",
            bytes
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
}

pub(crate) fn functions(beam: &BeamFile) -> Result<Vec<String>, String> {
    let code = &beam.code.instructions;
    let infos: Vec<usize> = code
        .iter()
        .enumerate()
        .filter_map(|(i, ins)| (ins.op.name() == "func_info").then_some(i))
        .collect();
    let mut starts = Vec::new();
    for &info in &infos {
        let mut start = info;
        while start > 0 && matches!(code[start - 1].op.name(), "label" | "line") {
            start -= 1;
        }
        starts.push(start);
    }
    let mut labels = HashMap::new();
    for &info in &infos {
        let name = match code[info].args.get(1) {
            Some(Operand::Atom(i)) => beam.atom(*i).ok_or("function name missing")?,
            _ => return Err("bad func_info name".into()),
        };
        let arity = u(code[info].args.get(2).ok_or("function arity missing")?)?;
        let entry = match code.get(info + 1).and_then(|ins| ins.args.first()) {
            Some(Operand::U(n)) if code[info + 1].op.name() == "label" => *n as u32,
            _ => return Err("function entry label missing".into()),
        };
        labels.insert(
            entry,
            tuple(vec![atom(&beam.module), atom(name), num(arity)]),
        );
    }
    let source = source_name(beam);
    let mut out = Vec::new();
    for (j, &info) in infos.iter().enumerate() {
        let end = starts.get(j + 1).copied().unwrap_or(code.len() - 1);
        let name = match code[info].args.get(1) {
            Some(Operand::Atom(i)) => beam.atom(*i).ok_or("function name missing")?,
            _ => return Err("bad func_info name".into()),
        };
        let arity = u(code[info].args.get(2).ok_or("function arity missing")?)?;
        let entry = match code.get(info + 1).and_then(|ins| ins.args.first()) {
            Some(Operand::U(n)) => *n,
            _ => return Err("function entry label missing".into()),
        };
        let instrs = code[starts[j]..end]
            .iter()
            .map(|ins| resolve(ins, beam, &labels, &source))
            .collect::<Result<Vec<_>, _>>()?;
        out.push(format!(
            "{}.",
            render(&tuple(vec![
                atom("function"),
                atom(name),
                num(arity),
                num(entry),
                Term::List(instrs)
            ]))
        ));
    }
    Ok(out)
}

pub(crate) fn command(args: &[String]) -> Result<(), String> {
    if args.first().is_some_and(|arg| arg == "--check-all") {
        return check_all(&args[1..]);
    }
    let files: Vec<_> = args
        .iter()
        .filter(|arg| arg.as_str() != "--format" && arg.as_str() != "erl")
        .collect();
    if files.len() != 1
        || (args.len() != 1 && !(args.len() == 3 && args[1] == "--format" && args[2] == "erl"))
    {
        return Err("usage: arinsal disasm <file.beam> [--format erl]".into());
    }
    let bytes = fs::read(files[0]).map_err(|e| e.to_string())?;
    let beam = arinsal_beam::parse(&bytes).map_err(|e| e.to_string())?;
    let terms = functions(&beam)?;
    let rendered =
        std::env::temp_dir().join(format!("arinsal-disasm-render-{}.erl", std::process::id()));
    fs::write(&rendered, terms.join("\n") + "\n").map_err(|e| e.to_string())?;
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/disasm/expand.escript");
    let output = Command::new("escript")
        .arg(script)
        .arg(files[0])
        .arg(&rendered)
        .output()
        .map_err(|e| e.to_string())?;
    fs::remove_file(rendered).map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    print!("{}", String::from_utf8_lossy(&output.stdout));
    Ok(())
}

fn collect(path: &Path, paths: &mut Vec<PathBuf>) -> Result<(), String> {
    if path.is_file() {
        if path.extension().is_some_and(|ext| ext == "beam") {
            paths.push(path.to_path_buf());
        }
        return Ok(());
    }
    for entry in fs::read_dir(path).map_err(|e| format!("{}: {e}", path.display()))? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        if path.is_dir() {
            collect(&path, paths)?;
        } else if path.extension().is_some_and(|ext| ext == "beam") {
            paths.push(path);
        }
    }
    Ok(())
}

fn check_all(dirs: &[String]) -> Result<(), String> {
    let dirs: Vec<String> = if dirs.is_empty() {
        let mut roots = Vec::new();
        if let Some(otp) = runtime_path("erl", "io:format(\"~s\",[code:root_dir()]),halt().") {
            roots.push(otp.join("lib").display().to_string());
            if let Ok(entries) = fs::read_dir(&otp) {
                roots.extend(
                    entries
                        .flatten()
                        .filter(|entry| entry.file_name().to_string_lossy().starts_with("erts-"))
                        .map(|entry| entry.path().display().to_string()),
                );
            }
        }
        if let Some(elixir_ebin) = runtime_path("elixir", "IO.write(:code.lib_dir(:elixir))")
            && let Some(lib) = elixir_ebin.parent().and_then(Path::parent)
        {
            roots.push(lib.display().to_string());
        }
        roots
    } else {
        dirs.to_vec()
    };
    let mut paths = Vec::new();
    for dir in &dirs {
        collect(Path::new(dir), &mut paths)?;
    }
    paths.sort();
    paths.dedup();
    if paths.is_empty() {
        return Err("no .beam files found".into());
    }
    let start = Instant::now();
    let work = std::env::temp_dir().join(format!("arinsal-disasm-{}", std::process::id()));
    let dumps = work.join("dumps");
    let renders = work.join("renders");
    fs::create_dir_all(&dumps).map_err(|e| e.to_string())?;
    fs::create_dir_all(&renders).map_err(|e| e.to_string())?;
    let manifest = work.join("manifest.txt");
    let manifest_text = paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&manifest, format!("{manifest_text}\n")).map_err(|e| e.to_string())?;
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/disasm");
    let status = Command::new("escript")
        .arg(root.join("dump.escript"))
        .arg("--batch")
        .arg(&manifest)
        .arg(&dumps)
        .status()
        .map_err(|e| e.to_string())?;
    if !status.success() {
        return Err(format!(
            "reference dump failed; artifacts: {}",
            work.display()
        ));
    }
    let mut render_failures = Vec::new();
    for (index, path) in paths.iter().enumerate() {
        let result = fs::read(path)
            .map_err(|e| e.to_string())
            .and_then(|bytes| arinsal_beam::parse(&bytes).map_err(|e| e.to_string()))
            .and_then(|beam| functions(&beam));
        match result {
            Ok(lines) => fs::write(
                renders.join(format!("{}.erl", index + 1)),
                lines.join("\n") + "\n",
            )
            .map_err(|e| e.to_string())?,
            Err(error) => render_failures.push(format!("{}: {error}", path.display())),
        }
    }
    if !render_failures.is_empty() {
        return Err(format!(
            "{} rendering failures (first: {}); artifacts: {}",
            render_failures.len(),
            render_failures[0],
            work.display()
        ));
    }
    let output = Command::new("escript")
        .arg(root.join("check.escript"))
        .arg(&manifest)
        .arg(&dumps)
        .arg(&renders)
        .output()
        .map_err(|e| e.to_string())?;
    print!("{}", String::from_utf8_lossy(&output.stdout));
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    println!(
        "elapsed {:.3}s for {} modules",
        start.elapsed().as_secs_f64(),
        paths.len()
    );
    if !output.status.success() {
        return Err(format!("operand mismatches; artifacts: {}", work.display()));
    }
    fs::remove_dir_all(work).map_err(|e| e.to_string())?;
    Ok(())
}

fn runtime_path(program: &str, expression: &str) -> Option<PathBuf> {
    let output = if program == "elixir" {
        std::process::Command::new(program)
            .args(["-e", expression])
            .output()
            .ok()?
    } else {
        std::process::Command::new(program)
            .args(["-noshell", "-eval", expression])
            .output()
            .ok()?
    };
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok().map(PathBuf::from)
}
