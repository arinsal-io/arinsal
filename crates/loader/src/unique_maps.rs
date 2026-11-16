//! Experiment `ARINSAL_UNIQUE_MAPS` (default off): in-place single-pair `put_map_assoc`.
//!
//! OTP updates a map by copying it. For a loop such as
//! `loop(I, N, M) -> loop(I + 1, N, M#{I rem 32 => I})` the old map is dead right after the
//! update, so the copy is pure overhead. This pass finds such functions in the BEAM code and
//! marks their `put_map_assoc` instructions (and the `return`s of the function); the native
//! helper behind a marked instruction overwrites the value word of the map in place when the
//! map is the process's *unique-map slot* (`NativeAbi::uniq_map`) and copies otherwise.
//!
//! # Soundness argument
//!
//! Slot invariant: if `slot != 0`, the object it names is referenced only from X registers of
//! the running analyzed function (or is unreachable garbage). The slot is written only by a
//! marked put that allocated its result fresh (the one reference is the destination register).
//! It is cleared by every collection and heap move, and before every `return` of an analyzed
//! function; an analyzed function has no frame and calls nothing but itself with
//! `call_only`, so the activation that set the slot is the only code that can run while the
//! slot is non-zero, except after an exception, when the object is unreachable.
//!
//! The pass keeps the invariant by a forward dataflow over the function: `U` is the set of X
//! registers that may hold the slot object. `U` grows only at a marked put (its destination)
//! and through `move`; a loop-carried value enters `U` at the entry through the arguments of
//! the self `call_only` (never from outside: callers cannot hold the slot object because of
//! the clearing rule). A function is rewritten only if every instruction is on a short
//! allow-list in which a `U` register is read only by `move`, tests, `select_val`, a marked
//! put and the self call; a read by a BIF, a call, a tuple or list constructor or a `Y`
//! register store would create a second reference (or expose the term in a stack trace), so
//! the function is left alone. At a marked put, every other register of `U` must be dead
//! afterwards: the in-place store would otherwise be visible through the old name.
//!
//! The pass never changes semantics when the slot is empty: a marked put then behaves like
//! `erts_maps_put`.

use arinsal_beam::{BeamFile, Instr, Operand};
use arinsal_spec::Opcode;
use std::collections::HashMap;

/// Bit set in the `Live` operand of a marked `put_map_assoc` (see `arinsal_beamasm::map`).
pub const UNIQUE_MAP_FLAG: u64 = 1 << 20;

/// Whether the experiment is enabled (`ARINSAL_UNIQUE_MAPS=1`).
pub fn enabled() -> bool {
    std::env::var_os("ARINSAL_UNIQUE_MAPS").is_some_and(|v| v != "0")
}

/// Returns a copy of `file` with the analyzed functions marked, or `None` when no function
/// qualifies. The BeamAsm port assembles from `code.bytes`, so the marked instructions are
/// re-encoded into a new byte stream (label numbers, not offsets, address the code).
pub fn rewrite(file: &BeamFile) -> Option<BeamFile> {
    let decoded;
    let src = if file.code.instructions.is_empty() {
        let mut copy = file.clone();
        copy.decode_code().ok()?;
        decoded = copy;
        &decoded
    } else {
        file
    };
    let code = &src.code.instructions;
    let starts = function_starts(code);
    let mut edits: Vec<(usize, Edit)> = Vec::new();
    for (n, &start) in starts.iter().enumerate() {
        let end = starts.get(n + 1).copied().unwrap_or(code.len());
        if let Some(function_edits) = analyze(&code[start..end], start) {
            if std::env::var_os("ARINSAL_UNIQUE_MAPS_TRACE").is_some() {
                let name = code[start..end]
                    .iter()
                    .find(|i| i.op == Opcode::FuncInfo)
                    .map(|i| format!("{:?}", i.args));
                eprintln!("unique_maps: {} marks {:?}", file.module, name);
            }
            edits.extend(function_edits);
        }
    }
    if edits.is_empty() {
        return None;
    }
    let bytes = &src.code.bytes;
    let mut out_bytes = Vec::with_capacity(bytes.len() + 16 * edits.len());
    let mut edit_iter = edits.iter().peekable();
    for (index, instr) in code.iter().enumerate() {
        let end = code.get(index + 1).map_or(bytes.len(), |next| next.offset);
        let original = bytes.get(instr.offset..end)?;
        match edit_iter.peek() {
            Some((at, edit)) if *at == index => {
                match edit {
                    Edit::Mark => {
                        let mut marked = instr.clone();
                        let Some(Operand::U(live)) = marked.args.get_mut(3) else {
                            return None;
                        };
                        *live |= UNIQUE_MAP_FLAG;
                        // Plain registers: the type annotation does not matter to the update.
                        for arg in marked.args.iter_mut().take(3) {
                            if let Operand::TypedReg { reg, .. } = arg {
                                *arg = (**reg).clone();
                            }
                        }
                        encode(&marked, &mut out_bytes)?;
                    }
                    Edit::ReleaseBefore => {
                        let release = Instr {
                            op: Opcode::PutMapAssoc,
                            args: vec![
                                Operand::Label(0),
                                Operand::X(0),
                                Operand::X(0),
                                Operand::U(UNIQUE_MAP_FLAG),
                                Operand::List(Box::default()),
                            ],
                            offset: 0,
                        };
                        encode(&release, &mut out_bytes)?;
                        out_bytes.extend_from_slice(original);
                    }
                }
                edit_iter.next();
            }
            _ => out_bytes.extend_from_slice(original),
        }
    }
    let mut out = src.clone();
    out.code.bytes = out_bytes;
    out.code.instructions = Vec::new();
    Some(out)
}

/// Compact-term encoding of an unsigned (`tag` 0) or signed (`tag` 1) integer.
// Inverse of arinsal_beam compact_inner (beam_file.c beamreader_read_tagged).
fn compact(tag: u8, value: i64, out: &mut Vec<u8>) {
    if (0..16).contains(&value) {
        out.push(((value as u8) << 4) | tag);
    } else if (0..0x800).contains(&value) {
        out.push((((value >> 8) as u8) << 5) | 0x08 | tag);
        out.push(value as u8);
    } else {
        let be = value.to_be_bytes();
        let skip = if value >= 0 {
            be.iter().take_while(|b| **b == 0).count()
        } else {
            be.iter().take_while(|b| **b == 0xff).count()
        };
        // Signed values keep one sign byte; unsigned ones may need a leading zero byte.
        let mut start = skip.min(7);
        if value >= 0 && tag == 1 && be[start] & 0x80 != 0 {
            start -= 1;
        }
        if value < 0 && be[start] & 0x80 == 0 {
            start -= 1;
        }
        let len = 8 - start;
        let len = len.max(2);
        out.push((((len - 2) as u8) << 5) | 0x18 | tag);
        out.extend_from_slice(&be[8 - len..]);
    }
}

fn encode_operand(operand: &Operand, out: &mut Vec<u8>) -> Option<()> {
    match operand {
        Operand::U(n) => compact(0, i64::try_from(*n).ok()?, out),
        Operand::Int(n) => compact(1, *n, out),
        Operand::Atom(n) => compact(2, i64::from(*n), out),
        Operand::Nil => compact(2, 0, out),
        Operand::X(n) => compact(3, i64::from(*n), out),
        Operand::Y(n) => compact(4, i64::from(*n), out),
        Operand::Label(n) => compact(5, i64::from(*n), out),
        Operand::Char(n) => compact(6, i64::from(*n), out),
        Operand::FR(n) => {
            out.push(0x27);
            compact(0, i64::from(*n), out);
        }
        Operand::Literal(n) => {
            out.push(0x47);
            compact(0, i64::from(*n), out);
        }
        Operand::TypedReg { reg, type_index } => {
            out.push(0x57);
            encode_operand(reg, out)?;
            compact(0, i64::from(*type_index), out);
        }
        Operand::List(items) => {
            out.push(0x17);
            compact(0, i64::try_from(items.len()).ok()?, out);
            for item in items.iter() {
                encode_operand(item, out)?;
            }
        }
        Operand::BigInt(_) | Operand::Alloc(_) => return None,
    }
    Some(())
}

fn encode(instr: &Instr, out: &mut Vec<u8>) -> Option<()> {
    out.push(instr.op as u8);
    for arg in &instr.args {
        encode_operand(arg, out)?;
    }
    Some(())
}

#[derive(Clone, Copy)]
enum Edit {
    /// Set the flag in the `Live` operand of the `put_map_assoc` at this index.
    Mark,
    /// Insert a release instruction before the `return` at this index.
    ReleaseBefore,
}

/// Index of the first instruction (the `label` before `func_info`, with its `line`) of each
/// function.
fn function_starts(code: &[Instr]) -> Vec<usize> {
    let mut starts = Vec::new();
    for (index, instr) in code.iter().enumerate() {
        if instr.op != Opcode::FuncInfo {
            continue;
        }
        let mut start = index;
        if start > 0 && code[start - 1].op == Opcode::Line {
            start -= 1;
        }
        if start > 0 && code[start - 1].op == Opcode::Label {
            start -= 1;
        }
        starts.push(start);
    }
    starts
}

/// An X register operand (a typed register counts), `Ok(None)` for a non-register operand and
/// `Err` for a register the pass does not model.
fn reg(operand: &Operand) -> Result<Option<u32>, ()> {
    match operand {
        Operand::X(n) if *n < 64 => Ok(Some(*n)),
        Operand::X(_) | Operand::Y(_) | Operand::FR(_) => Err(()),
        Operand::TypedReg { reg: inner, .. } => reg(inner),
        _ => Ok(None),
    }
}

fn mask(operand: &Operand) -> Result<u64, ()> {
    Ok(reg(operand)?.map_or(0, |n| 1u64 << n))
}

fn mask_all(operands: &[Operand]) -> Result<u64, ()> {
    operands.iter().try_fold(0u64, |acc, o| Ok(acc | mask(o)?))
}

fn label(operand: &Operand) -> Option<u32> {
    match operand {
        Operand::Label(0) => None,
        Operand::Label(l) => Some(*l),
        _ => None,
    }
}

fn low_regs(n: u64) -> u64 {
    if n >= 64 { u64::MAX } else { (1u64 << n) - 1 }
}

/// What the dataflow needs to know about one instruction.
struct Step {
    /// Registers read (for liveness and for the allow-list).
    reads: u64,
    /// Registers written.
    defs: u64,
    /// Registers that must not hold the slot object when read here.
    forbidden: u64,
    /// Labels control may transfer to.
    targets: Vec<u32>,
    /// Whether control may fall through.
    falls: bool,
    /// Registers proven not to hold a map on the failure edge (`is_map` failed).
    fail_clear: u64,
    /// Registers proven not to hold a map on the success edge (`is_integer` and the like).
    ok_clear: u64,
    kind: Kind,
}

enum Kind {
    Plain,
    /// `move`: copies membership of `U` from `from` to `to`.
    Move {
        from: u64,
        to: u64,
    },
    /// A marked-put candidate: destination gets the slot object.
    Put {
        dst: u64,
    },
    /// The self `call_only`: its argument registers flow to the entry.
    SelfCall,
    Return,
}

fn step(instr: &Instr, arity: u32, entry: u32, info: u32) -> Option<Step> {
    let a = &instr.args;
    let plain = |reads: u64, defs: u64, targets: Vec<u32>| Step {
        reads,
        defs,
        forbidden: 0,
        targets,
        falls: true,
        fail_clear: 0,
        ok_clear: 0,
        kind: Kind::Plain,
    };
    use Opcode::*;
    let step = match instr.op {
        Label | Line | ExecutableLine | FuncInfo => plain(0, 0, vec![]),
        Move => {
            let from = mask(a.first()?).ok()?;
            let to = mask(a.get(1)?).ok()?;
            if to == 0 && !matches!(a.get(1)?, Operand::X(_) | Operand::TypedReg { .. }) {
                return None;
            }
            Step {
                kind: Kind::Move { from, to },
                ..plain(from, to, vec![])
            }
        }
        Jump => Step {
            falls: false,
            ..plain(0, 0, label(a.first()?).into_iter().collect())
        },
        IsLt | IsGe | IsEq | IsNe | IsEqExact | IsNeExact | IsInteger | IsFloat | IsNumber
        | IsAtom | IsPid | IsReference | IsPort | IsNil | IsBinary | IsList | IsNonemptyList
        | IsTuple | IsBoolean | IsMap | IsBitstr | TestArity | IsTaggedTuple => {
            let reads = mask_all(a.get(1..)?).ok()?;
            let tested = mask(a.get(1)?).ok()?;
            let (fail_clear, ok_clear) = match instr.op {
                // The failure edge of `is_map` carries a non-map: not the slot object.
                IsMap => (tested, 0),
                // A success edge of a type test other than `is_map` carries a non-map.
                IsInteger | IsFloat | IsNumber | IsAtom | IsPid | IsReference | IsPort | IsNil
                | IsBinary | IsList | IsNonemptyList | IsTuple | IsBoolean | IsBitstr
                | TestArity | IsTaggedTuple => (0, tested),
                _ => (0, 0),
            };
            Step {
                fail_clear,
                ok_clear,
                ..plain(reads, 0, label(a.first()?).into_iter().collect())
            }
        }
        PutTuple2 => {
            let items = match a.get(1)? {
                Operand::List(items) => mask_all(items).ok()?,
                _ => return None,
            };
            Step {
                forbidden: items,
                ..plain(items, mask(a.first()?).ok()?, vec![])
            }
        }
        CallExtOnly => {
            // A tail call out of the function: the arguments must not name the slot object; the
            // registers left behind are dead.
            let Operand::U(n) = a.first()? else {
                return None;
            };
            Step {
                falls: false,
                forbidden: low_regs(*n),
                ..plain(low_regs(*n), 0, vec![])
            }
        }
        SelectVal | SelectTupleArity => {
            let reads = mask(a.first()?).ok()?;
            let mut targets: Vec<u32> = label(a.get(1)?).into_iter().collect();
            let Operand::List(items) = a.get(2)? else {
                return None;
            };
            targets.extend(items.iter().skip(1).step_by(2).filter_map(label));
            Step {
                falls: false,
                ..plain(reads, 0, targets)
            }
        }
        GcBif1 | GcBif2 | GcBif3 | Bif1 | Bif2 => {
            let gc = matches!(instr.op, GcBif1 | GcBif2 | GcBif3);
            let first_src = if gc { 3 } else { 2 };
            let (dst, srcs) = a.split_last()?;
            let srcs = srcs.get(first_src..)?;
            let src_mask = mask_all(srcs).ok()?;
            let live = if gc {
                match a.get(1)? {
                    Operand::U(n) => low_regs(*n),
                    _ => return None,
                }
            } else {
                0
            };
            Step {
                forbidden: src_mask,
                ..plain(
                    src_mask | live,
                    mask(dst).ok()?,
                    label(a.first()?).into_iter().collect(),
                )
            }
        }
        TestHeap => {
            let live = match a.get(1)? {
                Operand::U(n) => low_regs(*n),
                _ => return None,
            };
            plain(live, 0, vec![])
        }
        GetMapElements | HasMapFields => {
            // Reads the map only; extracted values are subterms, not the map.
            let src = mask(a.get(1)?).ok()?;
            let Operand::List(items) = a.get(2)? else {
                return None;
            };
            let mut reads = src;
            let mut defs = 0;
            let step_by = if instr.op == GetMapElements { 2 } else { 1 };
            for (i, item) in items.iter().enumerate() {
                if step_by == 2 && i % 2 == 1 {
                    defs |= mask(item).ok()?;
                } else {
                    reads |= mask(item).ok()?;
                }
            }
            plain(reads, defs, label(a.first()?).into_iter().collect())
        }
        PutMapAssoc => {
            let Operand::List(items) = a.get(4)? else {
                return None;
            };
            if items.len() != 2 || label(a.first()?).is_some() {
                return None;
            }
            if matches!(a.get(1)?, Operand::Label(_)) || a.get(1).is_none() {
                return None;
            }
            let src = reg(a.get(1)?).ok()??;
            let dst = reg(a.get(2)?).ok()??;
            let kv = mask_all(items).ok()?;
            Step {
                forbidden: kv,
                kind: Kind::Put { dst: 1 << dst },
                ..plain(kv | (1 << src), 1 << dst, vec![])
            }
        }
        CallOnly => {
            let (Operand::U(n), Operand::Label(l)) = (a.first()?, a.get(1)?) else {
                return None;
            };
            if *n as u32 != arity || *l != entry {
                return None;
            }
            Step {
                falls: false,
                kind: Kind::SelfCall,
                ..plain(low_regs(u64::from(arity)), 0, vec![])
            }
        }
        Return => Step {
            falls: false,
            kind: Kind::Return,
            ..plain(1, 0, vec![])
        },
        _ => return None,
    };
    if step.targets.contains(&info) {
        return None; // function_clause path would expose the arguments
    }
    Some(step)
}

fn analyze(body: &[Instr], base: usize) -> Option<Vec<(usize, Edit)>> {
    let mut info_label = None;
    let mut entry = None;
    let mut arity = 0u32;
    let mut labels: HashMap<u32, usize> = HashMap::new();
    for (i, instr) in body.iter().enumerate() {
        match (instr.op, instr.args.first()) {
            (Opcode::Label, Some(Operand::U(l))) => {
                labels.insert(*l as u32, i);
                if info_label.is_none() {
                    info_label = Some(*l as u32);
                } else if entry.is_none() {
                    entry = Some(*l as u32);
                }
            }
            (Opcode::FuncInfo, _) => {
                if let Some(Operand::U(n)) = instr.args.get(2) {
                    arity = *n as u32;
                }
            }
            _ => {}
        }
    }
    let (info_label, entry) = (info_label?, entry?);
    if arity > 32 || !body.iter().any(|i| i.op == Opcode::PutMapAssoc) {
        return None;
    }
    let trace = std::env::var_os("ARINSAL_UNIQUE_MAPS_TRACE").is_some();
    let mut steps: Vec<Step> = Vec::with_capacity(body.len());
    for i in body {
        match step(i, arity, entry, info_label) {
            Some(s) => steps.push(s),
            None => {
                if trace {
                    eprintln!("unique_maps: rejected at {:?} {:?}", i.op, i.args);
                }
                return None;
            }
        }
    }
    let target_index = |label: u32| labels.get(&label).copied();
    let entry_index = *labels.get(&entry)?;
    // Fixpoint over the argument positions that may carry the slot object into the entry.
    let mut params = 0u64;
    let u_in = loop {
        let mut u_in: Vec<Option<u64>> = vec![None; body.len()];
        u_in[entry_index] = Some(params);
        let mut work = vec![entry_index];
        let mut carried = 0u64;
        while let Some(i) = work.pop() {
            let u = u_in[i]?;
            let s = &steps[i];
            let out = match s.kind {
                Kind::Move { from, to } => {
                    let cleared = u & !to;
                    if u & from != 0 { cleared | to } else { cleared }
                }
                Kind::Put { dst } => u | dst,
                _ => u & !s.defs,
            };
            if matches!(s.kind, Kind::SelfCall) {
                carried |= u & low_regs(u64::from(arity));
            }
            let mut next: Vec<(usize, u64)> = Vec::new();
            for l in &s.targets {
                next.push((target_index(*l)?, out & !s.fail_clear));
            }
            if s.falls && i + 1 < body.len() {
                next.push((i + 1, out & !s.ok_clear));
            }
            for (n, out) in next {
                let merged = u_in[n].map_or(out, |old| old | out);
                if u_in[n] != Some(merged) {
                    u_in[n] = Some(merged);
                    work.push(n);
                }
            }
        }
        // `carried` also holds registers already in `params`; positions are registers here
        // because the arguments of a call are x0..x(arity-1).
        if carried & !params == 0 {
            break u_in;
        }
        params |= carried;
    };
    // Checks and edits.
    let mut edits = Vec::new();
    for (i, s) in steps.iter().enumerate() {
        let Some(u) = u_in[i] else { continue };
        if s.forbidden & u != 0 {
            if trace {
                eprintln!("unique_maps: forbidden read at {:?} u={u:b}", body[i].op);
            }
            return None;
        }
        match s.kind {
            Kind::Put { dst } => {
                // Every other register that may name the object must be dead afterwards.
                let others = u & !dst;
                if others != 0 && read_after(&steps, &labels, i, others, arity).is_none() {
                    if trace {
                        eprintln!("unique_maps: alias live after put, others={others:b}");
                    }
                    return None;
                }
                edits.push((base + i, Edit::Mark));
            }
            Kind::Return => edits.push((base + i, Edit::ReleaseBefore)),
            _ => {}
        }
    }
    if !edits.iter().any(|(_, e)| matches!(e, Edit::Mark)) {
        return None;
    }
    Some(edits)
}

/// `Some(())` when none of `regs` is read on any path from after instruction `from` before it
/// is overwritten.
fn read_after(
    steps: &[Step],
    labels: &HashMap<u32, usize>,
    from: usize,
    regs: u64,
    _arity: u32,
) -> Option<()> {
    for r in 0..64 {
        let bit = 1u64 << r;
        if regs & bit == 0 {
            continue;
        }
        let mut seen = vec![false; steps.len()];
        let mut work = vec![from];
        seen[from] = true;
        let mut first = true;
        while let Some(i) = work.pop() {
            let s = &steps[i];
            if !first {
                if s.reads & bit != 0 {
                    return None;
                }
                if s.defs & bit != 0 {
                    continue;
                }
            }
            first = false;
            let mut next: Vec<usize> = Vec::new();
            for l in &s.targets {
                next.push(*labels.get(l)?);
            }
            if s.falls && i + 1 < steps.len() {
                next.push(i + 1);
            }
            for n in next {
                if !seen[n] {
                    seen[n] = true;
                    work.push(n);
                }
            }
        }
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dump() {
        let dir = std::env::temp_dir();
        let src = dir.join("um_dump.erl");
        std::fs::write(&src, "-module(um_dump).\n-export([loop/3]).\nloop(N, N, M) -> M;\nloop(I, N, M) -> loop(I + 1, N, M#{I rem 4 => I}).\n").unwrap();
        if !std::process::Command::new("erlc")
            .arg("-o")
            .arg(&dir)
            .arg(&src)
            .status()
            .is_ok_and(|s| s.success())
        {
            return;
        }
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../cli/tests/fixtures/unique_maps.erl");
        let _ = std::process::Command::new("erlc")
            .arg("-o")
            .arg(&dir)
            .arg(&fixture)
            .status();
        let bytes = std::fs::read(dir.join("unique_maps.beam")).unwrap();
        let file = arinsal_beam::parse(&bytes).unwrap();
        let out = rewrite(&file).expect("marked");
        let mut reparsed = out.clone();
        reparsed.decode_code().expect("re-encoded code decodes");
        assert!(reparsed.code.instructions.iter().any(|i| {
            i.op == Opcode::PutMapAssoc
                && matches!(i.args.get(3), Some(Operand::U(n)) if n & UNIQUE_MAP_FLAG != 0)
        }));
    }
}
