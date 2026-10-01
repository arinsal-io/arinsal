//! BEAM bit syntax instruction handlers.

use crate::{Process, VmError};
use arinsal_bits::{
    BitsError, MatchOps, SegFlags, SegSize, SegType, Segment, SegmentValue, create_bin,
    create_bin_size, get_position, init_writable, set_position_term, start_match,
};
use arinsal_etf::OwnedTerm;
use arinsal_loader::{Arg, BitCommandKind, GenericOp, Instr, Module};
use arinsal_spec::Opcode;
use arinsal_term::{Term, TermKind, exact_eq, is_match_context, to_owned};

/// Execute a load-time decoded common bit-syntax command.
pub(super) fn execute_compact(
    p: &mut Process,
    instr: Instr,
    frame: impl Fn() -> String,
) -> Result<(), VmError> {
    match instr {
        Instr::BsEnsure {
            context,
            bits,
            unit,
            fail,
            exact,
        } => {
            let ctx = p.x[context as usize];
            let ok = is_match_context(ctx)
                && if exact {
                    ctx.ensure_exactly(bits as usize)
                } else {
                    ctx.ensure_at_least(bits as usize, unit as usize)
                };
            if !ok {
                return branch(p, Arg::new(Arg::LABEL, u64::from(fail)), &frame);
            }
        }
        Instr::BsReadU32 { context, dst, fail } => {
            let Some(value) = arinsal_bits::match_u32_be(p.x[context as usize]) else {
                return branch(p, Arg::new(Arg::LABEL, u64::from(fail)), &frame);
            };
            p.x[dst as usize] = Term::small(i64::from(value)).unwrap();
        }
        Instr::BsReadUint {
            context,
            dst,
            fail,
            ensure_bits,
            unit,
            bits,
        } => {
            let Some(value) = arinsal_bits::match_uint_be(
                p.x[context as usize],
                ensure_bits as usize,
                unit as usize,
                bits as usize,
            ) else {
                return branch(p, Arg::new(Arg::LABEL, u64::from(fail)), &frame);
            };
            p.x[dst as usize] = Term::small(i64::from(value)).unwrap();
        }
        Instr::BsBinaryReg {
            context,
            size,
            dst,
            live,
            fail,
        } => {
            let Some(bits) = p.x[size as usize]
                .as_small()
                .and_then(|n| usize::try_from(n).ok())
                .and_then(|n| n.checked_mul(8))
            else {
                return branch(p, Arg::new(Arg::LABEL, u64::from(fail)), &frame);
            };
            if !is_match_context(p.x[context as usize]) {
                return branch(p, Arg::new(Arg::LABEL, u64::from(fail)), &frame);
            }
            let result = allocated_compact(
                p,
                live as usize,
                |p| p.x[context as usize].get_binary(bits, &mut p.heap),
                &frame,
            )?;
            let Some(value) = result else {
                return branch(p, Arg::new(Arg::LABEL, u64::from(fail)), &frame);
            };
            p.x[dst as usize] = value;
        }
        Instr::BsTail { context, dst, live } => {
            if !is_match_context(p.x[context as usize]) {
                return Err(VmError::Exception {
                    reason: "badarg".into(),
                    frame: frame(),
                });
            }
            let value = allocated_compact(
                p,
                live as usize,
                |p| p.x[context as usize].get_tail(&mut p.heap),
                &frame,
            )?;
            p.x[dst as usize] = value;
        }
        Instr::BsMatchTail {
            context,
            dst,
            live,
            unit,
            fail,
        } => {
            if !is_match_context(p.x[context as usize]) {
                return branch(p, Arg::new(Arg::LABEL, u64::from(fail)), &frame);
            }
            let value = allocated_compact(
                p,
                live as usize,
                |p| p.x[context as usize].get_tail_unit(unit as usize, &mut p.heap),
                &frame,
            )?;
            let Some(value) = value else {
                return branch(p, Arg::new(Arg::LABEL, u64::from(fail)), &frame);
            };
            p.x[dst as usize] = value;
        }
        _ => unreachable!(),
    }
    p.ip += 1;
    Ok(())
}

fn atom(term: Term) -> Option<std::sync::Arc<str>> {
    term.as_atom()
        .and_then(|a| arinsal_term::global_atoms().text(a))
}

#[inline]
fn number(p: &Process, arg: Arg) -> Result<Option<usize>, VmError> {
    let value = if arg.kind() == Arg::U {
        return Ok(usize::try_from(arg.value()).ok());
    } else {
        p.read(arg)?
    };
    Ok(value.as_small().and_then(|n| usize::try_from(n).ok()))
}

#[inline]
fn flags(p: &Process, arg: Arg) -> SegFlags {
    if arg.kind() != Arg::U {
        let mut current = p.read(arg).unwrap_or(Term::NIL);
        let mut parsed = SegFlags::default();
        while current.classify() == TermKind::List {
            // SAFETY: The operand literal heap remains owned by the loaded module.
            let Some((head, tail)) = (unsafe { current.cons_ref() }) else {
                break;
            };
            match atom(head).as_deref() {
                Some("little") => parsed.little = true,
                Some("signed") => parsed.signed = true,
                Some("native") => parsed.native = true,
                _ => {}
            }
            current = tail;
        }
        return parsed;
    }
    let bits = arg.value();
    SegFlags {
        little: bits & 2 != 0,
        signed: bits & 4 != 0,
        native: bits & 16 != 0,
    }
}

trait FrameName {
    fn to_frame_string(&self) -> String;
}

impl FrameName for str {
    fn to_frame_string(&self) -> String {
        self.to_owned()
    }
}

impl FrameName for String {
    fn to_frame_string(&self) -> String {
        self.clone()
    }
}

impl<F: Fn() -> String> FrameName for F {
    fn to_frame_string(&self) -> String {
        self()
    }
}

#[inline]
fn branch(p: &mut Process, fail: Arg, frame: &(impl FrameName + ?Sized)) -> Result<(), VmError> {
    if fail.kind() == Arg::LABEL && fail.value() != u32::MAX as u64 {
        p.ip = fail.value() as usize;
        Ok(())
    } else {
        Err(VmError::Exception {
            reason: "badarg".into(),
            frame: frame.to_frame_string(),
        })
    }
}

/// The exception reason and `error_info` of a failed bit syntax operation in native code.
pub(crate) fn native_error(error: BitsError) -> (String, Option<Box<arinsal_etf::OwnedTerm>>) {
    match self::error(error, "") {
        VmError::ExceptionInfo { reason, info, .. } => (reason, Some(info)),
        VmError::Exception { reason, .. } => (reason, None),
        _ => ("badarg".into(), None),
    }
}

fn error(error: BitsError, frame: &(impl FrameName + ?Sized)) -> VmError {
    match error {
        BitsError::Detailed {
            segment,
            reason,
            ty,
            field,
            value,
        } => {
            let Some(value) = to_owned(value).ok() else {
                return VmError::Exception {
                    reason: reason.into(),
                    frame: frame.to_frame_string(),
                };
            };
            let atom = |name: &str| OwnedTerm::Atom(name.to_owned());
            let info = OwnedTerm::Map(vec![
                (
                    atom("cause"),
                    OwnedTerm::Tuple(vec![
                        OwnedTerm::Int(segment as i64),
                        atom(ty),
                        atom(field),
                        value,
                    ]),
                ),
                (atom("function"), atom("format_bs_fail")),
                (atom("module"), atom("erl_erts_errors")),
            ]);
            VmError::ExceptionInfo {
                reason: reason.into(),
                frame: frame.to_frame_string(),
                info: Box::new(info),
            }
        }
        BitsError::BadArg { .. } => VmError::Exception {
            reason: "badarg".into(),
            frame: frame.to_frame_string(),
        },
        BitsError::SystemLimit { .. } => VmError::Exception {
            reason: "system_limit".into(),
            frame: frame.to_frame_string(),
        },
        BitsError::HeapFull { .. } => VmError::Unsupported("bit syntax heap".into()),
    }
}

#[inline]
fn allocated<T>(
    p: &mut Process,
    live: usize,
    mut operation: impl FnMut(&mut Process) -> Result<T, BitsError>,
    frame: &impl Fn() -> String,
) -> Result<T, VmError> {
    match operation(p) {
        Ok(result) => Ok(result),
        Err(BitsError::HeapFull { need_words }) => {
            retry_after_gc(p, live, need_words, &mut operation, frame)
        }
        Err(other) => Err(error(other, &frame())),
    }
}

fn live_with_source(live: usize, source: Arg) -> usize {
    if source.kind() == Arg::X {
        live.max(source.value() as usize + 1)
    } else {
        live
    }
}

#[inline]
fn allocated_compact<T>(
    p: &mut Process,
    live: usize,
    mut operation: impl FnMut(&mut Process) -> Result<T, BitsError>,
    frame: &impl Fn() -> String,
) -> Result<T, VmError> {
    match operation(p) {
        Ok(result) => Ok(result),
        Err(BitsError::HeapFull { need_words }) => {
            retry_after_gc(p, live, need_words, &mut operation, frame)
        }
        Err(other) => Err(error(other, frame)),
    }
}

/// Collect and retry a bit-syntax allocation.
///
/// The heap-word hint is a lower bound. A slice of a heap binary can need more
/// words than a refc sub-binary, and `free_words` can already cover a short
/// hint while the real object does not fit. Each miss asks for a strictly
/// larger gap so the next collection cannot no-op.
fn retry_after_gc<T>(
    p: &mut Process,
    live: usize,
    mut need_words: usize,
    operation: &mut impl FnMut(&mut Process) -> Result<T, BitsError>,
    frame: &impl Fn() -> String,
) -> Result<T, VmError> {
    for _ in 0..4 {
        let free = p.heap.free_words();
        let request = if free >= need_words {
            need_words
                .saturating_mul(2)
                .max(need_words.saturating_add(16))
        } else {
            need_words
        };
        p.ensure(request, live)?;
        match operation(p) {
            Ok(result) => return Ok(result),
            Err(BitsError::HeapFull { need_words: next }) => {
                need_words = next.max(request);
            }
            Err(other) => return Err(error(other, frame)),
        }
    }
    Err(error(BitsError::HeapFull { need_words }, frame))
}

fn segments<'a>(
    p: &Process,
    module: &'a Module,
    args: &[Arg],
) -> Result<Vec<Segment<'a>>, VmError> {
    let mut out = Vec::with_capacity(args.len() / 6);
    for (index, part) in args.as_chunks::<6>().0.iter().enumerate() {
        let ty = match atom(p.read(part[0])?).as_deref() {
            Some("integer") => SegType::Integer,
            Some("float") => SegType::Float,
            Some("binary") => SegType::Binary,
            Some("append") => SegType::Append,
            Some("private_append") => SegType::PrivateAppend,
            Some("string") => SegType::String,
            Some("utf8") => SegType::Utf8,
            Some("utf16") => SegType::Utf16,
            Some("utf32") => SegType::Utf32,
            _ => return Err(VmError::Unsupported("bit syntax segment type".into())),
        };
        let size = match part[5].kind() {
            Arg::U => SegSize::Units(part[5].value()),
            _ => {
                let term = p.read(part[5])?;
                if atom(term).as_deref() == Some("all") {
                    SegSize::All
                } else {
                    SegSize::Term(term)
                }
            }
        };
        let value = if ty == SegType::String {
            let start = usize::try_from(part[4].value())
                .map_err(|_| VmError::Unsupported("string offset".into()))?;
            let len = match size {
                SegSize::Units(n) => usize::try_from(n).ok(),
                SegSize::Term(term) => term.as_small().and_then(|n| usize::try_from(n).ok()),
                SegSize::All => None,
            }
            .ok_or_else(|| VmError::Unsupported("string length".into()))?;
            SegmentValue::String(
                module
                    .strings
                    .get(start..start.saturating_add(len))
                    .ok_or_else(|| VmError::Unsupported("string table range".into()))?,
            )
        } else {
            SegmentValue::Term(p.read(part[4])?)
        };
        out.push(Segment {
            ty,
            index: usize::try_from(part[1].value()).unwrap_or(index + 1),
            unit: u8::try_from(part[2].value())
                .map_err(|_| VmError::Unsupported("bit syntax unit".into()))?,
            flags: flags(p, part[3]),
            value,
            size,
        });
    }
    Ok(out)
}

fn field_bits(p: &Process, size: Arg, unit: Arg) -> Result<Option<usize>, VmError> {
    Ok(number(p, size)?.and_then(|n| n.checked_mul(unit.value() as usize)))
}

fn match_commands(
    p: &mut Process,
    module: &Module,
    op: &GenericOp,
    frame: &impl Fn() -> String,
) -> Result<(), VmError> {
    let [fail, context_arg, commands] = op.args;
    let index = commands.value() as usize;
    let args = &module.lists[index];
    let decoded = module.bit_commands[index].as_deref();
    let mut offset = 0;
    let mut command_index = 0;
    while offset < args.len() {
        let (kind, width) = if let Some(decoded) = decoded {
            let command = decoded[command_index];
            (command.kind, command.width)
        } else {
            let name = atom(p.read(args[offset])?)
                .ok_or_else(|| VmError::Unsupported("bs_match command".into()))?;
            match name.as_ref() {
                "ensure_at_least" => (BitCommandKind::EnsureAtLeast, 3),
                "ensure_exactly" => (BitCommandKind::EnsureExactly, 2),
                "skip" => (BitCommandKind::Skip, 2),
                "integer" => (BitCommandKind::Integer, 6),
                "binary" => (BitCommandKind::Binary, 6),
                "get_tail" => (BitCommandKind::GetTail, 4),
                "=:=" => (BitCommandKind::Eq, 4),
                _ => return Err(VmError::Unsupported(format!("bs_match command {name}"))),
            }
        };
        let part = args
            .get(offset..offset + width)
            .ok_or_else(|| VmError::Unsupported("short bs_match command".into()))?;
        let ctx = p.read(context_arg)?;
        let ok = match kind {
            BitCommandKind::EnsureAtLeast => number(p, part[1])?
                .is_some_and(|bits| ctx.ensure_at_least(bits, part[2].value() as usize)),
            BitCommandKind::EnsureExactly => {
                number(p, part[1])?.is_some_and(|bits| ctx.ensure_exactly(bits))
            }
            BitCommandKind::Skip => number(p, part[1])?.is_some_and(|bits| ctx.skip(bits)),
            BitCommandKind::Eq => {
                let Some(bits) = number(p, part[2])? else {
                    return branch(p, fail, &frame());
                };
                if bits <= 64 && part[3].kind() == Arg::U {
                    ctx.match_integer(bits, part[3].value())
                } else if part[3].kind() != Arg::U
                    && bits <= 59
                    && p.read(part[3])?.as_small().is_some_and(|n| n >= 0)
                {
                    ctx.match_integer(bits, p.read(part[3])?.as_small().unwrap() as u64)
                } else {
                    let saved = ctx.position();
                    let result = allocated(
                        p,
                        part[1].value() as usize,
                        |p| {
                            p.read(context_arg)
                                .map_err(|_| BitsError::BadArg { segment: 0 })?
                                .get_integer(bits, SegFlags::default(), &mut p.heap)
                        },
                        frame,
                    )?;
                    let same = match result {
                        Some(term) if part[3].kind() == Arg::U => match to_owned(term) {
                            Ok(OwnedTerm::Int(n)) => n >= 0 && n as u64 == part[3].value(),
                            Ok(OwnedTerm::BigInt(ref n)) => {
                                n.to_string() == part[3].value().to_string()
                            }
                            _ => false,
                        },
                        Some(term) => exact_eq(term, p.read(part[3])?),
                        None => false,
                    };
                    if !same {
                        p.read(context_arg)?.set_position(saved);
                    }
                    same
                }
            }
            BitCommandKind::Integer | BitCommandKind::Binary => {
                let Some(bits) = field_bits(p, part[3], part[4])? else {
                    return branch(p, fail, &frame());
                };
                let live = part[1].value() as usize;
                let result = allocated(
                    p,
                    live,
                    |p| {
                        let ctx = p
                            .read(context_arg)
                            .map_err(|_| BitsError::BadArg { segment: 0 })?;
                        if matches!(kind, BitCommandKind::Integer) {
                            ctx.get_integer(bits, flags(p, part[2]), &mut p.heap)
                        } else {
                            ctx.get_binary(bits, &mut p.heap)
                        }
                    },
                    frame,
                )?;
                if let Some(value) = result {
                    p.write(part[5], value)?;
                    true
                } else {
                    false
                }
            }
            BitCommandKind::GetTail => {
                let live = part[1].value() as usize;
                let result = allocated(
                    p,
                    live,
                    |p| {
                        let ctx = p
                            .read(context_arg)
                            .map_err(|_| BitsError::BadArg { segment: 0 })?;
                        ctx.get_tail_unit(part[2].value() as usize, &mut p.heap)
                    },
                    frame,
                )?;
                if let Some(value) = result {
                    p.write(part[3], value)?;
                    true
                } else {
                    false
                }
            }
        };
        if !ok {
            return branch(p, fail, &frame());
        }
        offset += width;
        command_index += 1;
    }
    p.ip += 1;
    Ok(())
}

/// Execute a bit syntax opcode after the VM has synchronized its heap cursor.
#[inline]
pub(super) fn execute(
    p: &mut Process,
    module: &Module,
    op: &GenericOp,
    frame: &impl Fn() -> String,
) -> Result<(), VmError> {
    let [a, b, c] = op.args;
    match op.opcode() {
        Opcode::BsCreateBin => {
            let list = module.arg(op, 5);
            let live = c.value() as usize;
            let args = &module.lists[list.value() as usize];
            if let [part] = args.as_chunks::<6>().0
                && args.len() == 6
                && let Some(kind) = p.read(part[0])?.as_atom()
                && let Some(ty) = match kind {
                    arinsal_term::atoms::UTF8 => Some(SegType::Utf8),
                    arinsal_term::atoms::UTF16 => Some(SegType::Utf16),
                    arinsal_term::atoms::UTF32 => Some(SegType::Utf32),
                    _ => None,
                }
            {
                let source = part[4];
                let source_live = live_with_source(live, source);
                let segment_flags = flags(p, part[3]);
                p.ensure(3 + b.value() as usize, source_live)?;
                let value = allocated(
                    p,
                    source_live,
                    |p| {
                        arinsal_bits::create_utf_segment(
                            p.read(source)
                                .map_err(|_| BitsError::BadArg { segment: 1 })?,
                            ty,
                            segment_flags,
                            &mut p.heap,
                        )
                    },
                    frame,
                )?;
                p.write(module.arg(op, 4), value)?;
                p.ip += 1;
                return Ok(());
            }
            let initial = match segments(p, module, args) {
                Ok(segments) => segments,
                Err(error) => {
                    if a.kind() == Arg::LABEL && a.value() != u64::from(u32::MAX) {
                        return branch(p, a, frame);
                    }
                    return Err(error);
                }
            };
            let need = match create_bin_size(&initial) {
                Ok(need) => need,
                Err(BitsError::BadArg { segment }) => {
                    if a.kind() == Arg::LABEL && a.value() != u64::from(u32::MAX) {
                        return branch(p, a, frame);
                    }
                    return Err(construct_fail(&initial, segment, &frame()));
                }
                Err(err) => return Err(error(err, frame)),
            };
            let bit_copy_cost = initial
                .iter()
                .map(|segment| {
                    let source_bits = match segment.value {
                        SegmentValue::Term(value) => arinsal_bits::bit_size(value).unwrap_or(0),
                        SegmentValue::String(_) => 0,
                    };
                    let segment_bits = match segment.size {
                        SegSize::All => source_bits,
                        SegSize::Units(units) => usize::try_from(units)
                            .ok()
                            .and_then(|units| units.checked_mul(usize::from(segment.unit)))
                            .unwrap_or(0),
                        SegSize::Term(term) => term
                            .as_small()
                            .and_then(|units| usize::try_from(units).ok())
                            .and_then(|units| units.checked_mul(usize::from(segment.unit)))
                            .unwrap_or(0),
                    };
                    match segment.ty {
                        SegType::Binary => segment_bits,
                        SegType::Append | SegType::PrivateAppend => source_bits,
                        _ => 0,
                    }
                })
                .sum::<usize>()
                / (8 * 1024);
            p.ensure(need.heap_words + b.value() as usize, live)?;
            let value = allocated(
                p,
                live,
                |p| {
                    let parts =
                        segments(p, module, args).map_err(|_| BitsError::BadArg { segment: 0 })?;
                    create_bin(&parts, &mut p.heap)
                },
                frame,
            )?;
            p.reductions_used = p.reductions_used.saturating_add(bit_copy_cost as u64);
            p.reductions = p
                .reductions
                .saturating_sub(bit_copy_cost.min(i32::MAX as usize) as i32);
            p.write(module.arg(op, 4), value)?;
            p.ip += 1;
            Ok(())
        }
        Opcode::BsMatch => match_commands(p, module, op, frame),
        Opcode::BsStartMatch3 | Opcode::BsStartMatch4 => {
            let (source_arg, live) = if op.opcode() == Opcode::BsStartMatch4 {
                (c, b.value() as usize)
            } else {
                (b, c.value() as usize)
            };
            // bs_start_match4 may report live=0 while its source is still in X0.
            // A moving collection must retain that source before the retry rereads it.
            let live = live_with_source(live, source_arg);
            let source = p.read(source_arg)?;
            let result = if is_match_context(source) {
                Some(source)
            } else {
                allocated(
                    p,
                    live,
                    |p| {
                        start_match(
                            p.read(source_arg)
                                .map_err(|_| BitsError::BadArg { segment: 0 })?,
                            &mut p.heap,
                        )
                    },
                    frame,
                )?
            };
            if let Some(value) = result {
                p.write(module.arg(op, 3), value)?;
                p.ip += 1;
                Ok(())
            } else {
                branch(p, a, frame)
            }
        }
        Opcode::BsGetTail => {
            let value = allocated(
                p,
                c.value() as usize,
                |p| {
                    p.read(a)
                        .map_err(|_| BitsError::BadArg { segment: 0 })?
                        .get_tail(&mut p.heap)
                },
                frame,
            )?;
            p.write(b, value)?;
            p.ip += 1;
            Ok(())
        }
        Opcode::BsGetPosition => {
            let value = allocated(
                p,
                c.value() as usize,
                |p| {
                    get_position(
                        p.read(a).map_err(|_| BitsError::BadArg { segment: 0 })?,
                        &mut p.heap,
                    )
                },
                frame,
            )?;
            p.write(b, value)?;
            p.ip += 1;
            Ok(())
        }
        Opcode::BsSetPosition => {
            if !set_position_term(p.read(a)?, p.read(b)?) {
                return Err(VmError::Exception {
                    reason: "badarg".into(),
                    frame: frame.to_frame_string(),
                });
            }
            p.ip += 1;
            Ok(())
        }
        Opcode::BsInitWritable => {
            let value = allocated(p, 0, |p| init_writable(&mut p.heap), frame)?;
            p.x[0] = value;
            p.ip += 1;
            Ok(())
        }
        Opcode::IsBitstr => {
            if p.read(b)?.classify() == TermKind::Bitstring {
                p.ip += 1;
                Ok(())
            } else {
                branch(p, a, frame)
            }
        }
        Opcode::IsBinary => {
            let term = p.read(b)?;
            // SAFETY: The source term remains live through this test.
            let is_binary =
                unsafe { term.binary_ref() }.is_some_and(|view| view.bit_len().is_multiple_of(8));
            if is_binary {
                p.ip += 1;
                Ok(())
            } else {
                branch(p, a, frame)
            }
        }
        Opcode::BsTestTail2 | Opcode::BsTestUnit => {
            let ctx = p.read(b)?;
            let n = number(p, c)?.unwrap_or(usize::MAX);
            let ok = if op.opcode() == Opcode::BsTestTail2 {
                ctx.ensure_exactly(n)
            } else {
                ctx.test_unit(n)
            };
            if ok {
                p.ip += 1;
                Ok(())
            } else {
                branch(p, a, frame)
            }
        }
        Opcode::BsSkipBits2 => {
            let Some(bits) = field_bits(p, c, module.arg(op, 3))? else {
                return branch(p, a, frame);
            };
            if p.read(b)?.skip(bits) {
                p.ip += 1;
                Ok(())
            } else {
                branch(p, a, frame)
            }
        }
        Opcode::BsGetInteger2 | Opcode::BsGetBinary2 | Opcode::BsGetFloat2 => {
            let Some(bits) = field_bits(p, module.arg(op, 3), module.arg(op, 4))? else {
                return branch(p, a, frame);
            };
            let live = c.value() as usize;
            let result = allocated(
                p,
                live,
                |p| {
                    let ctx = p.read(b).map_err(|_| BitsError::BadArg { segment: 0 })?;
                    match op.opcode() {
                        Opcode::BsGetInteger2 => {
                            ctx.get_integer(bits, flags(p, module.arg(op, 5)), &mut p.heap)
                        }
                        Opcode::BsGetBinary2 => ctx.get_binary(bits, &mut p.heap),
                        _ => ctx.get_float(bits, flags(p, module.arg(op, 5)), &mut p.heap),
                    }
                },
                frame,
            )?;
            if let Some(value) = result {
                p.write(module.arg(op, 6), value)?;
                p.ip += 1;
                Ok(())
            } else {
                branch(p, a, frame)
            }
        }
        Opcode::BsGetUtf8
        | Opcode::BsGetUtf16
        | Opcode::BsGetUtf32
        | Opcode::BsSkipUtf8
        | Opcode::BsSkipUtf16
        | Opcode::BsSkipUtf32 => {
            let ctx = p.read(b)?;
            let field_flags = flags(p, module.arg(op, 3));
            let value = match op.opcode() {
                Opcode::BsGetUtf8 => ctx.get_utf8(),
                Opcode::BsGetUtf16 => ctx.get_utf16(field_flags),
                Opcode::BsGetUtf32 => ctx.get_utf32(field_flags),
                Opcode::BsSkipUtf8 => ctx.skip_utf8().then_some(Term::NIL),
                Opcode::BsSkipUtf16 => ctx.skip_utf16(field_flags).then_some(Term::NIL),
                Opcode::BsSkipUtf32 => ctx.skip_utf32(field_flags).then_some(Term::NIL),
                _ => unreachable!(),
            };
            if let Some(value) = value {
                if matches!(
                    op.opcode(),
                    Opcode::BsGetUtf8 | Opcode::BsGetUtf16 | Opcode::BsGetUtf32
                ) {
                    p.write(module.arg(op, 4), value)?;
                }
                p.ip += 1;
                Ok(())
            } else {
                branch(p, a, frame)
            }
        }
        Opcode::BsMatchString => {
            let bits = c.value() as usize;
            let offset = module.arg(op, 3).value() as usize;
            let byte_len = bits.div_ceil(8);
            let expected = module
                .strings
                .get(offset..offset.saturating_add(byte_len))
                .ok_or_else(|| VmError::Unsupported("string table range".into()))?;
            let context = p.read(b)?;
            if context.match_string(expected, bits) {
                p.ip += 1;
                Ok(())
            } else {
                branch(p, a, frame)
            }
        }
        _ => Err(VmError::Unsupported(format!(
            "bit syntax opcode {}",
            op.opcode().name()
        ))),
    }
}

// Port of erts/emulator/beam/emu/beam_emu.c:734 (erts_prepare_bs_construct_fail_info), OTP-29.1.1.
fn construct_fail(segments: &[Segment<'_>], index: usize, frame: &str) -> VmError {
    let Some(segment) = index.checked_sub(1).and_then(|index| segments.get(index)) else {
        return VmError::Exception {
            reason: "badarg".into(),
            frame: frame.into(),
        };
    };
    let (info, value) = match segment.size {
        SegSize::Term(value) => ("size", value),
        SegSize::All | SegSize::Units(_) => {
            let SegmentValue::Term(value) = segment.value else {
                return VmError::Exception {
                    reason: "badarg".into(),
                    frame: frame.into(),
                };
            };
            ("type", value)
        }
    };
    let Ok(value) = to_owned(value) else {
        return VmError::Exception {
            reason: "badarg".into(),
            frame: frame.into(),
        };
    };
    let operation = match segment.ty {
        SegType::Integer => "integer",
        SegType::Float => "float",
        SegType::Binary | SegType::Append | SegType::PrivateAppend => "binary",
        SegType::String => "string",
        SegType::Utf8 => "utf8",
        SegType::Utf16 => "utf16",
        SegType::Utf32 => "utf32",
    };
    let cause = OwnedTerm::Tuple(vec![
        OwnedTerm::Int(index as i64),
        OwnedTerm::atom(operation),
        OwnedTerm::atom(info),
        value,
    ]);
    let info = OwnedTerm::Map(vec![
        (OwnedTerm::atom("cause"), cause),
        (
            OwnedTerm::atom("function"),
            OwnedTerm::atom("format_bs_fail"),
        ),
        (
            OwnedTerm::atom("module"),
            OwnedTerm::atom("erl_erts_errors"),
        ),
    ]);
    VmError::Trap(crate::exceptions::Trap {
        class: arinsal_bifs::Class::Error,
        reason: crate::signals::atom("badarg"),
        trace: None,
        top: Some(crate::stacktrace::TopFrame::CurrentArgsWithInfo(
            None,
            Box::new(info),
        )),
        raw_rethrow: false,
        untrappable: false,
    })
}

#[cfg(test)]
mod tests {
    use arinsal_difftest::RefErl;
    use arinsal_term::{Term, TermBuilder, VecHeap};

    use crate::Vm;

    #[test]
    fn recursive_byte_summer_uses_constant_process_heap_words() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping byte summer allocation test");
            return;
        };
        let beam = reference
            .compile_named(
                "binparse_variants",
                include_str!("../tests/fixtures/binparse_variants.erl"),
                &[],
            )
            .unwrap();
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let mut allocated = None;
        for bytes in [0, 1, 4096] {
            let mut source_heap = VecHeap::new();
            let source = TermBuilder::new(&mut source_heap)
                .binary(&vec![7; bytes])
                .unwrap();
            let result = vm
                .eval("binparse_variants", "sum_input", &[source])
                .unwrap();
            assert_eq!(result.term.as_small(), Some(7 * bytes as i64));
            assert_eq!(result.stats.gc.collections, 0);
            let words = result._process.heap.used_words();
            if let Some(previous) = allocated {
                assert_eq!(words, previous, "byte count changed process heap usage");
            }
            allocated = Some(words);
        }
    }

    #[test]
    fn utf8_tail_matches_survive_repeated_collection() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping utf8 match collection test");
            return;
        };
        let beam = reference
            .compile_named(
                "utf8_len",
                r#"
                -module(utf8_len).
                -export([repeat/2]).
                len(<<>>) -> 0;
                len(<<_/utf8, Rest/binary>>) -> 1 + len(Rest).
                repeat(0, _) -> 0;
                repeat(N, Bin) when N > 0 -> len(Bin) + repeat(N - 1, Bin).
                "#,
                &[],
            )
            .unwrap();
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let bytes = "Привіт, Elixir 123. ".repeat(8).into_bytes();
        let mut source_heap = VecHeap::new();
        let source = TermBuilder::new(&mut source_heap).binary(&bytes).unwrap();
        let times = Term::small(40).unwrap();
        let result = vm.eval("utf8_len", "repeat", &[times, source]).unwrap();
        assert_eq!(result.term.as_small(), Some(40 * 160));
        assert!(result.stats.gc.collections > 0);
    }
}
