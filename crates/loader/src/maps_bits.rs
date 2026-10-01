//! Opcode classification for map and bit syntax interpreter handlers.

use arinsal_spec::Opcode;
use arinsal_term::{Term, global_atoms};

use crate::{Arg, GenericOp, Instr};

/// A bit match command recognized at module load time.
#[derive(Clone, Copy, Debug)]
pub enum BitCommandKind {
    /// Check a minimum remaining length and alignment.
    EnsureAtLeast,
    /// Check the exact remaining length.
    EnsureExactly,
    /// Advance a fixed number of bits.
    Skip,
    /// Read an integer field.
    Integer,
    /// Read a binary field.
    Binary,
    /// Return the unmatched tail.
    GetTail,
    /// Match a fixed integer value.
    Eq,
}

/// A predecoded command with operands retained in the module's list table.
#[derive(Clone, Copy, Debug)]
pub struct BitCommand {
    /// Operation to execute.
    pub kind: BitCommandKind,
    /// First operand in the source list.
    pub offset: usize,
    /// Number of source operands.
    pub width: usize,
}

/// Decode every supported command list once, independent of its caller.
pub(crate) fn decode_commands(lists: &[Box<[Arg]>]) -> Vec<Option<Box<[BitCommand]>>> {
    lists
        .iter()
        .map(|args| {
            let mut decoded = Vec::new();
            let mut offset = 0;
            while offset < args.len() {
                let (kind, width) = if command_name(args[offset], "ensure_at_least") {
                    (BitCommandKind::EnsureAtLeast, 3)
                } else if command_name(args[offset], "ensure_exactly") {
                    (BitCommandKind::EnsureExactly, 2)
                } else if command_name(args[offset], "skip") {
                    (BitCommandKind::Skip, 2)
                } else if command_name(args[offset], "integer") {
                    (BitCommandKind::Integer, 6)
                } else if command_name(args[offset], "binary") {
                    (BitCommandKind::Binary, 6)
                } else if command_name(args[offset], "get_tail") {
                    (BitCommandKind::GetTail, 4)
                } else if command_name(args[offset], "=:=") {
                    (BitCommandKind::Eq, 4)
                } else {
                    return None;
                };
                if offset + width > args.len() {
                    return None;
                }
                decoded.push(BitCommand {
                    kind,
                    offset,
                    width,
                });
                offset += width;
            }
            Some(decoded.into_boxed_slice())
        })
        .collect()
}

/// Instructions whose decoded operands are retained for the VM feature handlers.
#[inline]
pub(crate) fn handles(op: Opcode) -> bool {
    matches!(
        op.name(),
        "put_map_assoc"
            | "put_map_exact"
            | "get_map_elements"
            | "has_map_fields"
            | "bs_create_bin"
            | "bs_match"
            | "bs_start_match3"
            | "bs_start_match4"
            | "bs_get_tail"
            | "bs_get_position"
            | "bs_set_position"
            | "bs_test_tail2"
            | "bs_skip_bits2"
            | "bs_get_integer2"
            | "bs_get_binary2"
            | "bs_get_float2"
            | "bs_get_utf8"
            | "bs_get_utf16"
            | "bs_get_utf32"
            | "bs_skip_utf8"
            | "bs_skip_utf16"
            | "bs_skip_utf32"
            | "bs_init_writable"
            | "bs_test_unit"
            | "bs_match_string"
            | "is_bitstr"
            | "is_binary"
    )
}

fn arg_number(arg: Arg, expected: u64) -> bool {
    (arg.kind() == Arg::U && arg.value() == expected)
        || (arg.kind() == Arg::INT && arg.signed() >= 0 && arg.signed() as u64 == expected)
}

fn command_name(arg: Arg, expected: &str) -> bool {
    arg.kind() == Arg::TERM
        && arg.term().as_atom().and_then(|a| global_atoms().text(a)) == Some(expected)
}

fn x_index(arg: Arg) -> Option<u16> {
    (arg.kind() == Arg::X && arg.value() < 1024).then_some(arg.value() as u16)
}

fn small_unsigned(arg: Arg) -> Option<u32> {
    let value = match arg.kind() {
        Arg::U => arg.value(),
        Arg::INT if arg.signed() >= 0 => arg.signed() as u64,
        _ => return None,
    };
    u32::try_from(value).ok()
}

/// Predecode the common command shapes while retaining all other forms.
pub(crate) fn specialize_bit_commands(
    code: &mut [Instr],
    generic: &[GenericOp],
    lists: &[Box<[Arg]>],
    tails: &[Box<[Arg]>],
) {
    for instr in code {
        let Instr::MapsBits(index) = *instr else {
            continue;
        };
        let Some(op) = generic.get(index as usize).copied() else {
            continue;
        };
        let replacement = match op.opcode() {
            Opcode::BsStartMatch3 | Opcode::BsStartMatch4 => {
                let source_arg = if op.opcode() == Opcode::BsStartMatch3 {
                    op.args[1]
                } else {
                    op.args[2]
                };
                let Some(source) = x_index(source_arg) else {
                    continue;
                };
                let Some(tail) = tails.get((op.meta & 0x00ff_ffff) as usize) else {
                    continue;
                };
                let Some(dst) = tail.first().and_then(|arg| x_index(*arg)) else {
                    continue;
                };
                Instr::BsStartReuse {
                    source,
                    dst,
                    fallback: index,
                }
            }
            Opcode::BsGetPosition => {
                let (Some(context), Some(dst)) = (x_index(op.args[0]), x_index(op.args[1])) else {
                    continue;
                };
                Instr::BsPositionSmall {
                    context,
                    dst,
                    fallback: index,
                }
            }
            Opcode::BsCreateBin => {
                let Some(tail) = tails.get((op.meta & 0x00ff_ffff) as usize) else {
                    continue;
                };
                let [unit, dst, list] = tail.as_ref() else {
                    continue;
                };
                if !arg_number(*unit, 8) || list.kind() != Arg::LIST {
                    continue;
                }
                let Some(segments) = lists.get(list.value() as usize) else {
                    continue;
                };
                let [
                    append,
                    append_index,
                    append_unit,
                    append_flags,
                    source,
                    all,
                    integer,
                    integer_index,
                    integer_unit,
                    integer_flags,
                    value,
                    size,
                ] = segments.as_ref()
                else {
                    continue;
                };
                if !command_name(*append, "private_append")
                    || !arg_number(*append_index, 1)
                    || !arg_number(*append_unit, 8)
                    || append_flags.kind() != Arg::TERM
                    || append_flags.term() != Term::NIL
                    || !command_name(*all, "all")
                    || !command_name(*integer, "integer")
                    || !arg_number(*integer_index, 2)
                    || !arg_number(*integer_unit, 1)
                    || integer_flags.kind() != Arg::TERM
                    || integer_flags.term() != Term::NIL
                    || !arg_number(*size, 8)
                {
                    continue;
                }
                let (Some(source), Some(value), Some(dst)) =
                    (x_index(*source), x_index(*value), x_index(*dst))
                else {
                    continue;
                };
                Instr::BsAppendByte {
                    source,
                    value,
                    dst,
                    fallback: index,
                }
            }
            Opcode::BsMatch => {
                let Some(context) = x_index(op.args[1]) else {
                    continue;
                };
                if op.args[0].kind() != Arg::LABEL {
                    continue;
                }
                let fail = op.args[0].value() as u32;
                let Some(commands) = lists.get(op.args[2].value() as usize) else {
                    continue;
                };
                match commands.as_ref() {
                    [name, bits] if command_name(*name, "ensure_exactly") => {
                        let Some(bits) = small_unsigned(*bits) else {
                            continue;
                        };
                        Instr::BsEnsure {
                            context,
                            bits,
                            unit: 1,
                            fail,
                            exact: true,
                        }
                    }
                    [name, bits, unit] if command_name(*name, "ensure_at_least") => {
                        let (Some(bits), Some(unit)) =
                            (small_unsigned(*bits), small_unsigned(*unit))
                        else {
                            continue;
                        };
                        let Ok(unit) = u16::try_from(unit) else {
                            continue;
                        };
                        Instr::BsEnsure {
                            context,
                            bits,
                            unit,
                            fail,
                            exact: false,
                        }
                    }
                    [
                        ensure,
                        bits,
                        unit,
                        integer,
                        live,
                        flags,
                        size,
                        int_unit,
                        dst,
                    ] if command_name(*ensure, "ensure_at_least")
                        && arg_number(*bits, 32)
                        && arg_number(*unit, 1)
                        && command_name(*integer, "integer")
                        && small_unsigned(*live).is_some()
                        && flags.kind() == Arg::TERM
                        && flags.term() == Term::NIL
                        && arg_number(*size, 32)
                        && arg_number(*int_unit, 1)
                        && x_index(*dst).is_some() =>
                    {
                        Instr::BsReadU32 {
                            context,
                            dst: x_index(*dst).unwrap(),
                            fail,
                        }
                    }
                    // bits_cursor: predecode the common unsigned field command for any
                    // caller; the original command list handles all other flag forms.
                    [
                        ensure,
                        minimum,
                        tail_unit,
                        integer,
                        live,
                        flags,
                        size,
                        int_unit,
                        dst,
                    ] if command_name(*ensure, "ensure_at_least")
                        && command_name(*integer, "integer")
                        && small_unsigned(*live).is_some()
                        && flags.kind() == Arg::TERM
                        && flags.term() == Term::NIL =>
                    {
                        let (Some(minimum), Some(tail_unit), Some(size), Some(int_unit), Some(dst)) = (
                            small_unsigned(*minimum),
                            small_unsigned(*tail_unit).and_then(|n| u16::try_from(n).ok()),
                            small_unsigned(*size),
                            small_unsigned(*int_unit),
                            x_index(*dst),
                        ) else {
                            continue;
                        };
                        let Some(bits) = size
                            .checked_mul(int_unit)
                            .and_then(|n| u8::try_from(n).ok())
                        else {
                            continue;
                        };
                        if bits > 32 || tail_unit == 0 {
                            continue;
                        }
                        Instr::BsReadUint {
                            context,
                            dst,
                            fail,
                            ensure_bits: minimum,
                            unit: tail_unit,
                            bits,
                        }
                    }
                    [binary, live, _, size, unit, dst]
                        if command_name(*binary, "binary") && arg_number(*unit, 8) =>
                    {
                        let (Some(live), Some(size), Some(dst)) = (
                            small_unsigned(*live).and_then(|n| u16::try_from(n).ok()),
                            x_index(*size),
                            x_index(*dst),
                        ) else {
                            continue;
                        };
                        Instr::BsBinaryReg {
                            context,
                            size,
                            dst,
                            live,
                            fail,
                        }
                    }
                    [tail, live, unit, dst] if command_name(*tail, "get_tail") => {
                        let (Some(live), Some(unit), Some(dst)) = (
                            small_unsigned(*live).and_then(|n| u16::try_from(n).ok()),
                            small_unsigned(*unit).and_then(|n| u16::try_from(n).ok()),
                            x_index(*dst),
                        ) else {
                            continue;
                        };
                        Instr::BsMatchTail {
                            context,
                            dst,
                            live,
                            unit,
                            fail,
                        }
                    }
                    _ => continue,
                }
            }
            Opcode::BsGetBinary2 => {
                if op.args[0].kind() != Arg::LABEL {
                    continue;
                }
                let Some(context) = x_index(op.args[1]) else {
                    continue;
                };
                let Some(live) = small_unsigned(op.args[2]).and_then(|n| u16::try_from(n).ok())
                else {
                    continue;
                };
                let Some(tail) = tails.get((op.meta & 0x00ff_ffff) as usize) else {
                    continue;
                };
                let [size, unit, _, dst] = tail.as_ref() else {
                    continue;
                };
                if !arg_number(*unit, 8) {
                    continue;
                }
                let (Some(size), Some(dst)) = (x_index(*size), x_index(*dst)) else {
                    continue;
                };
                Instr::BsBinaryReg {
                    context,
                    size,
                    dst,
                    live,
                    fail: op.args[0].value() as u32,
                }
            }
            Opcode::BsGetTail => {
                let (Some(context), Some(dst)) = (x_index(op.args[0]), x_index(op.args[1])) else {
                    continue;
                };
                let Some(live) = small_unsigned(op.args[2]).and_then(|n| u16::try_from(n).ok())
                else {
                    continue;
                };
                Instr::BsTail { context, dst, live }
            }
            _ => continue,
        };
        *instr = replacement;
    }
}
