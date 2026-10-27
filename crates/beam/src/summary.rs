//! What the loader needs to know about a module's code without decoding its instructions: its
//! functions, the registers it uses and its `-on_load` function. erts finds the first while it
//! emits (the `func_info`/entry label pairs of `int_func_start`), the others it does not need;
//! this runtime sizes its register files per module and decides on `-on_load` before it emits,
//! so one cheap pass over the operand bytes provides them.

use crate::{BeamError, bad};
use arinsal_spec::Opcode;

/// One function of the Code chunk, in code order.
#[derive(Clone, Debug)]
pub struct FunctionSummary {
    /// One-based atom index of the function name (`func_info`).
    pub function_atom: u32,
    /// Function arity.
    pub arity: u32,
    /// The entry label: the label that follows the `func_info`.
    pub entry_label: u32,
    /// Whether a `nif_start` follows the entry label (a stub a `load_nif` can replace).
    pub nif_stub: bool,
}

/// The facts of one pass over the code bytes.
#[derive(Clone, Debug, Default)]
pub struct CodeSummary {
    /// The functions, in code order.
    pub functions: Vec<FunctionSummary>,
    /// X registers the code needs, counting call arities (at least 2, at most 1024).
    pub x_registers: usize,
    /// Float registers the code needs (at least 1, at most 1024).
    pub float_registers: usize,
    /// The index in `functions` of the `-on_load` function.
    pub on_load: Option<usize>,
    /// The number of generic instructions.
    pub instructions: usize,
}

struct Skim<'a> {
    data: &'a [u8],
    pos: usize,
    x: usize,
    fr: usize,
}

/// A tagged number: its tag and, when it fits a word, its value.
struct Raw {
    tag: u8,
    value: u64,
}

impl Skim<'_> {
    fn u8(&mut self) -> Result<u8, BeamError> {
        let byte = *self
            .data
            .get(self.pos)
            .ok_or_else(|| bad("Code", self.pos, "truncated data"))?;
        self.pos += 1;
        Ok(byte)
    }

    /// `beamreader_read_tagged` without the integer conversions: a value that does not fit a
    /// word is skipped and reads as `u64::MAX`.
    #[inline(always)]
    fn tagged(&mut self, depth: usize) -> Result<Raw, BeamError> {
        // The one-byte form is nearly every operand.
        if let Some(&first) = self.data.get(self.pos)
            && first & 8 == 0
        {
            self.pos += 1;
            return Ok(Raw {
                tag: first & 7,
                value: u64::from(first >> 4),
            });
        }
        self.tagged_wide(depth)
    }

    #[inline(never)]
    fn tagged_wide(&mut self, depth: usize) -> Result<Raw, BeamError> {
        if depth > 32 {
            return Err(bad("Code", self.pos, "compact length nesting too deep"));
        }
        let first = self.u8()?;
        let tag = first & 7;
        if first & 8 == 0 {
            return Ok(Raw {
                tag,
                value: u64::from(first >> 4),
            });
        }
        if first & 16 == 0 {
            let extra = self.u8()?;
            return Ok(Raw {
                tag,
                value: (u64::from(first >> 5) << 8) | u64::from(extra),
            });
        }
        let code = first >> 5;
        let count = if code < 7 {
            usize::from(code) + 2
        } else {
            let prefix = self.tagged(depth + 1)?;
            if prefix.tag != 0 || prefix.value >= (i32::MAX as u64) - 9 {
                return Err(bad("Code", self.pos, "bad compact length"));
            }
            prefix.value as usize + 9
        };
        let end = self
            .pos
            .checked_add(count)
            .filter(|end| *end <= self.data.len())
            .ok_or_else(|| bad("Code", self.pos, "truncated data"))?;
        let bytes = &self.data[self.pos..end];
        self.pos = end;
        let value = if count <= 8 {
            let word = bytes
                .iter()
                .fold(0u64, |word, byte| (word << 8) | u64::from(*byte));
            if tag == 1 || (word as i64) >= 0 {
                word
            } else {
                u64::MAX
            }
        } else {
            u64::MAX
        };
        Ok(Raw { tag, value })
    }

    fn register(&mut self, raw: &Raw) {
        if raw.value < 1024 {
            self.x = self.x.max(raw.value as usize + 1);
        }
    }

    /// One operand.
    fn operand(&mut self, depth: usize) -> Result<Raw, BeamError> {
        if depth > 32 {
            return Err(bad("Code", self.pos, "operand nesting too deep"));
        }
        let raw = self.tagged(depth)?;
        match raw.tag {
            3 => self.register(&raw),
            7 => match raw.value {
                1 => {
                    let count = self.tagged(depth)?;
                    if count.value as usize > self.data.len() - self.pos {
                        return Err(bad("Code", self.pos, "list count exceeds code"));
                    }
                    for _ in 0..count.value {
                        self.operand(depth + 1)?;
                    }
                }
                2 => {
                    let index = self.tagged(depth)?;
                    if index.value < 1024 {
                        self.fr = self.fr.max(index.value as usize + 1);
                    }
                }
                3 => {
                    let count = self.tagged(depth)?;
                    if count.value > 3 {
                        return Err(bad("Code", self.pos, "bad allocation list"));
                    }
                    for _ in 0..count.value * 2 {
                        self.tagged(depth)?;
                    }
                }
                4 => {
                    self.tagged(depth)?;
                }
                5 => {
                    self.operand(depth + 1)?;
                    self.tagged(depth)?;
                }
                0 => return Err(bad("Code", self.pos, "obsolete inline float operand")),
                other => {
                    return Err(bad(
                        "Code",
                        self.pos,
                        format!("unknown extended tag {other}"),
                    ));
                }
            },
            _ => {}
        }
        Ok(raw)
    }
}

/// One pass over the instruction bytes of a Code chunk.
pub(crate) fn summarize(
    data: &[u8],
    max_opcode: u32,
    function_count: u32,
) -> Result<CodeSummary, BeamError> {
    let mut skim = Skim {
        data,
        pos: 0,
        x: 2,
        fr: 1,
    };
    let mut summary = CodeSummary::default();
    let mut last = None;
    let mut seen_end = false;
    while skim.pos < data.len() {
        let offset = skim.pos;
        let byte = skim.u8()?;
        let op = Opcode::from_u8(byte)
            .ok_or_else(|| bad("Code", offset, format!("unknown opcode {byte}")))?;
        if byte as u32 > max_opcode {
            return Err(bad(
                "Code",
                offset,
                format!("opcode {} exceeds max opcode", op.name()),
            ));
        }
        if op.is_deprecated() {
            return Err(bad(
                "Code",
                offset,
                format!("deprecated opcode {}", op.name()),
            ));
        }
        let mut args = [0u64; 4];
        for index in 0..usize::from(op.arity()) {
            let raw = skim.operand(0)?;
            if let Some(slot) = args.get_mut(index) {
                *slot = raw.value;
            }
        }
        // Calls and function entries need their arity of X registers.
        let arity = match op {
            Opcode::FuncInfo => Some(args[2]),
            Opcode::Call
            | Opcode::CallLast
            | Opcode::CallOnly
            | Opcode::CallExt
            | Opcode::CallExtLast
            | Opcode::CallExtOnly => Some(args[0]),
            Opcode::CallFun2 => Some(args[1]),
            _ => None,
        };
        if let Some(count) = arity
            && count < 1024
        {
            skim.x = skim.x.max(count as usize + 1);
        }
        match op {
            Opcode::FuncInfo => {
                // The atom operands of a func_info are checked by the code reader; a bad index
                // makes the module fail to load there.
                summary.functions.push(FunctionSummary {
                    function_atom: u32::try_from(args[1])
                        .map_err(|_| bad("Code", offset, "atom index overflow"))?,
                    arity: u32::try_from(args[2])
                        .map_err(|_| bad("Code", offset, "arity overflow"))?,
                    entry_label: 0,
                    nif_stub: false,
                });
                last = Some(summary.functions.len() - 1);
            }
            Opcode::Label => {
                // The label after a func_info is the entry label.
                if let Some(index) = last.take() {
                    summary.functions[index].entry_label = u32::try_from(args[0])
                        .map_err(|_| bad("Code", offset, "label overflow"))?;
                }
            }
            Opcode::NifStart => {
                if let Some(function) = summary.functions.last_mut() {
                    function.nif_stub = true;
                }
            }
            Opcode::OnLoad if summary.on_load.is_none() => {
                summary.on_load = summary.functions.len().checked_sub(1);
            }
            _ => {}
        }
        summary.instructions += 1;
        seen_end = op == Opcode::IntCodeEnd;
    }
    if !seen_end {
        return Err(bad("Code", skim.pos, "missing final int_code_end"));
    }
    if summary.functions.len() != function_count as usize {
        return Err(bad("Code", skim.pos, "function count mismatch"));
    }
    summary.x_registers = skim.x.min(1024);
    summary.float_registers = skim.fr.min(1024);
    Ok(summary)
}
