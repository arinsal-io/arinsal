//! A skim over the operand bytes of a Code chunk for the two facts a caller needs before (or
//! without) loading the code: which functions begin with `nif_start`, and whether the module has
//! an `-on_load` function. The load itself learns both while it emits (`stp->load_hdr->are_nifs`
//! and `beamasm_get_on_load` of erts); this skim serves the caller that must know first: the
//! emitter of a module that imports `erlang:load_nif/2` (the NIF padding of a function is
//! decided at its start here) and the autoload check for a module not yet loaded.

use crate::{BeamError, bad};
use arinsal_spec::Opcode;

struct Skim<'a> {
    data: &'a [u8],
    pos: usize,
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

    /// One operand.
    fn operand(&mut self, depth: usize) -> Result<Raw, BeamError> {
        if depth > 32 {
            return Err(bad("Code", self.pos, "operand nesting too deep"));
        }
        let raw = self.tagged(depth)?;
        if raw.tag == 7 {
            match raw.value {
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
                    self.tagged(depth)?;
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
            }
        }
        Ok(raw)
    }
}

/// What [`scan`] found.
#[derive(Clone, Debug, Default)]
pub struct CodeScan {
    /// For each function in code order, whether a `nif_start` follows its entry label (a stub a
    /// `load_nif` can replace).
    pub nif_stubs: Vec<bool>,
    /// Whether the module has an `-on_load` function.
    pub on_load: bool,
}

/// One pass over the instruction bytes of a Code chunk.
pub fn scan(data: &[u8], max_opcode: u32) -> Result<CodeScan, BeamError> {
    let mut skim = Skim { data, pos: 0 };
    let mut found = CodeScan::default();
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
        for _ in 0..op.arity() {
            skim.operand(0)?;
        }
        match op {
            Opcode::FuncInfo => found.nif_stubs.push(false),
            Opcode::NifStart => {
                if let Some(stub) = found.nif_stubs.last_mut() {
                    *stub = true;
                }
            }
            Opcode::OnLoad => found.on_load = true,
            _ => {}
        }
        seen_end = op == Opcode::IntCodeEnd;
    }
    if !seen_end {
        return Err(bad("Code", skim.pos, "missing final int_code_end"));
    }
    Ok(found)
}
