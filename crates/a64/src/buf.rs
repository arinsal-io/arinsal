//! Label-aware AArch64 code buffer with branch veneers and a literal pool.

use std::collections::HashMap;
use std::fmt;
use std::hash::{BuildHasherDefault, Hasher};

use crate::enc::{Cond, Emitter, EncodeError, Gpr, Shift};

/// Maximum byte interval between checks for code stubs.
pub const STUB_CHECK_INTERVAL: usize = 4 << 10;
const TB_RANGE: i64 = 1 << 15;
const COND_RANGE: i64 = 1 << 20;
const BRANCH_RANGE: i64 = 1 << 27;

/// Hasher for label ids: a label is a dense `u32`, and SipHash costs more than the lookups it
/// guards (every branch and every bind looks one up).
#[derive(Default, Clone, Copy)]
pub struct LabelHasher(u64);

impl Hasher for LabelHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 = (self.0 ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    fn write_u32(&mut self, value: u32) {
        self.0 = u64::from(value).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    }
}

/// A map keyed by a dense `u32` id (a BEAM label or lambda index).
pub type IdMap<V> = HashMap<u32, V, BuildHasherDefault<LabelHasher>>;

/// A map keyed by label.
pub type LabelMap<V> = HashMap<Label, V, BuildHasherDefault<LabelHasher>>;

/// Opaque label allocated by [`CodeBuffer`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Label(u32);

/// Failure while building or finalizing a code buffer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BufferError {
    /// An instruction could not be encoded.
    Encode(EncodeError),
    /// The label was already bound.
    AlreadyBound(Label),
    /// A label does not belong to the unresolved label set.
    InvalidLabel(Label),
    /// A finalized branch could not reach its target or veneer.
    BranchOutOfRange { from: usize, to: usize },
    /// An ADR target is beyond its signed 21-bit byte displacement.
    AdrOutOfRange { from: usize, to: usize },
    /// An unresolved label remained at finish.
    UnboundLabel(Label),
}

impl fmt::Display for BufferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for BufferError {}
impl From<EncodeError> for BufferError {
    fn from(value: EncodeError) -> Self {
        Self::Encode(value)
    }
}

#[derive(Clone, Copy, Debug)]
enum BranchKind {
    B,
    Bl,
    Cond(Cond),
    Cbz(Gpr),
    Cbnz(Gpr),
    Tbz(Gpr, u8),
    Tbnz(Gpr, u8),
    Adr(Gpr),
    Literal(Gpr),
}

impl BranchKind {
    fn reach(self) -> i64 {
        match self {
            Self::Tbz(..) | Self::Tbnz(..) => TB_RANGE,
            Self::Cond(..) | Self::Cbz(..) | Self::Cbnz(..) | Self::Literal(..) => COND_RANGE,
            Self::B | Self::Bl => BRANCH_RANGE,
            Self::Adr(..) => 1 << 20,
        }
    }
    fn is_control(self) -> bool {
        !matches!(self, Self::Adr(_) | Self::Literal(_))
    }
}

#[derive(Clone, Debug)]
struct Fixup {
    site: usize,
    label: Label,
    kind: BranchKind,
    veneer: Option<usize>,
    resolved: bool,
}

#[derive(Clone, Debug)]
struct Literal {
    sites: Vec<(usize, Gpr)>,
    value: u64,
}

/// AArch64 code builder. Offsets returned by [`label_offset`](Self::label_offset) are bytes.
#[derive(Clone, Debug, Default)]
pub struct CodeBuffer {
    emitter: Emitter,
    next_label: u32,
    labels: LabelMap<usize>,
    /// Unresolved branches in emission order; a resolved one stays until the next flush as a
    /// tombstone so the indices of `waiting` hold.
    fixups: Vec<Fixup>,
    /// Indices into `fixups` of the unresolved branches to each label, in emission order.
    waiting: LabelMap<Vec<usize>>,
    literals: Vec<Literal>,
    literal_sites: HashMap<u64, Vec<usize>>,
    unreachable: bool,
    last_check: usize,
    binds: u64,
}

impl CodeBuffer {
    /// Creates an empty code buffer.
    pub fn new() -> Self {
        Self::default()
    }
    /// Returns the current byte offset.
    pub fn offset(&self) -> usize {
        self.emitter.len() * 4
    }
    /// Number of labels bound so far: a join point changes it without emitting code.
    pub fn bind_count(&self) -> u64 {
        self.binds
    }
    /// Allocates a new unbound label.
    pub fn new_label(&mut self) -> Label {
        let label = Label(self.next_label);
        self.next_label = self.next_label.checked_add(1).expect("label id exhausted");
        label
    }
    /// Returns a label's bound byte offset, if bound.
    pub fn label_offset(&self, label: Label) -> Option<usize> {
        self.labels.get(&label).copied()
    }
    /// Returns all currently bound labels and their byte offsets.
    pub fn label_offsets(&self) -> &LabelMap<usize> {
        &self.labels
    }

    /// Binds a label at the current offset and resolves waiting fixups.
    // Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp:590-610, OTP-29.1.1
    pub fn bind(&mut self, label: Label) -> Result<(), BufferError> {
        if self.labels.contains_key(&label) {
            return Err(BufferError::AlreadyBound(label));
        }
        if label.0 >= self.next_label {
            return Err(BufferError::InvalidLabel(label));
        }
        let offset = self.offset();
        self.binds += 1;
        self.labels.insert(label, offset);
        // Only the branches waiting for this label: scanning every pending branch per bind is
        // quadratic in the size of a module.
        for index in self.waiting.remove(&label).unwrap_or_default() {
            let fixup = &mut self.fixups[index];
            fixup.resolved = true;
            let (site, kind, veneer) = (fixup.site, fixup.kind, fixup.veneer);
            self.patch(site, kind, veneer.unwrap_or(offset))?;
        }
        Ok(())
    }

    fn emit_branch(&mut self, label: Label, kind: BranchKind) -> Result<(), BufferError> {
        if label.0 >= self.next_label {
            return Err(BufferError::InvalidLabel(label));
        }
        let site = self.offset();
        let mut e = Emitter::new();
        match kind {
            BranchKind::B => e.b(0)?,
            BranchKind::Bl => e.bl(0)?,
            BranchKind::Cond(c) => e.b_cond(c, 0)?,
            BranchKind::Cbz(r) => e.cbz(r, 0)?,
            BranchKind::Cbnz(r) => e.cbnz(r, 0)?,
            BranchKind::Tbz(r, b) => e.tbz(r, b, 0)?,
            BranchKind::Tbnz(r, b) => e.tbnz(r, b, 0)?,
            BranchKind::Adr(r) => e.adr(r, 0)?,
            BranchKind::Literal(r) => e.ldr_literal(r, 0)?,
        }
        self.emitter.word(e.words[0]);
        if let Some(&target) = self.labels.get(&label) {
            if kind.is_control() && !branch_fits(kind, site, target) {
                let after = self.new_label();
                self.emit_branch(after, BranchKind::B)?;
                let veneer = self.offset();
                self.patch(site, kind, veneer)?;
                self.emit_veneer(label)?;
                self.bind(after)?;
            } else {
                self.patch(site, kind, target)?;
            }
        } else {
            self.waiting
                .entry(label)
                .or_default()
                .push(self.fixups.len());
            self.fixups.push(Fixup {
                site,
                label,
                kind,
                veneer: None,
                resolved: false,
            });
        }
        Ok(())
    }

    /// Emits `b label`.
    // Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp:664-723, OTP-29.1.1
    pub fn b(&mut self, label: Label) -> Result<(), BufferError> {
        self.emit_branch(label, BranchKind::B)
    }
    /// Emits `bl label`.
    // Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp:664-723, OTP-29.1.1
    pub fn bl(&mut self, label: Label) -> Result<(), BufferError> {
        self.emit_branch(label, BranchKind::Bl)
    }
    /// Emits `b.cond label`.
    // Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp:664-723, OTP-29.1.1
    pub fn b_cond(&mut self, cond: Cond, label: Label) -> Result<(), BufferError> {
        self.emit_branch(label, BranchKind::Cond(cond))
    }
    /// Emits `cbz reg, label`.
    // Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp:664-723, OTP-29.1.1
    pub fn cbz(&mut self, reg: Gpr, label: Label) -> Result<(), BufferError> {
        self.emit_branch(label, BranchKind::Cbz(reg))
    }
    /// Emits `cbnz reg, label`.
    // Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp:664-723, OTP-29.1.1
    pub fn cbnz(&mut self, reg: Gpr, label: Label) -> Result<(), BufferError> {
        self.emit_branch(label, BranchKind::Cbnz(reg))
    }
    /// Emits `tbz reg, bit, label`.
    // Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp:664-723, OTP-29.1.1
    pub fn tbz(&mut self, reg: Gpr, bit: u8, label: Label) -> Result<(), BufferError> {
        self.emit_branch(label, BranchKind::Tbz(reg, bit))
    }
    /// Emits `tbnz reg, bit, label`.
    // Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp:664-723, OTP-29.1.1
    pub fn tbnz(&mut self, reg: Gpr, bit: u8, label: Label) -> Result<(), BufferError> {
        self.emit_branch(label, BranchKind::Tbnz(reg, bit))
    }
    /// Emits `adr reg, label`.
    // Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp:771-780, OTP-29.1.1
    pub fn adr(&mut self, reg: Gpr, label: Label) -> Result<(), BufferError> {
        self.emit_branch(label, BranchKind::Adr(reg))
    }

    /// Emits a literal load, deduplicating an identical register/value pair.
    // Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp:736-769, OTP-29.1.1
    pub fn ldr_literal(&mut self, reg: Gpr, value: u64) -> Result<(), BufferError> {
        let site = self.offset();
        let mut e = Emitter::new();
        e.ldr_literal(reg, 0)?;
        self.emitter.word(e.words[0]);
        if let Some(&offset) = self.literal_sites.get(&value).and_then(|v| {
            v.iter()
                .find(|&&p| (p as i64 - site as i64).abs() < COND_RANGE - 16)
        }) {
            self.patch(site, BranchKind::Literal(reg), offset)?;
        } else if let Some(pending) = self.literals.iter_mut().find(|l| l.value == value) {
            pending.sites.push((site, reg));
        } else {
            self.literals.push(Literal {
                sites: vec![(site, reg)],
                value,
            });
        }
        Ok(())
    }

    /// Emits an instruction through the underlying encoder.
    pub fn emit<F>(&mut self, encode: F) -> Result<(), BufferError>
    where
        F: FnOnce(&mut Emitter) -> Result<(), EncodeError>,
    {
        let old_len = self.emitter.len();
        encode(&mut self.emitter)?;
        if self.emitter.len() > old_len {
            self.unreachable = false;
        }
        Ok(())
    }

    /// Emits a raw word.
    pub fn word(&mut self, word: u32) {
        self.emitter.word(word);
        self.unreachable = false;
    }

    /// Emits all stubs approaching their architecture reach limits.
    // Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp:796-814, OTP-29.1.1
    pub fn check_pending_stubs(&mut self) -> Result<(), BufferError> {
        if self.offset().saturating_sub(self.last_check) < STUB_CHECK_INTERVAL {
            return Ok(());
        }
        self.flush_pending_stubs(STUB_CHECK_INTERVAL * 2)?;
        self.last_check = self.offset();
        Ok(())
    }

    /// Flushes veneers and constants whose remaining reach is within `range` bytes.
    // Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp:816-900, OTP-29.1.1
    pub fn flush_pending_stubs(&mut self, range: usize) -> Result<(), BufferError> {
        let now = self.offset();
        // Drop the resolved branches and renumber the waiting lists.
        if self.fixups.iter().any(|fixup| fixup.resolved) {
            self.fixups.retain(|fixup| !fixup.resolved);
            self.waiting.clear();
            for (index, fixup) in self.fixups.iter().enumerate() {
                self.waiting.entry(fixup.label).or_default().push(index);
            }
        }
        let due_fixups: Vec<usize> = self
            .fixups
            .iter()
            .enumerate()
            .filter_map(|(i, f)| {
                let deadline = f
                    .site
                    .saturating_add(f.kind.reach() as usize)
                    .saturating_sub(range);
                (f.kind.is_control() && f.veneer.is_none() && deadline <= now).then_some(i)
            })
            .collect();
        let due_literals = self.literals.iter().any(|l| {
            l.sites.iter().any(|(site, _)| {
                site.saturating_add(COND_RANGE as usize)
                    .saturating_sub(range)
                    <= now
            })
        });
        if due_fixups.is_empty() && !due_literals {
            return Ok(());
        }

        let jump_site = self.offset();
        let after = self.new_label();
        if !self.unreachable {
            self.emit_branch(after, BranchKind::B)?;
        }
        for idx in due_fixups {
            let site = self.fixups[idx].site;
            let label = self.fixups[idx].label;
            let kind = self.fixups[idx].kind;
            let veneer = self.offset();
            self.fixups[idx].veneer = Some(veneer);
            self.patch(site, kind, veneer)?;
            self.emit_veneer(label)?;
        }
        let due: Vec<Literal> = self.literals.drain_filter_due(now, range);
        for literal in due {
            self.align8();
            let offset = self.offset();
            for (site, reg) in literal.sites {
                self.patch(site, BranchKind::Literal(reg), offset)?;
            }
            self.emitter.embed_uint64(literal.value);
            self.literal_sites
                .entry(literal.value)
                .or_default()
                .push(offset);
        }
        self.bind(after)?;
        let _ = jump_site;
        self.unreachable = false;
        Ok(())
    }

    fn emit_veneer(&mut self, target: Label) -> Result<(), BufferError> {
        let site = self.offset();
        if let Some(&to) = self.labels.get(&target) {
            if (to as i64 - site as i64).abs() < BRANCH_RANGE {
                return self.emit_branch(target, BranchKind::B);
            }
            self.emit_long_veneer(to as i64 - site as i64)?;
        } else {
            self.emit_branch(target, BranchKind::B)?;
        }
        Ok(())
    }

    fn emit_long_veneer(&mut self, delta: i64) -> Result<(), BufferError> {
        let mut e = Emitter::new();
        // x15 and x16 hold X4 and X5 across native BEAM code.
        e.ldr_literal(Gpr::x(17), 4)?; // +16: displacement payload
        e.adr(Gpr::x(14), 4)?; // address of the origin used by the payload
        e.add_reg(Gpr::x(17), Gpr::x(17), Gpr::x(14), Shift::Lsl, 0)?;
        e.br(Gpr::x(17))?;
        self.emitter.words.extend(e.words);
        self.emitter.embed_uint64((delta - 4) as u64);
        Ok(())
    }

    fn align8(&mut self) {
        if !self.offset().is_multiple_of(8) {
            self.emitter.word(0);
        }
    }

    fn patch(&mut self, site: usize, kind: BranchKind, target: usize) -> Result<(), BufferError> {
        let delta = target as i64 - site as i64;
        let word_index = site / 4;
        let word = self.emitter.words[word_index];
        if delta % 4 != 0 && !matches!(kind, BranchKind::Adr(_)) {
            return Err(BufferError::BranchOutOfRange {
                from: site,
                to: target,
            });
        }
        let encoded = match kind {
            BranchKind::B | BranchKind::Bl => signed_fit(delta / 4, 26)
                .then_some((word & !0x03ff_ffff) | ((delta / 4) as u32 & 0x03ff_ffff)),
            BranchKind::Cond(_)
            | BranchKind::Cbz(_)
            | BranchKind::Cbnz(_)
            | BranchKind::Literal(_) => signed_fit(delta / 4, 19)
                .then_some((word & !(0x7ffff << 5)) | (((delta / 4) as u32 & 0x7ffff) << 5)),
            BranchKind::Tbz(..) | BranchKind::Tbnz(..) => signed_fit(delta / 4, 14)
                .then_some((word & !(0x3fff << 5)) | (((delta / 4) as u32 & 0x3fff) << 5)),
            BranchKind::Adr(_) => {
                let imm = delta as u32 & 0x1f_ffff;
                (-(1 << 20)..(1 << 20)).contains(&delta).then_some({
                    (word & !((3 << 29) | (0x7ffff << 5)))
                        | ((imm & 3) << 29)
                        | (((imm >> 2) & 0x7ffff) << 5)
                })
            }
        };
        if let Some(encoded) = encoded {
            self.emitter.words[word_index] = encoded;
            Ok(())
        } else if matches!(kind, BranchKind::Adr(_)) {
            Err(BufferError::AdrOutOfRange {
                from: site,
                to: target,
            })
        } else {
            Err(BufferError::BranchOutOfRange {
                from: site,
                to: target,
            })
        }
    }

    /// Finalizes the buffer and returns encoded words. Unresolved labels are errors.
    // Port of erts/emulator/beam/jit/arm/beam_asm_module.cpp:829-900, OTP-29.1.1
    pub fn finish(self) -> Result<Vec<u32>, BufferError> {
        self.finish_with_labels().map(|(words, _)| words)
    }

    /// Finalizes the buffer and returns both words and the label offset map.
    pub fn finish_with_labels(mut self) -> Result<(Vec<u32>, LabelMap<usize>), BufferError> {
        self.flush_pending_stubs(usize::MAX / 2)?;
        if let Some(fixup) = self.fixups.iter().find(|fixup| !fixup.resolved) {
            return Err(BufferError::UnboundLabel(fixup.label));
        }
        Ok((self.emitter.words, self.labels))
    }
}

fn signed_fit(value: i64, bits: u8) -> bool {
    value >= -(1_i64 << (bits - 1)) && value < (1_i64 << (bits - 1))
}

fn branch_fits(kind: BranchKind, site: usize, target: usize) -> bool {
    let delta = target as i64 - site as i64;
    if matches!(kind, BranchKind::Adr(_)) {
        return (-(1 << 20)..(1 << 20)).contains(&delta);
    }
    delta % 4 == 0
        && signed_fit(
            delta / 4,
            match kind {
                BranchKind::B | BranchKind::Bl => 26,
                BranchKind::Cond(_) | BranchKind::Cbz(_) | BranchKind::Cbnz(_) => 19,
                BranchKind::Tbz(..) | BranchKind::Tbnz(..) => 14,
                BranchKind::Adr(_) | BranchKind::Literal(_) => 19,
            },
        )
}

trait DrainDue {
    fn drain_filter_due(&mut self, now: usize, range: usize) -> Vec<Literal>;
}
impl DrainDue for Vec<Literal> {
    fn drain_filter_due(&mut self, now: usize, range: usize) -> Vec<Literal> {
        let mut due = Vec::new();
        let mut keep = Vec::new();
        for item in self.drain(..) {
            if item.sites.iter().any(|(site, _)| {
                site.saturating_add(COND_RANGE as usize)
                    .saturating_sub(range)
                    <= now
            }) {
                due.push(item);
            } else {
                keep.push(item);
            }
        }
        *self = keep;
        due
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_veneer_preserves_beam_x4_and_x5_registers() {
        let mut buffer = CodeBuffer::new();
        buffer.emit_long_veneer(128 * 1024 * 1024).unwrap();

        let words = &buffer.emitter.words;
        assert_eq!(words.len(), 6);
        let written = [words[0] & 0x1f, words[1] & 0x1f, words[2] & 0x1f];
        assert_eq!(written, [17, 14, 17]);
        assert_eq!(words[2] >> 5 & 0x1f, 17);
        assert_eq!(words[2] >> 16 & 0x1f, 14);
        assert_eq!(words[3] >> 5 & 0x1f, 17);
        assert!(!written.contains(&15));
        assert!(!written.contains(&16));
    }
}
