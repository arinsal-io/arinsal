//! Code/data sections, labels, x86 relative fixups, and address relocations.
//!
//! Port of asmjit's `CodeHolder`, `Assembler::align`, and `EmitJmpCall` paths used by
//! `erts/emulator/beam/jit/x86/beam_asm_module.cpp`, OTP-29.1.1.

use std::fmt;

use crate::enc::{Emitter, EncodeError, RipFixup};

/// The active section in a [`CodeBuffer`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Section {
    /// Executable bytes emitted by [`CodeBuffer::emit`].
    #[default]
    Code,
    /// Read-only data embedded by [`CodeBuffer::embed`].
    Data,
}

/// Opaque index identifying a label allocated by a code buffer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Label(u32);

/// A section-relative label position.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LabelLocation {
    /// Section containing the label.
    pub section: Section,
    /// Byte offset within that section.
    pub offset: usize,
}

/// A base-dependent relocation retained for the linker/final allocator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Relocation {
    /// Section containing the relocation payload.
    pub section: Section,
    /// Offset of the payload within its section.
    pub offset: usize,
    /// Relocation payload interpretation.
    pub kind: RelocationKind,
}

/// Final code/data bytes and metadata returned after local fixups are resolved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalizedCode {
    /// Executable section bytes.
    pub code: Vec<u8>,
    /// Data section bytes.
    pub data: Vec<u8>,
    /// Byte offset at which the data section begins in a contiguous image.
    pub data_offset: usize,
    /// Byte offset of the `.addrtab` section, after the data: one 8-byte slot reserved per
    /// distinct external `call`/`jmp` target, used only by the calls that cannot reach their
    /// target with a rel32.
    pub address_table_offset: usize,
    /// The distinct external `call`/`jmp` targets (`CodeHolder::_address_table_entries`).
    pub address_table: Vec<u64>,
    /// The slots [`Self::relocate`] assigned, in order (`AddressTableEntry::_slot`).
    pub address_table_slots: Vec<u64>,
    /// Base-dependent relocation records.
    pub relocations: Vec<Relocation>,
    /// Label locations in allocation order.
    pub labels: Vec<Option<LabelLocation>>,
}

impl FinalizedCode {
    /// `CodeHolder::code_size()`: the size of the flattened image, every section included.
    // Port of erts/emulator/asmjit/core/codeholder.cpp (CodeHolder::code_size), OTP-29.1.1.
    pub fn code_size(&self) -> usize {
        self.address_table_offset + self.address_table.len() * 8
    }

    /// `CodeHolder::label_offset_from_base(label)`: the offset of a bound label from the start
    /// of the flattened image; `None` for an unbound or unknown label.
    // Port of erts/emulator/asmjit/core/codeholder.h (CodeHolder::label_offset_from_base),
    // OTP-29.1.1.
    pub fn label_offset_from_base(&self, label: Label) -> Option<usize> {
        let location = self.labels.get(label.0 as usize).copied().flatten()?;
        Some(match location.section {
            Section::Code => location.offset,
            Section::Data => self.data_offset + location.offset,
        })
    }

    /// Combines the sections using the finalized aligned data offset.
    pub fn image(&self) -> Result<Vec<u8>, BufferError> {
        let end = self
            .address_table_offset
            .checked_add(self.address_table.len() * 8)
            .ok_or(BufferError::LayoutOverflow)?;
        let mut image = vec![0; end];
        image[..self.code.len()].copy_from_slice(&self.code);
        image[self.data_offset..self.data_offset + self.data.len()].copy_from_slice(&self.data);
        for (slot, entry) in self.address_table_slots.iter().enumerate() {
            let at = self.address_table_offset + slot * 8;
            image[at..at + 8].copy_from_slice(&entry.to_le_bytes());
        }
        Ok(image)
    }

    /// Applies recorded addresses after the combined image has been assigned `base_address`.
    // Port of asmjit `CodeHolder::relocate_to_base`, `core/codeholder.cpp:1144`, OTP-29.1.1.
    pub fn relocate(&mut self, base_address: u64) -> Result<(), BufferError> {
        let relocations = std::mem::take(&mut self.relocations);
        let result = self.apply_relocations(&relocations, base_address);
        self.relocations = relocations;
        result
    }

    fn apply_relocations(
        &mut self,
        relocations: &[Relocation],
        base_address: u64,
    ) -> Result<(), BufferError> {
        for relocation in relocations {
            if let RelocationKind::AddressEntry {
                address,
                next_offset,
            } = relocation.kind
            {
                self.relocate_address_entry(base_address, relocation.offset, address, next_offset)?;
                continue;
            }
            let (target, addend) = match relocation.kind {
                RelocationKind::AddressEntry { .. } => unreachable!("handled above"),
                RelocationKind::Absolute64 { target, addend }
                | RelocationKind::Relative32 { target, addend, .. } => {
                    let address = match target {
                        RelocationTarget::External(address) => address,
                        RelocationTarget::Label(label) => {
                            let location = self
                                .labels
                                .get(label.0 as usize)
                                .copied()
                                .flatten()
                                .ok_or(BufferError::UnboundRelocation(label))?;
                            let offset = location
                                .offset
                                .checked_add(if location.section == Section::Data {
                                    self.data_offset
                                } else {
                                    0
                                })
                                .ok_or(BufferError::LayoutOverflow)?;
                            base_address
                                .checked_add(offset as u64)
                                .ok_or(BufferError::LayoutOverflow)?
                        }
                    };
                    (address, addend)
                }
            };
            let address = add_signed(target, addend)?;
            let source_base = if relocation.section == Section::Data {
                self.data_offset
            } else {
                0
            };
            let section = match relocation.section {
                Section::Code => &mut self.code,
                Section::Data => &mut self.data,
            };
            match relocation.kind {
                RelocationKind::AddressEntry { .. } => unreachable!("handled above"),
                RelocationKind::Absolute64 { .. } => {
                    let end = relocation
                        .offset
                        .checked_add(8)
                        .ok_or(BufferError::LayoutOverflow)?;
                    let field = section
                        .get_mut(relocation.offset..end)
                        .ok_or(BufferError::InvalidRelocation)?;
                    field.copy_from_slice(&address.to_le_bytes());
                }
                RelocationKind::Relative32 { next_offset, .. } => {
                    let next = base_address
                        .checked_add(
                            source_base
                                .checked_add(next_offset)
                                .ok_or(BufferError::LayoutOverflow)?
                                as u64,
                        )
                        .ok_or(BufferError::LayoutOverflow)?;
                    let delta = address as i128 - next as i128;
                    if !(i32::MIN as i128..=i32::MAX as i128).contains(&delta) {
                        return Err(BufferError::DisplacementOutOfRange {
                            from: source_base + next_offset,
                            to: address as usize,
                            width: 4,
                        });
                    }
                    let end = relocation
                        .offset
                        .checked_add(4)
                        .ok_or(BufferError::LayoutOverflow)?;
                    let field = section
                        .get_mut(relocation.offset..end)
                        .ok_or(BufferError::InvalidRelocation)?;
                    field.copy_from_slice(&(delta as i32).to_le_bytes());
                }
            }
        }
        Ok(())
    }
}

impl FinalizedCode {
    /// `kX64AddressEntry`: a `REX call/jmp rel32` keeps its rel32 when the target is within
    /// reach of the code's final address; otherwise it becomes `call/jmp [rip+slot]` through a
    /// slot of the `.addrtab` section, assigned on first use.
    // Port of erts/emulator/asmjit/core/codeholder.cpp:1235-1286 (relocate_to_base,
    // RelocType::kX64AddressEntry), OTP-29.1.1.
    fn relocate_address_entry(
        &mut self,
        base_address: u64,
        offset: usize,
        address: u64,
        next_offset: usize,
    ) -> Result<(), BufferError> {
        if offset < 2 || offset + 4 > self.code.len() {
            return Err(BufferError::InvalidRelocation);
        }
        let next = base_address
            .checked_add(next_offset as u64)
            .ok_or(BufferError::LayoutOverflow)?;
        let mut value = address as i128 - next as i128;
        if !(i32::MIN as i128..=i32::MAX as i128).contains(&value) {
            let slot = match self.address_table_slots.iter().position(|a| *a == address) {
                Some(slot) => slot,
                None => {
                    self.address_table_slots.push(address);
                    self.address_table_slots.len() - 1
                }
            };
            if slot >= self.address_table.len() {
                return Err(BufferError::InvalidRelocation);
            }
            value = (self.address_table_offset + slot * 8) as i128 - next_offset as i128;
            if !(i32::MIN as i128..=i32::MAX as i128).contains(&value) {
                return Err(BufferError::DisplacementOutOfRange {
                    from: next_offset,
                    to: self.address_table_offset + slot * 8,
                    width: 4,
                });
            }
            // Bytes that replace [REX, OPCODE]: CALL becomes FF /2, JMP FF /4, `[rip+disp32]`.
            let modrm = match self.code[offset - 1] {
                0xe8 => 0x15,
                0xe9 => 0x25,
                _ => return Err(BufferError::InvalidRelocation),
            };
            self.code[offset - 2] = 0xff;
            self.code[offset - 1] = modrm;
        }
        self.code[offset..offset + 4].copy_from_slice(&(value as i32).to_le_bytes());
        Ok(())
    }
}

fn add_signed(base: u64, addend: i64) -> Result<u64, BufferError> {
    if addend >= 0 {
        base.checked_add(addend as u64)
    } else {
        base.checked_sub(addend.unsigned_abs())
    }
    .ok_or(BufferError::LayoutOverflow)
}

/// Supported x86 address relocation payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelocationKind {
    /// `target + addend`, written as an absolute 64-bit address.
    Absolute64 {
        target: RelocationTarget,
        addend: i64,
    },
    /// `target + addend - (image_base + next_offset)`, written as signed rel32.
    Relative32 {
        target: RelocationTarget,
        addend: i64,
        next_offset: usize,
    },
    /// asmjit's `kX64AddressEntry`: the rel32 of a `REX call/jmp` to the absolute `address`,
    /// or, out of rel32 reach, `call/jmp [rip]` through the address table.
    AddressEntry { address: u64, next_offset: usize },
}

/// A local label or an absolute external address used by a relocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelocationTarget {
    /// Address of a label after sections are laid out.
    Label(Label),
    /// Address supplied by the caller.
    External(u64),
}

/// Errors returned by buffer operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BufferError {
    /// An instruction could not be encoded.
    Encode(EncodeError),
    /// Alignment exceeds asmjit's supported range or is not a power of two.
    InvalidAlignment(usize),
    /// A label was not allocated by this buffer.
    InvalidLabel(Label),
    /// A label has already been bound.
    AlreadyBound(Label),
    /// A label still had unresolved references at finalization.
    UnboundLabel(Label),
    /// A relative displacement does not fit its field.
    DisplacementOutOfRange { from: usize, to: usize, width: u8 },
    /// Relocation references a label not bound before finalization.
    UnboundRelocation(Label),
    /// A condition code is outside x86's 0..=15 range.
    InvalidCondition(u8),
    /// A code emission was attempted while the data section was selected.
    CodeSectionRequired,
    /// The emitted instruction did not contain a RIP-relative memory operand.
    MissingRipFixup,
    /// A relocation field does not fit the finalized section.
    InvalidRelocation,
    /// Arithmetic overflow while laying out sections.
    LayoutOverflow,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Fixup {
    label: Label,
    section: Section,
    displacement_offset: usize,
    next_offset: usize,
    width: u8,
    addend: i64,
    next: Option<usize>,
    resolved: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BranchKind {
    Jump,
    Call,
    Conditional(u8),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BranchWidth {
    Auto,
    Short,
    Near,
}

/// Mutable x86 code and data sections with label fixups and relocation records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodeBuffer {
    code: Emitter,
    data: Vec<u8>,
    active: Section,
    data_alignment: usize,
    labels: Vec<Option<LabelLocation>>,
    fixups: Vec<Fixup>,
    waiting: Vec<Option<usize>>,
    relocations: Vec<Relocation>,
    /// `_address_table_entries`: distinct external `call`/`jmp` targets.
    address_table: Vec<u64>,
}

impl Default for CodeBuffer {
    fn default() -> Self {
        Self {
            code: Emitter::new(),
            data: Vec::new(),
            active: Section::Code,
            data_alignment: 1,
            labels: Vec::new(),
            fixups: Vec::new(),
            waiting: Vec::new(),
            relocations: Vec::new(),
            address_table: Vec::new(),
        }
    }
}

impl CodeBuffer {
    /// Creates an empty buffer with the code section active.
    pub fn new() -> Self {
        Self::default()
    }

    /// Selects the section used by following emission and embedding operations.
    // Port of `BeamModuleAssembler::embed_vararg_rodata`, x86 `beam_asm_module.cpp:108-141`.
    pub fn select(&mut self, section: Section) {
        self.active = section;
    }

    /// Returns the currently selected section.
    pub fn active_section(&self) -> Section {
        self.active
    }

    /// Returns the active section's byte offset.
    pub fn offset(&self) -> usize {
        self.section_offset(self.active)
    }

    /// Returns a section's byte offset.
    pub fn section_offset(&self, section: Section) -> usize {
        self.bytes(section).len()
    }

    /// Returns bytes accumulated in a section.
    pub fn bytes(&self, section: Section) -> &[u8] {
        match section {
            Section::Code => &self.code.bytes,
            Section::Data => &self.data,
        }
    }

    /// Returns all bound labels and their section-relative locations.
    pub fn label_locations(&self) -> impl Iterator<Item = (Label, LabelLocation)> + '_ {
        self.labels
            .iter()
            .enumerate()
            .filter_map(|(id, location)| location.map(|loc| (Label(id as u32), loc)))
    }

    /// Returns the location of a bound label.
    pub fn label_location(&self, label: Label) -> Option<LabelLocation> {
        self.labels.get(label.0 as usize).copied().flatten()
    }

    /// Returns recorded base-dependent relocations.
    pub fn relocations(&self) -> &[Relocation] {
        &self.relocations
    }

    /// Allocates an unbound label.
    // Port of erts/emulator/asmjit/core/codeholder.cpp:685-698 (CodeHolder::new_label_id), OTP-29.1.1.
    pub fn new_label(&mut self) -> Label {
        let label = Label(u32::try_from(self.labels.len()).expect("x86 label id exhausted"));
        self.labels.push(None);
        self.waiting.push(None);
        label
    }

    /// Binds a label at the current section offset and resolves its pending local references.
    // Port of erts/emulator/asmjit/core/codeholder.cpp:874 (CodeHolder::bind_label), OTP-29.1.1.
    pub fn bind(&mut self, label: Label) -> Result<(), BufferError> {
        let index = label.0 as usize;
        if self
            .labels
            .get(index)
            .ok_or(BufferError::InvalidLabel(label))?
            .is_some()
        {
            return Err(BufferError::AlreadyBound(label));
        }
        let location = LabelLocation {
            section: self.active,
            offset: self.offset(),
        };

        // Validate every same-section reference before changing the label or any code bytes.
        let mut pending = self.waiting[index];
        while let Some(fixup_index) = pending {
            let fixup = self.fixups[fixup_index];
            pending = fixup.next;
            if fixup.section == location.section {
                self.displacement(fixup, location.offset)?;
            }
        }

        self.labels[index] = Some(location);
        pending = self.waiting[index].take();
        while let Some(fixup_index) = pending {
            let fixup = self.fixups[fixup_index];
            pending = fixup.next;
            if fixup.section == location.section {
                self.patch_displacement(fixup, location.offset)?;
                self.fixups[fixup_index].resolved = true;
            }
        }
        Ok(())
    }

    /// Emits an instruction or sequence of instructions through the one x86 [`Emitter`].
    pub fn emit<F>(&mut self, encode: F) -> Result<(), BufferError>
    where
        F: FnOnce(&mut Emitter) -> Result<(), EncodeError>,
    {
        if self.active != Section::Code {
            return Err(BufferError::CodeSectionRequired);
        }
        let old_len = self.code.len();
        if let Err(error) = encode(&mut self.code) {
            self.code.truncate(old_len);
            return Err(error.into());
        }
        Ok(())
    }

    /// Emits an instruction containing `[rip + addend]` and binds its displacement to `label`.
    ///
    /// The callback must emit a RIP-relative memory operand using `Mem::rip`; the displacement
    /// and end offsets come from [`Emitter::last_rip_fixup`], including a trailing immediate.
    // Port of asmjit x86assembler.cpp `EmitModSib`, kX86MemInfo_BaseLabel, OTP-29.1.1.
    pub fn emit_rip_label<F>(&mut self, label: Label, encode: F) -> Result<(), BufferError>
    where
        F: FnOnce(&mut Emitter) -> Result<(), EncodeError>,
    {
        self.ensure_label(label)?;
        if self.active != Section::Code {
            return Err(BufferError::CodeSectionRequired);
        }
        let old_len = self.code.len();
        self.emit(encode)?;
        let Some(RipFixup { disp_at, end }) = self.code.last_rip_fixup() else {
            self.code.truncate(old_len);
            return Err(BufferError::MissingRipFixup);
        };
        if disp_at < old_len || end < disp_at + 4 || end > self.code.len() {
            self.code.truncate(old_len);
            return Err(BufferError::MissingRipFixup);
        }
        let addend = i32::from_le_bytes(
            self.code.bytes[disp_at..disp_at + 4]
                .try_into()
                .expect("validated RIP displacement field"),
        ) as i64;
        let result = self.record_fixup(Fixup {
            label,
            section: Section::Code,
            displacement_offset: disp_at,
            next_offset: end,
            width: 4,
            addend,
            next: None,
            resolved: false,
        });
        if result.is_err() {
            self.code.truncate(old_len);
        }
        result
    }

    /// Emits a `jmp` to a label, selecting short only for a bound in-range target.
    // Port of asmjit `EmitJmpCall`, OTP-29.1.1. Unbound labels are emitted as rel32.
    pub fn jmp(&mut self, label: Label) -> Result<(), BufferError> {
        self.branch(BranchKind::Jump, BranchWidth::Auto, label)
    }

    /// Emits a near `jmp rel32` to a label.
    pub fn jmp_near(&mut self, label: Label) -> Result<(), BufferError> {
        self.branch(BranchKind::Jump, BranchWidth::Near, label)
    }

    /// Emits a short `jmp rel8` to a label.
    pub fn jmp_short(&mut self, label: Label) -> Result<(), BufferError> {
        self.branch(BranchKind::Jump, BranchWidth::Short, label)
    }

    /// Emits a `call rel32` to a label.
    pub fn call(&mut self, label: Label) -> Result<(), BufferError> {
        self.branch(BranchKind::Call, BranchWidth::Near, label)
    }

    /// Emits a conditional branch to a label, selecting short only for a bound in-range target.
    ///
    /// `condition` is the x86 condition-code nibble (the `CondCode` enum is being added with the
    /// condition instruction family).
    pub fn jcc(&mut self, condition: u8, label: Label) -> Result<(), BufferError> {
        self.check_condition(condition)?;
        self.branch(BranchKind::Conditional(condition), BranchWidth::Auto, label)
    }

    /// Emits a near conditional branch (`0F 8x rel32`).
    pub fn jcc_near(&mut self, condition: u8, label: Label) -> Result<(), BufferError> {
        self.check_condition(condition)?;
        self.branch(BranchKind::Conditional(condition), BranchWidth::Near, label)
    }

    /// Emits a short conditional branch (`7x rel8`).
    pub fn jcc_short(&mut self, condition: u8, label: Label) -> Result<(), BufferError> {
        self.check_condition(condition)?;
        self.branch(
            BranchKind::Conditional(condition),
            BranchWidth::Short,
            label,
        )
    }

    /// `a.call(imm(address))` with the base address unknown: `REX call rel32` (6 bytes),
    /// relocated to a rel32 or to `call [rip+slot]` of the address table.
    pub fn call_external(&mut self, address: u64) -> Result<usize, BufferError> {
        self.address_entry_branch(0xe8, address)
    }

    /// `a.jmp(imm(address))` with the base address unknown: `REX jmp rel32` (6 bytes),
    /// relocated to a rel32 or to `jmp [rip+slot]` of the address table.
    pub fn jmp_external(&mut self, address: u64) -> Result<usize, BufferError> {
        self.address_entry_branch(0xe9, address)
    }

    // Port of erts/emulator/asmjit/x86/x86assembler.cpp:4855-4911 (EmitJmpCall, immediate
    // target, no base address: REX prefix, `add_address_to_address_table`,
    // RelocType::kX64AddressEntry), OTP-29.1.1.
    fn address_entry_branch(&mut self, opcode: u8, address: u64) -> Result<usize, BufferError> {
        if self.active != Section::Code {
            return Err(BufferError::CodeSectionRequired);
        }
        if !self.address_table.contains(&address) {
            self.address_table.push(address);
        }
        let (offset, next_offset) = self.code.emit_relative_placeholder(&[0x40, opcode], 4);
        self.relocations.push(Relocation {
            section: Section::Code,
            offset,
            kind: RelocationKind::AddressEntry {
                address,
                next_offset,
            },
        });
        Ok(offset)
    }

    /// Emits an external near conditional branch and records its base-dependent relocation.
    pub fn jcc_external(&mut self, condition: u8, address: u64) -> Result<usize, BufferError> {
        self.check_condition(condition)?;
        self.external_branch(&[0x0f, 0x80 | condition], address)
    }

    // Port of asmjit x86assembler.cpp `EmitJmpCall` and `RelocType::kAbsToRel`, OTP-29.1.1.
    fn external_branch(&mut self, opcode: &[u8], address: u64) -> Result<usize, BufferError> {
        if self.active != Section::Code {
            return Err(BufferError::CodeSectionRequired);
        }
        let (offset, next_offset) = self.code.emit_relative_placeholder(opcode, 4);
        self.relocations.push(Relocation {
            section: Section::Code,
            offset,
            kind: RelocationKind::Relative32 {
                target: RelocationTarget::External(address),
                addend: 0,
                next_offset,
            },
        });
        Ok(offset)
    }

    fn branch(
        &mut self,
        kind: BranchKind,
        requested: BranchWidth,
        label: Label,
    ) -> Result<(), BufferError> {
        self.ensure_label(label)?;
        if self.active != Section::Code {
            return Err(BufferError::CodeSectionRequired);
        }
        let site = self.code.len();
        let bound_here = self
            .label_location(label)
            .filter(|location| location.section == Section::Code);
        let width = match requested {
            BranchWidth::Short => 1,
            BranchWidth::Near => 4,
            BranchWidth::Auto => {
                if let Some(location) = bound_here {
                    let short_len = opcode(kind, 1).len() + 1;
                    let displacement = location.offset as i128 - (site + short_len) as i128;
                    if (-128..=127).contains(&displacement) {
                        1
                    } else {
                        4
                    }
                } else {
                    4
                }
            }
        };
        let branch_opcode = opcode(kind, width);
        if let Some(location) = bound_here {
            let next_offset = site
                .checked_add(branch_opcode.len())
                .and_then(|offset| offset.checked_add(width as usize))
                .ok_or(BufferError::LayoutOverflow)?;
            self.displacement(
                Fixup {
                    label,
                    section: Section::Code,
                    displacement_offset: next_offset - width as usize,
                    next_offset,
                    width,
                    addend: 0,
                    next: None,
                    resolved: false,
                },
                location.offset,
            )?;
        }
        let (displacement_offset, next_offset) =
            self.code.emit_relative_placeholder(&branch_opcode, width);
        self.record_fixup(Fixup {
            label,
            section: Section::Code,
            displacement_offset,
            next_offset,
            width,
            addend: 0,
            next: None,
            resolved: false,
        })
    }

    fn record_fixup(&mut self, mut fixup: Fixup) -> Result<(), BufferError> {
        if let Some(location) = self.label_location(fixup.label) {
            if location.section == fixup.section {
                self.patch_displacement(fixup, location.offset)?;
                return Ok(());
            }
            self.fixups.push(fixup);
            return Ok(());
        }
        let label_index = fixup.label.0 as usize;
        fixup.next = self.waiting[label_index];
        let index = self.fixups.len();
        self.fixups.push(fixup);
        self.waiting[label_index] = Some(index);
        Ok(())
    }

    fn displacement(&self, fixup: Fixup, target: usize) -> Result<[u8; 4], BufferError> {
        let delta = target as i128 - fixup.next_offset as i128 + fixup.addend as i128;
        let valid = if fixup.width == 1 {
            (-128..=127).contains(&delta)
        } else {
            (i32::MIN as i128..=i32::MAX as i128).contains(&delta)
        };
        if !valid {
            return Err(BufferError::DisplacementOutOfRange {
                from: fixup.next_offset,
                to: target,
                width: fixup.width,
            });
        }
        let mut bytes = [0; 4];
        if fixup.width == 1 {
            bytes[0] = delta as i8 as u8;
        } else {
            bytes.copy_from_slice(&(delta as i32).to_le_bytes());
        }
        Ok(bytes)
    }

    fn patch_displacement(&mut self, fixup: Fixup, target: usize) -> Result<(), BufferError> {
        let bytes = self.displacement(fixup, target)?;
        match fixup.section {
            Section::Code => self
                .code
                .patch(fixup.displacement_offset, &bytes[..fixup.width as usize]),
            Section::Data => {
                let end = fixup.displacement_offset + fixup.width as usize;
                self.data[fixup.displacement_offset..end]
                    .copy_from_slice(&bytes[..fixup.width as usize]);
            }
        }
        Ok(())
    }

    /// Embeds bytes in the active section and returns their offset: erts embeds the canned
    /// NOPs of `aligned_call` and the patch words of `make_word_patch` in the code section,
    /// and its read-only tables in the data section.
    // Port of asmjit core/assembler.cpp (BaseAssembler::embed) as used by
    // erts/emulator/beam/jit/x86/beam_asm.hpp (aligned_call, make_word_patch) and
    // beam_asm_module.cpp:108-141 (embed_vararg_rodata), OTP-29.1.1.
    pub fn embed(&mut self, bytes: &[u8]) -> Result<usize, BufferError> {
        let offset = self.offset();
        match self.active {
            Section::Code => self.code.bytes.extend_from_slice(bytes),
            Section::Data => self.data.extend_from_slice(bytes),
        }
        Ok(offset)
    }

    /// Embeds a byte in the active section.
    pub fn embed_u8(&mut self, value: u8) -> Result<usize, BufferError> {
        self.embed(&[value])
    }

    /// Embeds a little-endian 16-bit value in the active section.
    pub fn embed_u16(&mut self, value: u16) -> Result<usize, BufferError> {
        self.embed(&value.to_le_bytes())
    }

    /// Embeds a little-endian 32-bit value in the active section.
    pub fn embed_u32(&mut self, value: u32) -> Result<usize, BufferError> {
        self.embed(&value.to_le_bytes())
    }

    /// Embeds a little-endian 64-bit value in the active section.
    // Port of erts/emulator/beam/jit/x86/beam_asm_module.cpp:116-133 (`embed_uint64`), OTP-29.1.1.
    pub fn embed_u64(&mut self, value: u64) -> Result<usize, BufferError> {
        self.embed(&value.to_le_bytes())
    }

    /// Embeds an IEEE-754 double in the active section.
    // Port of erts/emulator/beam/jit/x86/instr_float.cpp:59-63 (`embed_double`), OTP-29.1.1.
    pub fn embed_f64(&mut self, value: f64) -> Result<usize, BufferError> {
        self.embed_u64(value.to_bits())
    }

    /// Embeds an absolute 64-bit label address and records its relocation.
    // Port of x86 `BeamModuleAssembler::embed_vararg_rodata`, beam_asm_module.cpp:126-128.
    pub fn embed_label(&mut self, label: Label) -> Result<usize, BufferError> {
        self.ensure_label(label)?;
        let offset = self.embed_u64(0)?;
        self.relocations.push(Relocation {
            section: self.active,
            offset,
            kind: RelocationKind::Absolute64 {
                target: RelocationTarget::Label(label),
                addend: 0,
            },
        });
        Ok(offset)
    }

    /// Embeds an external absolute 64-bit address and records its relocation.
    pub fn embed_external(&mut self, address: u64) -> Result<usize, BufferError> {
        let offset = self.embed_u64(0)?;
        self.relocations.push(Relocation {
            section: self.active,
            offset,
            kind: RelocationKind::Absolute64 {
                target: RelocationTarget::External(address),
                addend: 0,
            },
        });
        Ok(offset)
    }

    /// Aligns the active section using asmjit's code-NOP or data-`0xCC` fill pattern.
    // Port of erts/emulator/asmjit/x86/x86assembler.cpp:5025-5080 (Assembler::align), OTP-29.1.1.
    pub fn align(&mut self, alignment: usize) -> Result<(), BufferError> {
        if alignment <= 1 {
            return Ok(());
        }
        if alignment > 64 || !alignment.is_power_of_two() {
            return Err(BufferError::InvalidAlignment(alignment));
        }
        match self.active {
            Section::Code => self
                .code
                .align_code(alignment as u32)
                .map_err(|_| BufferError::InvalidAlignment(alignment))?,
            Section::Data => {
                let padding = self.data.len().wrapping_neg() & (alignment - 1);
                let new_len = self
                    .data
                    .len()
                    .checked_add(padding)
                    .ok_or(BufferError::LayoutOverflow)?;
                self.data.resize(new_len, 0xcc);
                self.data_alignment = self.data_alignment.max(alignment);
            }
        }
        Ok(())
    }

    /// Resolves cross-section references and returns both sections and relocation records.
    pub fn finish(mut self) -> Result<FinalizedCode, BufferError> {
        if let Some(fixup) = self
            .fixups
            .iter()
            .find(|fixup| !fixup.resolved && self.label_location(fixup.label).is_none())
        {
            return Err(BufferError::UnboundLabel(fixup.label));
        }
        let data_offset = self
            .code
            .len()
            .checked_add(self.data_alignment - 1)
            .ok_or(BufferError::LayoutOverflow)?
            & !(self.data_alignment - 1);
        for fixup in self.fixups.iter().copied().filter(|fixup| !fixup.resolved) {
            let target = self
                .label_location(fixup.label)
                .ok_or(BufferError::UnboundLabel(fixup.label))?;
            let absolute_target = target
                .offset
                .checked_add(if target.section == Section::Data {
                    data_offset
                } else {
                    0
                })
                .ok_or(BufferError::LayoutOverflow)?;
            let source_base = if fixup.section == Section::Data {
                data_offset
            } else {
                0
            };
            let absolute_next = source_base
                .checked_add(fixup.next_offset)
                .ok_or(BufferError::LayoutOverflow)?;
            let absolute_fixup = Fixup {
                next_offset: absolute_next,
                ..fixup
            };
            let bytes = self.displacement(absolute_fixup, absolute_target)?;
            let patch = &bytes[..fixup.width as usize];
            match fixup.section {
                Section::Code => self.code.patch(fixup.displacement_offset, patch),
                Section::Data => {
                    let end = fixup.displacement_offset + fixup.width as usize;
                    self.data[fixup.displacement_offset..end].copy_from_slice(patch);
                }
            }
        }
        // `.addrtab` follows the data, 8-byte aligned.
        let address_table_offset = data_offset
            .checked_add(self.data.len())
            .and_then(|end| end.checked_add(7))
            .ok_or(BufferError::LayoutOverflow)?
            & !7;
        Ok(FinalizedCode {
            code: self.code.bytes,
            data: self.data,
            data_offset,
            address_table_offset,
            address_table: self.address_table,
            address_table_slots: Vec::new(),
            relocations: self.relocations,
            labels: self.labels,
        })
    }

    fn check_condition(&self, condition: u8) -> Result<(), BufferError> {
        if condition <= 15 {
            Ok(())
        } else {
            Err(BufferError::InvalidCondition(condition))
        }
    }

    fn ensure_label(&self, label: Label) -> Result<(), BufferError> {
        if (label.0 as usize) < self.labels.len() {
            Ok(())
        } else {
            Err(BufferError::InvalidLabel(label))
        }
    }
}

fn opcode(kind: BranchKind, width: u8) -> Vec<u8> {
    match (kind, width) {
        (BranchKind::Jump, 1) => vec![0xeb],
        (BranchKind::Jump, _) => vec![0xe9],
        (BranchKind::Call, _) => vec![0xe8],
        (BranchKind::Conditional(condition), 1) => vec![0x70 | condition],
        (BranchKind::Conditional(condition), _) => vec![0x0f, 0x80 | condition],
    }
}

#[cfg(test)]
mod tests {
    use crate::enc::{EAX, Mem, RAX};

    use super::{BufferError, CodeBuffer, RelocationKind, RelocationTarget, Section};

    #[test]
    fn bound_backward_jumps_shorten_and_unbound_forward_jumps_stay_near() {
        let mut buffer = CodeBuffer::new();
        let back = buffer.new_label();
        buffer.emit(|emitter| emitter.mov_ri(EAX, 1)).unwrap();
        buffer.bind(back).unwrap();
        buffer.jmp(back).unwrap();
        let forward = buffer.new_label();
        buffer.jmp(forward).unwrap();
        buffer.emit(|emitter| emitter.mov_ri(EAX, 2)).unwrap();
        buffer.bind(forward).unwrap();
        similar_asserts::assert_eq!(&buffer.bytes(Section::Code)[5..7], &[0xeb, 0xfe]);
        similar_asserts::assert_eq!(&buffer.bytes(Section::Code)[7..12], &[0xe9, 5, 0, 0, 0]);
    }

    #[test]
    fn local_condition_and_call_fixups_use_rel8_and_rel32() {
        let mut buffer = CodeBuffer::new();
        let target = buffer.new_label();
        buffer.jcc(4, target).unwrap();
        buffer.call(target).unwrap();
        buffer.bind(target).unwrap();
        similar_asserts::assert_eq!(
            buffer.bytes(Section::Code),
            &[0x0f, 0x84, 5, 0, 0, 0, 0xe8, 0, 0, 0, 0]
        );
        let mut backwards = CodeBuffer::new();
        let target = backwards.new_label();
        backwards.bind(target).unwrap();
        backwards.jcc(5, target).unwrap();
        similar_asserts::assert_eq!(backwards.bytes(Section::Code), &[0x75, 0xfe]);
    }

    #[test]
    fn rip_fixup_uses_emitter_offsets_and_mem_addend() {
        let mut buffer = CodeBuffer::new();
        let target = buffer.new_label();
        buffer
            .emit_rip_label(target, |emitter| emitter.mov_rm(RAX, Mem::rip(4, 8)))
            .unwrap();
        buffer.bind(target).unwrap();
        similar_asserts::assert_eq!(&buffer.bytes(Section::Code)[3..7], &[4, 0, 0, 0]);
    }

    #[test]
    fn rip_fixup_resolves_across_code_and_data_sections() {
        let mut buffer = CodeBuffer::new();
        let target = buffer.new_label();
        buffer
            .emit_rip_label(target, |emitter| emitter.mov_rm(RAX, Mem::rip(3, 8)))
            .unwrap();
        buffer.select(Section::Data);
        buffer.bind(target).unwrap();
        buffer.embed_u64(9).unwrap();
        let finalized = buffer.finish().unwrap();
        similar_asserts::assert_eq!(&finalized.code[3..7], &[3, 0, 0, 0]);
    }

    #[test]
    fn sections_align_and_embed_integer_double_and_label_data() {
        let mut buffer = CodeBuffer::new();
        let label = buffer.new_label();
        buffer.emit(|emitter| emitter.mov_ri(EAX, 1)).unwrap();
        buffer.select(Section::Data);
        buffer.embed_u8(0xaa).unwrap();
        buffer.align(8).unwrap();
        buffer.embed_f64(1.5).unwrap();
        buffer.embed_u64(9).unwrap();
        buffer.embed_label(label).unwrap();
        buffer.select(Section::Code);
        buffer.bind(label).unwrap();
        let finalized = buffer.finish().unwrap();
        similar_asserts::assert_eq!(finalized.data_offset, 8);
        similar_asserts::assert_eq!(
            &finalized.data[..8],
            &[0xaa, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc]
        );
        similar_asserts::assert_eq!(&finalized.data[8..16], &1.5_f64.to_bits().to_le_bytes());
        similar_asserts::assert_eq!(&finalized.data[16..24], &9_u64.to_le_bytes());
        let mut relocated = finalized;
        relocated.relocate(0x1000).unwrap();
        similar_asserts::assert_eq!(&relocated.data[24..32], &0x1005_u64.to_le_bytes());
    }

    #[test]
    fn external_branch_and_address_relocations_use_final_image_base() {
        let mut buffer = CodeBuffer::new();
        buffer.call_external(0x1010).unwrap();
        buffer.jmp_external(0x1020).unwrap();
        buffer.jcc_external(4, 0x1030).unwrap();
        buffer.select(Section::Data);
        buffer.embed_external(0x1040).unwrap();
        let mut finalized = buffer.finish().unwrap();
        finalized.relocate(0x1000).unwrap();
        // asmjit keeps the REX prefix of a call/jmp whose target is within rel32 reach.
        similar_asserts::assert_eq!(&finalized.code[..6], &[0x40, 0xe8, 0x0a, 0, 0, 0]);
        similar_asserts::assert_eq!(&finalized.code[6..12], &[0x40, 0xe9, 0x14, 0, 0, 0]);
        similar_asserts::assert_eq!(&finalized.code[12..18], &[0x0f, 0x84, 0x1e, 0, 0, 0]);
        similar_asserts::assert_eq!(finalized.data, 0x1040_u64.to_le_bytes());
        assert!(finalized.address_table_slots.is_empty());
    }

    // Out of rel32 reach, a call/jmp goes through its `.addrtab` slot: `FF 15`/`FF 25
    // [rip+disp32]`, one slot per distinct target.
    #[test]
    fn far_external_calls_use_the_address_table() {
        let far = 0x7f00_0000_0000_u64;
        let mut buffer = CodeBuffer::new();
        buffer.call_external(far).unwrap();
        buffer.jmp_external(far).unwrap();
        buffer.call_external(0x2000).unwrap();
        let mut finalized = buffer.finish().unwrap();
        assert_eq!(finalized.address_table, [far, 0x2000]);
        assert_eq!(finalized.address_table_offset, 24);
        finalized.relocate(0x1000).unwrap();
        similar_asserts::assert_eq!(&finalized.code[..6], &[0xff, 0x15, 18, 0, 0, 0]);
        similar_asserts::assert_eq!(&finalized.code[6..12], &[0xff, 0x25, 12, 0, 0, 0]);
        similar_asserts::assert_eq!(&finalized.code[12..18], &[0x40, 0xe8, 0xee, 0x0f, 0, 0]);
        let image = finalized.image().unwrap();
        assert_eq!(image.len(), 40);
        assert_eq!(&image[24..32], &far.to_le_bytes());
    }

    #[test]
    fn alignment_and_section_errors_leave_bytes_unchanged() {
        let mut buffer = CodeBuffer::new();
        assert!(matches!(
            buffer.align(128),
            Err(BufferError::InvalidAlignment(128))
        ));
        buffer.select(Section::Data);
        assert!(matches!(
            buffer.emit(|emitter| emitter.mov_ri(EAX, 1)),
            Err(BufferError::CodeSectionRequired)
        ));
        assert!(buffer.bytes(Section::Code).is_empty());
    }

    // asmjit's embed writes into the active section: erts embeds canned NOPs and patch words
    // in code.
    #[test]
    fn embed_writes_the_active_section() {
        let mut buffer = CodeBuffer::new();
        buffer.emit(|emitter| emitter.nop()).unwrap();
        assert_eq!(buffer.embed(&[0x66, 0x90]).unwrap(), 1);
        let label = buffer.new_label();
        buffer.bind(label).unwrap();
        assert_eq!(buffer.embed_label(label).unwrap(), 3);
        buffer.select(Section::Data);
        assert_eq!(buffer.embed_u8(7).unwrap(), 0);
        let mut finalized = buffer.finish().unwrap();
        finalized.relocate(0x1000).unwrap();
        assert_eq!(&finalized.code[..3], &[0x90, 0x66, 0x90]);
        assert_eq!(&finalized.code[3..11], &0x1003_u64.to_le_bytes());
        assert_eq!(finalized.data, [7]);
    }

    #[test]
    fn code_alignment_uses_asmjit_optimized_nop_sequences() {
        let mut buffer = CodeBuffer::new();
        buffer.emit(|emitter| emitter.mov_ri(EAX, 1)).unwrap();
        buffer.align(8).unwrap();
        similar_asserts::assert_eq!(&buffer.bytes(Section::Code)[5..], &[0x0f, 0x1f, 0x00]);
    }

    #[test]
    fn bound_short_branch_range_is_checked_before_emission() {
        let mut buffer = CodeBuffer::new();
        let target = buffer.new_label();
        buffer.jmp_short(target).unwrap();
        for value in 0..26 {
            buffer.emit(|emitter| emitter.mov_ri(EAX, value)).unwrap();
        }
        let before_bind = buffer.bytes(Section::Code).to_vec();
        assert!(matches!(
            buffer.bind(target),
            Err(BufferError::DisplacementOutOfRange { width: 1, .. })
        ));
        similar_asserts::assert_eq!(buffer.bytes(Section::Code), before_bind);
    }

    #[test]
    fn label_and_external_data_create_absolute_relocations() {
        let mut buffer = CodeBuffer::new();
        let label = buffer.new_label();
        buffer.select(Section::Data);
        buffer.embed_label(label).unwrap();
        buffer.embed_external(0x1234).unwrap();
        buffer.select(Section::Code);
        buffer.bind(label).unwrap();
        let finalized = buffer.finish().unwrap();
        assert!(matches!(
            finalized.relocations[0].kind,
            RelocationKind::Absolute64 {
                target: RelocationTarget::Label(found),
                ..
            } if found == label
        ));
        similar_asserts::assert_eq!(finalized.relocations[1].offset, 8);
    }
}
