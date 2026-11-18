//! Code/data sections, labels, x86 relative fixups, and address relocations.
//!
//! Port of asmjit's `CodeHolder` label/section machinery used by
//! `erts/emulator/beam/jit/x86/beam_asm_module.cpp`, OTP-29.1.1.

use std::fmt;

/// The active section in a [`CodeBuffer`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Section {
    /// Executable bytes.
    #[default]
    Code,
    /// Read-only constants and embedded data.
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
    /// Base-dependent relocation records.
    pub relocations: Vec<Relocation>,
    /// Label locations in allocation order.
    pub labels: Vec<Option<LabelLocation>>,
}

impl FinalizedCode {
    /// Combines the sections using the finalized aligned data offset.
    pub fn image(&self) -> Result<Vec<u8>, BufferError> {
        let end = self
            .data_offset
            .checked_add(self.data.len())
            .ok_or(BufferError::LayoutOverflow)?;
        let mut image = vec![0; end];
        image[..self.code.len()].copy_from_slice(&self.code);
        image[self.data_offset..].copy_from_slice(&self.data);
        Ok(image)
    }

    /// Applies recorded addresses after the combined image has been assigned `base_address`.
    pub fn relocate(&mut self, base_address: u64) -> Result<(), BufferError> {
        for relocation in &self.relocations {
            let (target, addend) = match relocation.kind {
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
                            let offset = location.offset
                                + if location.section == Section::Data {
                                    self.data_offset
                                } else {
                                    0
                                };
                            base_address
                                .checked_add(offset as u64)
                                .ok_or(BufferError::LayoutOverflow)?
                        }
                    };
                    (address, addend)
                }
            };
            let address = if addend >= 0 {
                target.checked_add(addend as u64)
            } else {
                target.checked_sub(addend.unsigned_abs())
            }
            .ok_or(BufferError::LayoutOverflow)?;
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
                RelocationKind::Absolute64 { .. } => {
                    section[relocation.offset..relocation.offset + 8]
                        .copy_from_slice(&address.to_le_bytes());
                }
                RelocationKind::Relative32 { next_offset, .. } => {
                    let next = base_address
                        .checked_add((source_base + next_offset) as u64)
                        .ok_or(BufferError::LayoutOverflow)?;
                    let delta = address as i128 - next as i128;
                    if !(i32::MIN as i128..=i32::MAX as i128).contains(&delta) {
                        return Err(BufferError::DisplacementOutOfRange {
                            from: source_base + next_offset,
                            to: address as usize,
                            width: 4,
                        });
                    }
                    section[relocation.offset..relocation.offset + 4]
                        .copy_from_slice(&(delta as i32).to_le_bytes());
                }
            }
        }
        Ok(())
    }
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
    /// Alignment must be a nonzero power of two.
    InvalidAlignment(usize),
    /// Label was not allocated by this buffer.
    InvalidLabel(Label),
    /// Label has already been bound.
    AlreadyBound(Label),
    /// A label still had unresolved references at finalization.
    UnboundLabel(Label),
    /// A relative displacement does not fit its field.
    DisplacementOutOfRange { from: usize, to: usize, width: u8 },
    /// Relocation references a label not bound before finalization.
    UnboundRelocation(Label),
    /// Arithmetic overflow while laying out sections.
    LayoutOverflow,
}

impl fmt::Display for BufferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for BufferError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Fixup {
    label: Label,
    section: Section,
    displacement_offset: usize,
    next_offset: usize,
    width: u8,
    next: Option<usize>,
    resolved: bool,
}

/// Mutable x86 code and data sections with label fixups and relocation records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodeBuffer {
    code: Vec<u8>,
    data: Vec<u8>,
    active: Section,
    data_alignment: usize,
    labels: Vec<Option<LabelLocation>>,
    fixups: Vec<Fixup>,
    waiting: Vec<Option<usize>>,
    relocations: Vec<Relocation>,
}

impl Default for CodeBuffer {
    fn default() -> Self {
        Self {
            code: Vec::new(),
            data: Vec::new(),
            active: Section::Code,
            data_alignment: 1,
            labels: Vec::new(),
            fixups: Vec::new(),
            waiting: Vec::new(),
            relocations: Vec::new(),
        }
    }
}

impl CodeBuffer {
    /// Creates an empty buffer with the code section active.
    pub fn new() -> Self {
        Self::default()
    }

    /// Selects the section used by following append operations.
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
            Section::Code => &self.code,
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
    // Port of asmjit `CodeHolder::new_label` and `CodeHolder::new_label_entry`, OTP-29.1.1.
    pub fn new_label(&mut self) -> Label {
        let label = Label(u32::try_from(self.labels.len()).expect("x86 label id exhausted"));
        self.labels.push(None);
        self.waiting.push(None);
        label
    }

    /// Binds a label at the current section offset and resolves its pending local references.
    // Port of asmjit `CodeHolder::bind`, OTP-29.1.1.
    pub fn bind(&mut self, label: Label) -> Result<(), BufferError> {
        let index = label.0 as usize;
        let entry = self
            .labels
            .get(index)
            .ok_or(BufferError::InvalidLabel(label))?;
        if entry.is_some() {
            return Err(BufferError::AlreadyBound(label));
        }
        let location = LabelLocation {
            section: self.active,
            offset: self.offset(),
        };
        self.labels[index] = Some(location);
        let mut fixup_index = self.waiting[index].take();
        while let Some(fixup_index_value) = fixup_index {
            let fixup = self.fixups[fixup_index_value];
            fixup_index = fixup.next;
            if fixup.section == location.section {
                self.patch_displacement(fixup, location.offset)?;
                self.fixups[fixup_index_value].resolved = true;
            }
        }
        Ok(())
    }

    /// Appends a near `jmp rel32` to a label.
    // Port of x86 branch emission through asmjit `Assembler::jmp`, OTP-29.1.1.
    pub fn jmp_near(&mut self, label: Label) -> Result<(), BufferError> {
        self.branch(label, &[0xe9], 4)
    }
    /// Appends a short `jmp rel8` to a label.
    pub fn jmp_short(&mut self, label: Label) -> Result<(), BufferError> {
        self.branch(label, &[0xeb], 1)
    }
    /// Appends a `call rel32` to a label.
    // Port of x86 `BeamAssembler::aligned_call(Label)` using the fixed five-byte call encoding.
    pub fn call(&mut self, label: Label) -> Result<(), BufferError> {
        self.branch(label, &[0xe8], 4)
    }
    /// Appends a near conditional branch (`0F 8x rel32`).
    pub fn jcc_near(&mut self, condition: u8, label: Label) -> Result<(), BufferError> {
        if condition > 15 {
            return Err(BufferError::DisplacementOutOfRange {
                from: condition as usize,
                to: 15,
                width: 4,
            });
        }
        self.branch(label, &[0x0f, 0x80 | condition], 4)
    }
    /// Appends a short conditional branch (`7x rel8`).
    pub fn jcc_short(&mut self, condition: u8, label: Label) -> Result<(), BufferError> {
        if condition > 15 {
            return Err(BufferError::DisplacementOutOfRange {
                from: condition as usize,
                to: 15,
                width: 1,
            });
        }
        self.branch(label, &[0x70 | condition], 1)
    }
    fn branch(&mut self, label: Label, opcode: &[u8], width: u8) -> Result<(), BufferError> {
        if label.0 as usize >= self.labels.len() {
            return Err(BufferError::InvalidLabel(label));
        }
        let start = self.offset();
        self.append(opcode);
        let displacement_offset = self.offset();
        self.append(&vec![0; width as usize]);
        let fixup = Fixup {
            label,
            section: self.active,
            displacement_offset,
            next_offset: self.offset(),
            width,
            next: self.waiting[label.0 as usize],
            resolved: false,
        };
        if let Some(location) = self.label_location(label) {
            if location.section == self.active {
                self.patch_displacement(fixup, location.offset)?;
            } else {
                let index = self.fixups.len();
                self.fixups.push(fixup);
                self.waiting[label.0 as usize] = Some(index);
            }
        } else {
            let index = self.fixups.len();
            self.fixups.push(fixup);
            self.waiting[label.0 as usize] = Some(index);
        }
        let _ = start;
        Ok(())
    }
    fn patch_displacement(&mut self, fixup: Fixup, target: usize) -> Result<(), BufferError> {
        let delta = target as i128 - fixup.next_offset as i128;
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
        let bytes = if fixup.width == 1 {
            vec![delta as i8 as u8]
        } else {
            (delta as i32).to_le_bytes().to_vec()
        };
        let section = self.section_mut(fixup.section);
        section[fixup.displacement_offset..fixup.displacement_offset + fixup.width as usize]
            .copy_from_slice(&bytes);
        Ok(())
    }

    /// Appends an absolute 64-bit label address placeholder and records its relocation.
    // Port of x86 `BeamModuleAssembler::embed_vararg_rodata` / `a.embed_label`, OTP-29.1.1.
    pub fn embed_label(&mut self, label: Label) -> Result<usize, BufferError> {
        if label.0 as usize >= self.labels.len() {
            return Err(BufferError::InvalidLabel(label));
        }
        let offset = self.offset();
        self.append_u64(0);
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
    /// Appends an external absolute 64-bit address placeholder and records its relocation.
    pub fn embed_external(&mut self, address: u64) -> usize {
        let offset = self.offset();
        self.append_u64(0);
        self.relocations.push(Relocation {
            section: self.active,
            offset,
            kind: RelocationKind::Absolute64 {
                target: RelocationTarget::External(address),
                addend: 0,
            },
        });
        offset
    }
    /// Records an external relative call target at a rel32 displacement field.
    pub fn call_external(&mut self, address: u64) -> usize {
        self.append_u8(0xe8);
        let offset = self.offset();
        self.append_u32(0);
        self.relocations.push(Relocation {
            section: self.active,
            offset,
            kind: RelocationKind::Relative32 {
                target: RelocationTarget::External(address),
                addend: 0,
                next_offset: offset + 4,
            },
        });
        offset
    }

    /// Appends bytes to the active section.
    pub fn append(&mut self, bytes: &[u8]) {
        self.active_bytes_mut().extend_from_slice(bytes);
    }
    /// Appends one byte to the active section.
    pub fn append_u8(&mut self, value: u8) {
        self.active_bytes_mut().push(value);
    }
    /// Appends a little-endian 16-bit value.
    pub fn append_u16(&mut self, value: u16) {
        self.append(&value.to_le_bytes());
    }
    /// Appends a little-endian 32-bit value.
    pub fn append_u32(&mut self, value: u32) {
        self.append(&value.to_le_bytes());
    }
    /// Appends a little-endian 64-bit value.
    pub fn append_u64(&mut self, value: u64) {
        self.append(&value.to_le_bytes());
    }
    /// Appends an IEEE-754 double in little-endian form.
    pub fn append_f64(&mut self, value: f64) {
        self.append_u64(value.to_bits());
    }
    /// Pads the active section until its offset satisfies `alignment`.
    pub fn align(&mut self, alignment: usize, fill: u8) -> Result<(), BufferError> {
        if alignment == 0 || !alignment.is_power_of_two() {
            return Err(BufferError::InvalidAlignment(alignment));
        }
        let padding = self.offset().wrapping_neg() & (alignment - 1);
        let new_len = self
            .offset()
            .checked_add(padding)
            .ok_or(BufferError::LayoutOverflow)?;
        self.active_bytes_mut().resize(new_len, fill);
        if self.active == Section::Data {
            self.data_alignment = self.data_alignment.max(alignment);
        }
        Ok(())
    }
    /// Resolves references that cross sections and returns both sections and relocation records.
    pub fn finish(mut self) -> Result<FinalizedCode, BufferError> {
        if let Some(fixup) = self
            .fixups
            .iter()
            .find(|fixup| !fixup.resolved && self.label_location(fixup.label).is_none())
        {
            return Err(BufferError::UnboundLabel(fixup.label));
        }
        // Cross-section rel32 references use the final code-then-data layout.
        let data_base = self.code.len();
        let data_offset = data_base
            .checked_add(self.data_alignment - 1)
            .ok_or(BufferError::LayoutOverflow)?
            & !(self.data_alignment - 1);
        let fixups = std::mem::take(&mut self.fixups);
        for fixup in fixups.into_iter().filter(|fixup| !fixup.resolved) {
            let target = self
                .label_location(fixup.label)
                .ok_or(BufferError::UnboundLabel(fixup.label))?;
            let target = if target.section == Section::Data {
                data_offset
                    .checked_add(target.offset)
                    .ok_or(BufferError::LayoutOverflow)?
            } else {
                target.offset
            };
            let source_base = if fixup.section == Section::Data {
                data_offset
            } else {
                0
            };
            let absolute_next = source_base
                .checked_add(fixup.next_offset)
                .ok_or(BufferError::LayoutOverflow)?;
            let delta = target as i128 - absolute_next as i128;
            let valid = if fixup.width == 1 {
                (-128..=127).contains(&delta)
            } else {
                (i32::MIN as i128..=i32::MAX as i128).contains(&delta)
            };
            if !valid {
                return Err(BufferError::DisplacementOutOfRange {
                    from: absolute_next,
                    to: target,
                    width: fixup.width,
                });
            }
            let patch = if fixup.width == 1 {
                vec![delta as i8 as u8]
            } else {
                (delta as i32).to_le_bytes().to_vec()
            };
            let section = self.section_mut(fixup.section);
            section[fixup.displacement_offset..fixup.displacement_offset + fixup.width as usize]
                .copy_from_slice(&patch);
        }
        Ok(FinalizedCode {
            code: self.code,
            data: self.data,
            data_offset,
            relocations: self.relocations,
            labels: self.labels,
        })
    }
    fn active_bytes_mut(&mut self) -> &mut Vec<u8> {
        self.section_mut(self.active)
    }
    fn section_mut(&mut self, section: Section) -> &mut Vec<u8> {
        match section {
            Section::Code => &mut self.code,
            Section::Data => &mut self.data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BufferError, CodeBuffer, RelocationKind, RelocationTarget, Section};

    #[test]
    fn local_forward_and_backward_fixups_use_x86_end_relative_displacements() {
        let mut b = CodeBuffer::new();
        let target = b.new_label();
        b.jmp_near(target).unwrap();
        b.append(&[0x90, 0x90]);
        b.bind(target).unwrap();
        b.jmp_short(target).unwrap();
        assert_eq!(
            b.bytes(Section::Code),
            &[0xe9, 2, 0, 0, 0, 0x90, 0x90, 0xeb, 0xfe]
        );
    }
    #[test]
    fn short_branch_range_is_checked_at_bind() {
        let mut b = CodeBuffer::new();
        let target = b.new_label();
        b.jmp_short(target).unwrap();
        b.append(&[0x90; 128]);
        assert!(matches!(
            b.bind(target),
            Err(BufferError::DisplacementOutOfRange { width: 1, .. })
        ));
    }
    #[test]
    fn sections_align_and_embed_data() {
        let mut b = CodeBuffer::new();
        b.append_u8(0xcc);
        b.select(Section::Data);
        b.align(8, 0).unwrap();
        b.append_f64(1.5);
        assert_eq!(b.bytes(Section::Data), &[0, 0, 0, 0, 0, 0, 0xf8, 0x3f]);
    }
    #[test]
    fn labels_and_external_calls_create_relocations() {
        let mut b = CodeBuffer::new();
        let label = b.new_label();
        b.select(Section::Data);
        b.embed_label(label).unwrap();
        let off = b.call_external(0x1234);
        b.select(Section::Code);
        b.bind(label).unwrap();
        let finalized = b.finish().unwrap();
        assert!(
            matches!(finalized.relocations[0].kind, RelocationKind::Absolute64 { target: RelocationTarget::Label(l), .. } if l == label)
        );
        assert_eq!(finalized.relocations[1].offset, off);
    }

    #[test]
    fn relocation_writes_label_addresses_and_external_call_displacements() {
        let mut b = CodeBuffer::new();
        let target = b.new_label();
        b.call_external(0x1010);
        b.select(Section::Data);
        b.bind(target).unwrap();
        b.embed_label(target).unwrap();
        let mut finalized = b.finish().unwrap();
        finalized.relocate(0x1000).unwrap();
        assert_eq!(finalized.code, [0xe8, 0x0b, 0, 0, 0]);
        assert_eq!(finalized.data, 0x1005_u64.to_le_bytes());
    }
}
