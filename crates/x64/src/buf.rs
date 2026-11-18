//! Separate code and data byte buffers with section-relative offsets and alignment.
//!
//! Port of the section/buffer model exposed by `CodeHolder` in
//! `erts/emulator/beam/jit/beam_jit_common.hpp`, OTP-29.1.1.

use std::fmt;

/// The active byte section in a [`CodeBuffer`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Section {
    /// Executable instruction and stub bytes.
    #[default]
    Code,
    /// Constants and embedded data bytes.
    Data,
}

/// Errors from section alignment operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BufferError {
    /// Alignment must be a nonzero power of two.
    InvalidAlignment(usize),
}

impl fmt::Display for BufferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for BufferError {}

/// Mutable code/data sections; all offsets are byte offsets within their section.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CodeBuffer {
    code: Vec<u8>,
    data: Vec<u8>,
    active: Section,
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

    /// Returns the active section's current byte offset.
    pub fn offset(&self) -> usize {
        self.section_offset(self.active)
    }

    /// Returns a section's current byte offset.
    pub fn section_offset(&self, section: Section) -> usize {
        self.bytes(section).len()
    }

    /// Returns the bytes accumulated in a section.
    pub fn bytes(&self, section: Section) -> &[u8] {
        match section {
            Section::Code => &self.code,
            Section::Data => &self.data,
        }
    }

    /// Appends bytes to the active section.
    pub fn append(&mut self, bytes: &[u8]) {
        self.active_bytes_mut().extend_from_slice(bytes);
    }

    /// Appends one byte to the active section.
    pub fn append_u8(&mut self, value: u8) {
        self.active_bytes_mut().push(value);
    }

    /// Appends a little-endian 16-bit value to the active section.
    pub fn append_u16(&mut self, value: u16) {
        self.append(&value.to_le_bytes());
    }

    /// Appends a little-endian 32-bit value to the active section.
    pub fn append_u32(&mut self, value: u32) {
        self.append(&value.to_le_bytes());
    }

    /// Appends a little-endian 64-bit value to the active section.
    pub fn append_u64(&mut self, value: u64) {
        self.append(&value.to_le_bytes());
    }

    /// Pads the active section with `fill` until its offset satisfies `alignment`.
    pub fn align(&mut self, alignment: usize, fill: u8) -> Result<(), BufferError> {
        if alignment == 0 || !alignment.is_power_of_two() {
            return Err(BufferError::InvalidAlignment(alignment));
        }
        let padding = self.offset().wrapping_neg() & (alignment - 1);
        let new_len = self.offset() + padding;
        self.active_bytes_mut().resize(new_len, fill);
        Ok(())
    }

    fn active_bytes_mut(&mut self) -> &mut Vec<u8> {
        match self.active {
            Section::Code => &mut self.code,
            Section::Data => &mut self.data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BufferError, CodeBuffer, Section};

    #[test]
    fn code_and_data_offsets_are_independent() {
        let mut buffer = CodeBuffer::new();
        buffer.append(&[0x90, 0x90]);
        buffer.select(Section::Data);
        buffer.append_u32(0x1234_5678);
        assert_eq!(buffer.offset(), 4);
        assert_eq!(buffer.section_offset(Section::Code), 2);
        assert_eq!(buffer.bytes(Section::Code), &[0x90, 0x90]);
        assert_eq!(buffer.bytes(Section::Data), &[0x78, 0x56, 0x34, 0x12]);
        buffer.select(Section::Code);
        assert_eq!(buffer.offset(), 2);
    }

    #[test]
    fn alignment_pads_only_active_section() {
        let mut buffer = CodeBuffer::new();
        buffer.append(&[1, 2, 3]);
        buffer.align(4, 0x90).unwrap();
        assert_eq!(buffer.bytes(Section::Code), &[1, 2, 3, 0x90]);
        buffer.select(Section::Data);
        buffer.append_u8(7);
        buffer.align(8, 0).unwrap();
        assert_eq!(buffer.bytes(Section::Data), &[7, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(buffer.bytes(Section::Code).len(), 4);
    }

    #[test]
    fn append_primitives_are_little_endian() {
        let mut buffer = CodeBuffer::new();
        buffer.append_u8(0xab);
        buffer.append_u16(0xcdef);
        buffer.append_u32(0x0123_4567);
        buffer.append_u64(0x8899_aabb_ccdd_eeff);
        assert_eq!(
            buffer.bytes(Section::Code),
            &[
                0xab, 0xef, 0xcd, 0x67, 0x45, 0x23, 0x01, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99,
                0x88,
            ]
        );
    }

    #[test]
    fn alignment_requires_power_of_two() {
        let mut buffer = CodeBuffer::new();
        assert_eq!(buffer.align(0, 0), Err(BufferError::InvalidAlignment(0)));
        assert_eq!(buffer.align(3, 0), Err(BufferError::InvalidAlignment(3)));
    }
}
