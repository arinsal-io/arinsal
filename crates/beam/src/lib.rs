//! Strict, owning reader for Erlang/OTP 29 BEAM files.

#![forbid(unsafe_code)]

use arinsal_etf::{DecodeError, OwnedTerm, decode};
use arinsal_spec::{BEAM_FORMAT_NUMBER, Opcode};
use flate2::read::{GzDecoder, ZlibDecoder};
use num_bigint::BigInt;
use std::{collections::HashMap, io::Read};

/// A four-byte IFF chunk identifier.
pub type ChunkId = [u8; 4];

/// Parse failure with a byte offset into the affected chunk when available.
#[derive(Debug, thiserror::Error)]
pub enum BeamError {
    /// Malformed file or unsupported format.
    #[error("{context} at offset {offset}: {message}")]
    Invalid {
        context: String,
        offset: usize,
        message: String,
    },
    /// A literal's ETF bytes could not be decoded.
    #[error("literal ETF: {0}")]
    Literal(#[from] DecodeError),
}

fn bad(context: &str, offset: usize, message: impl Into<String>) -> BeamError {
    BeamError::Invalid {
        context: context.into(),
        offset,
        message: message.into(),
    }
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    context: &'static str,
}
impl<'a> Reader<'a> {
    fn new(data: &'a [u8], context: &'static str) -> Self {
        Self {
            data,
            pos: 0,
            context,
        }
    }
    fn take(&mut self, len: usize) -> Result<&'a [u8], BeamError> {
        let end = self
            .pos
            .checked_add(len)
            .filter(|&n| n <= self.data.len())
            .ok_or_else(|| bad(self.context, self.pos, "truncated data"))?;
        let out = &self.data[self.pos..end];
        self.pos = end;
        Ok(out)
    }
    fn u8(&mut self) -> Result<u8, BeamError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, BeamError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, BeamError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn done(&self) -> Result<(), BeamError> {
        if self.pos == self.data.len() {
            Ok(())
        } else {
            Err(bad(self.context, self.pos, "trailing data"))
        }
    }
    fn count(&mut self, entry_min: usize) -> Result<usize, BeamError> {
        let n = self.u32()? as usize;
        if n > (self.data.len() - self.pos) / entry_min.max(1) {
            return Err(bad(self.context, self.pos, "entry count exceeds chunk"));
        }
        Ok(n)
    }
}

/// An import table entry. Atom indices are one-based.
#[derive(Clone, Debug)]
pub struct Import {
    /// One-based module atom index.
    pub module_atom: u32,
    /// One-based function atom index.
    pub function_atom: u32,
    /// Imported arity.
    pub arity: u32,
}
/// An export or local function entry.
#[derive(Clone, Debug)]
pub struct Export {
    /// One-based function atom index.
    pub function_atom: u32,
    /// Exported arity.
    pub arity: u32,
    /// Entry label.
    pub label: u32,
}
/// A `FunT` entry.
#[derive(Clone, Debug)]
pub struct Lambda {
    /// One-based function atom index.
    pub function_atom: u32,
    /// Function arity.
    pub arity: u32,
    /// Entry label.
    pub label: u32,
    /// Fun table index.
    pub index: u32,
    /// Number of captured variables.
    pub num_free: u32,
    /// Legacy uniqueness value.
    pub old_uniq: u32,
}
/// Raw ETF literal, including version byte 131.
#[derive(Clone, Debug)]
pub struct LiteralRaw(pub Vec<u8>);
/// Source location item; name index zero is the implicit module source name.
#[derive(Clone, Debug)]
pub struct LineItem {
    /// Zero denotes the implicit module source name.
    pub name_index: u32,
    /// One-based source line.
    pub line: u64,
}
/// Decoded `Line` chunk.
#[derive(Clone, Debug)]
pub struct LineTable {
    /// Line chunk version.
    pub version: u32,
    /// Line execution and counter flags.
    pub flags: u32,
    /// Number of line instructions.
    pub instruction_count: u32,
    /// Decoded source locations.
    pub items: Vec<LineItem>,
    /// Explicit source file names; index one selects the first name.
    pub names: Vec<String>,
}
/// One entry of the `Type` chunk. Bounds are signed 64-bit integers; unit defaults to one.
#[derive(Clone, Debug)]
pub struct BeamType {
    /// OTP 29 type union bitmask.
    pub union_bits: u16,
    /// Optional inclusive integer lower bound.
    pub lower_bound: Option<i64>,
    /// Optional inclusive integer upper bound.
    pub upper_bound: Option<i64>,
    /// Bitstring size unit, defaulting to one.
    pub unit: u16,
}
/// Decoded `Type` chunk.
#[derive(Clone, Debug)]
pub struct TypeTable {
    /// Type chunk version.
    pub version: u32,
    /// Types indexed from zero.
    pub entries: Vec<BeamType>,
}
/// Allocation request type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllocKind {
    /// Heap words.
    Words,
    /// Float objects.
    Floats,
    /// Fun objects.
    Funs,
}
/// One allocation request.
#[derive(Clone, Debug)]
pub struct Allocation {
    /// Allocation category.
    pub kind: AllocKind,
    /// Requested quantity.
    pub count: u64,
}
/// One lossless generic BEAM operand.
#[derive(Clone, Debug)]
pub enum Operand {
    /// Unsigned compact value.
    U(u64),
    /// Signed integer fitting in i64.
    Int(i64),
    /// Integer outside the compact unsigned and signed 64-bit ranges.
    BigInt(Box<BigInt>),
    /// One-based atom index.
    Atom(u32),
    /// X register index.
    X(u32),
    /// Y register index.
    Y(u32),
    /// Float register index.
    FR(u32),
    /// Label index; zero is a failure sentinel.
    Label(u32),
    /// Character code point.
    Char(u32),
    /// Extended list operand.
    List(Box<Vec<Operand>>),
    /// Extended allocation list.
    Alloc(Box<Vec<Allocation>>),
    /// Zero-based literal index.
    Literal(u32),
    TypedReg {
        reg: Box<Operand>,
        type_index: u32,
    },
    /// The empty list encoded as atom index zero.
    Nil,
}
/// Generic instruction, with offset from the start of the `Code` chunk.
#[derive(Clone, Debug)]
pub struct Instr {
    /// Generic opcode.
    pub op: Opcode,
    /// Decoded operands in source order.
    pub args: Vec<Operand>,
    /// Byte offset from the start of the Code chunk.
    pub offset: usize,
}
/// Code chunk header and generic instruction sequence.
#[derive(Clone, Debug)]
pub struct CodeChunk {
    /// Bytes after the sub-size field and before code.
    pub header_size: u32,
    /// Generic instruction set version.
    pub instruction_set: u32,
    /// Highest opcode used when the module was compiled.
    pub max_opcode: u32,
    /// Upper bound for label indices.
    pub label_count: u32,
    /// Number of functions.
    pub function_count: u32,
    /// Generic instruction sequence including final int_code_end. Empty for a file from
    /// [`read`] until [`BeamFile::decode_code`] fills it.
    pub instructions: Vec<Instr>,
    /// The instructions as the file stores them: the Code chunk after its header.
    pub bytes: Vec<u8>,
}
/// A decoded BEAM file. `atoms[0]` is atom index 1; index 0 denotes nil only in operands.
#[derive(Clone, Debug)]
pub struct BeamFile {
    /// Module atom text.
    pub module: String,
    /// One-based atom table stored at zero-based vector positions.
    pub atoms: Vec<String>,
    /// Code chunk.
    pub code: CodeChunk,
    /// Import table.
    pub imports: Vec<Import>,
    /// Export table.
    pub exports: Vec<Export>,
    /// Local function table, when present.
    pub locals: Vec<Export>,
    /// Lambda table.
    pub lambdas: Vec<Lambda>,
    /// Raw ETF literal table.
    pub literals: Vec<LiteralRaw>,
    /// String table bytes.
    pub strings: Vec<u8>,
    /// Decoded line table, when present.
    pub lines: Option<LineTable>,
    /// Decoded type table, when present.
    pub types: Option<TypeTable>,
    /// Raw ETF attribute chunk.
    pub attributes: Option<Vec<u8>>,
    /// Raw ETF compiler info chunk.
    pub compile_info: Option<Vec<u8>>,
    /// Raw ETF metadata chunk.
    pub meta: Option<Vec<u8>>,
    /// Native record definitions decoded from the OTP `Recs` chunk.
    pub records: Vec<NativeRecord>,
    /// Chunk identifiers and payload sizes in file order.
    pub chunks: Vec<(ChunkId, usize)>,
    /// Unknown chunk payloads.
    pub other_chunks: Vec<(ChunkId, Vec<u8>)>,
}

/// One compiler-emitted native record definition.
#[derive(Clone, Debug)]
pub struct NativeRecord {
    /// Record name.
    pub name: String,
    /// Whether code outside the defining module can access the record.
    pub is_exported: bool,
    /// Fields in declaration order and their optional defaults.
    pub fields: Vec<(String, Option<OwnedTerm>)>,
}
impl BeamFile {
    /// Drop the decoded code, tables and literals of a loaded module, keeping the atoms,
    /// attributes, compiler info and the unknown chunks (erts frees the `BeamFile` after
    /// `beam_load_finalize` and keeps `module_info` data in the code header).
    pub fn release_decoded(&mut self) {
        self.code.instructions = Vec::new();
        self.code.bytes = Vec::new();
        self.imports = Vec::new();
        self.exports = Vec::new();
        self.locals = Vec::new();
        self.lambdas = Vec::new();
        self.literals = Vec::new();
        self.strings = Vec::new();
        self.lines = None;
        self.types = None;
        self.records = Vec::new();
    }

    /// Resolve a one-based atom index; zero is not a table entry.
    pub fn atom(&self, index: u32) -> Option<&str> {
        index
            .checked_sub(1)
            .and_then(|i| self.atoms.get(i as usize))
            .map(String::as_str)
    }
    /// Decode a literal only when requested.
    pub fn literal(&self, index: u32) -> Result<OwnedTerm, BeamError> {
        let raw = self
            .literals
            .get(index as usize)
            .ok_or_else(|| bad("LitT", index as usize, "literal index out of range"))?;
        Ok(decode(&raw.0)?)
    }
}

/// Parse a whole BEAM file, including gzip-wrapped files accepted by `beam_lib`, and decode
/// its instructions.
pub fn parse(bytes: &[u8]) -> Result<BeamFile, BeamError> {
    let mut file = read(bytes)?;
    file.decode_code()?;
    Ok(file)
}

impl BeamFile {
    /// Decode the instructions of the Code chunk into [`Instr`]s (`read` leaves them as bytes).
    pub fn decode_code(&mut self) -> Result<(), BeamError> {
        if !self.code.instructions.is_empty() {
            return Ok(());
        }
        let bytes = std::mem::take(&mut self.code.bytes);
        let result = decode_instructions(
            &bytes,
            self.code.max_opcode,
            self.code.label_count,
            self.code.function_count,
            self.atoms.len(),
            self.literals.len(),
            self.types.as_ref(),
        );
        self.code.bytes = bytes;
        self.code.instructions = result?;
        Ok(())
    }
}

/// Read a BEAM file's chunks into tables: the part of erts's `beamfile_read` (beam_file.c) that
/// does not touch the instructions. The Code chunk is validated at its header and kept as
/// bytes; [`BeamFile::decode_code`] decodes it for consumers that want [`Instr`]s, the loader's
/// code reader reads the bytes itself.
pub fn read(bytes: &[u8]) -> Result<BeamFile, BeamError> {
    let inflated;
    let bytes = if bytes.starts_with(&[0x1f, 0x8b]) {
        let mut decoder = GzDecoder::new(bytes);
        inflated = read_limited(&mut decoder, 256 * 1024 * 1024, "gzip")?;
        inflated.as_slice()
    } else {
        bytes
    };
    let mut r = Reader::new(bytes, "IFF");
    if r.take(4)? != b"FOR1" {
        return Err(bad("IFF", 0, "expected FOR1"));
    }
    let form_size = r.u32()? as usize;
    if form_size != bytes.len().saturating_sub(8) {
        return Err(bad("IFF", 4, "form size mismatch"));
    }
    if r.take(4)? != b"BEAM" {
        return Err(bad("IFF", 8, "expected BEAM"));
    }
    let mut chunks = Vec::new();
    let mut map: HashMap<ChunkId, &[u8]> = HashMap::with_capacity(16);
    while r.pos < bytes.len() {
        let id: ChunkId = r.take(4)?.try_into().unwrap();
        let size = r.u32()? as usize;
        let data = r.take(size)?;
        let padding = (4 - size % 4) % 4;
        r.take(padding)?;
        chunks.push((id, size));
        if map.insert(id, data).is_some() {
            return Err(bad(
                "IFF",
                r.pos,
                format!("duplicate chunk {}", String::from_utf8_lossy(&id)),
            ));
        }
    }
    let atoms = parse_atoms(
        required(&map, *b"AtU8").or_else(|_| required(&map, *b"Atom"))?,
        map.contains_key(b"AtU8"),
    )?;
    let module = atoms
        .first()
        .ok_or_else(|| bad("AtU8", 0, "empty atom table"))?
        .clone();
    let imports = parse_imports(required(&map, *b"ImpT")?, atoms.len())?;
    let exports = parse_exports(required(&map, *b"ExpT")?, atoms.len(), "ExpT")?;
    let locals = map
        .get(b"LocT")
        .map(|v| parse_exports(v, atoms.len(), "LocT"))
        .transpose()?
        .unwrap_or_default();
    let lambdas = map
        .get(b"FunT")
        .map(|v| parse_lambdas(v, atoms.len()))
        .transpose()?
        .unwrap_or_default();
    let literals = map
        .get(b"LitT")
        .map(|v| parse_literals(v))
        .transpose()?
        .unwrap_or_default();
    let records = map
        .get(b"Recs")
        .map(|chunk| parse_records(chunk, &atoms, &literals))
        .transpose()?
        .unwrap_or_default();
    let lines = map.get(b"Line").map(|v| parse_lines(v)).transpose()?;
    let types = map.get(b"Type").map(|v| parse_types(v)).transpose()?;
    let code = parse_code_header(required(&map, *b"Code")?)?;
    for lambda in &lambdas {
        if lambda.label == 0 || lambda.label >= code.label_count {
            return Err(bad("FunT", 0, "lambda label out of range"));
        }
    }
    let strings = required(&map, *b"StrT")?.to_vec();
    let known: &[ChunkId] = &[
        *b"AtU8", *b"Atom", *b"Code", *b"StrT", *b"ImpT", *b"ExpT", *b"LocT", *b"FunT", *b"LitT",
        *b"Line", *b"Type", *b"Attr", *b"CInf", *b"Meta", *b"Recs",
    ];
    let other_chunks = chunks
        .iter()
        .filter(|(id, _)| !known.contains(id))
        .map(|(id, _)| (*id, map[id].to_vec()))
        .collect();
    Ok(BeamFile {
        module,
        atoms,
        code,
        imports,
        exports,
        locals,
        lambdas,
        literals,
        strings,
        lines,
        types,
        attributes: map.get(b"Attr").map(|chunk| chunk.to_vec()),
        compile_info: map.get(b"CInf").map(|chunk| chunk.to_vec()),
        meta: map.get(b"Meta").map(|chunk| chunk.to_vec()),
        records,
        chunks,
        other_chunks,
    })
}

fn required<'a>(map: &HashMap<ChunkId, &'a [u8]>, id: ChunkId) -> Result<&'a [u8], BeamError> {
    map.get(&id).copied().ok_or_else(|| {
        bad(
            "IFF",
            0,
            format!("missing {} chunk", String::from_utf8_lossy(&id)),
        )
    })
}
fn read_limited<R: Read>(
    reader: &mut R,
    limit: usize,
    context: &str,
) -> Result<Vec<u8>, BeamError> {
    let mut out = Vec::new();
    reader
        .take((limit + 1) as u64)
        .read_to_end(&mut out)
        .map_err(|e| bad(context, 0, e.to_string()))?;
    if out.len() > limit {
        return Err(bad(context, 0, "decompressed data too large"));
    }
    Ok(out)
}
fn parse_atoms(data: &[u8], utf8: bool) -> Result<Vec<String>, BeamError> {
    let mut r = Reader::new(data, "atoms");
    let raw_count = r.u32()? as i32;
    let long = raw_count < 0;
    let count = raw_count.unsigned_abs() as usize;
    if count > data.len() - r.pos {
        return Err(bad("atoms", r.pos, "count exceeds chunk"));
    }
    let mut atoms = Vec::with_capacity(count);
    for _ in 0..count {
        let len = if long {
            compact_u(&mut r)? as usize
        } else {
            r.u8()? as usize
        };
        let bytes = r.take(len)?;
        let value = if utf8 {
            std::str::from_utf8(bytes)
                .map_err(|e| bad("atoms", r.pos, e.to_string()))?
                .to_owned()
        } else {
            bytes.iter().map(|&b| char::from(b)).collect()
        };
        atoms.push(value);
    }
    r.done()?;
    Ok(atoms)
}
fn atom_index(index: u32, count: usize, context: &str, pos: usize) -> Result<u32, BeamError> {
    if index == 0 || index as usize > count {
        Err(bad(context, pos, "atom index out of range"))
    } else {
        Ok(index)
    }
}
fn parse_imports(data: &[u8], atoms: usize) -> Result<Vec<Import>, BeamError> {
    let mut r = Reader::new(data, "ImpT");
    let n = r.count(12)?;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let module_atom = atom_index(r.u32()?, atoms, "ImpT", r.pos)?;
        let function_atom = atom_index(r.u32()?, atoms, "ImpT", r.pos)?;
        let arity = r.u32()?;
        if arity > 255 {
            return Err(bad("ImpT", r.pos, "arity exceeds MAX_ARG"));
        }
        out.push(Import {
            module_atom,
            function_atom,
            arity,
        });
    }
    r.done()?;
    Ok(out)
}
fn parse_exports(
    data: &[u8],
    atoms: usize,
    context: &'static str,
) -> Result<Vec<Export>, BeamError> {
    let mut r = Reader::new(data, context);
    let n = r.count(12)?;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let function_atom = atom_index(r.u32()?, atoms, context, r.pos)?;
        let arity = r.u32()?;
        if arity > 255 {
            return Err(bad(context, r.pos, "arity exceeds MAX_ARG"));
        }
        let label = r.u32()?;
        out.push(Export {
            function_atom,
            arity,
            label,
        });
    }
    r.done()?;
    Ok(out)
}
fn parse_lambdas(data: &[u8], atoms: usize) -> Result<Vec<Lambda>, BeamError> {
    let mut r = Reader::new(data, "FunT");
    let n = r.count(24)?;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let function_atom = atom_index(r.u32()?, atoms, "FunT", r.pos)?;
        out.push(Lambda {
            function_atom,
            arity: r.u32()?,
            label: r.u32()?,
            index: r.u32()?,
            num_free: r.u32()?,
            old_uniq: r.u32()?,
        });
    }
    r.done()?;
    Ok(out)
}
// Port of erts/emulator/beam/beam_file.c:1471 (parse_literal_chunk), OTP-29.1.1.
fn parse_literals(data: &[u8]) -> Result<Vec<LiteralRaw>, BeamError> {
    let mut r = Reader::new(data, "LitT");
    let expected = r.u32()? as usize;
    let inflated;
    let payload = if expected == 0 {
        r.take(data.len() - r.pos)?
    } else {
        inflated = read_limited(
            &mut ZlibDecoder::new(r.take(data.len() - r.pos)?),
            256 * 1024 * 1024,
            "LitT zlib",
        )?;
        if inflated.len() != expected {
            return Err(bad("LitT", 0, "uncompressed size mismatch"));
        }
        inflated.as_slice()
    };
    let mut r = Reader::new(payload, "LitT");
    let n = r.count(4)?;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let len = r.u32()? as usize;
        let bytes = r.take(len)?;
        if bytes.first() != Some(&131) {
            return Err(bad("LitT", r.pos, "literal lacks ETF version byte"));
        }
        out.push(LiteralRaw(bytes.to_vec()));
    }
    r.done()?;
    Ok(out)
}

// Port of erts/emulator/beam/beam_file.c:1077-1317 (parse_record_chunk_data), OTP-29.1.1.
fn parse_records(
    data: &[u8],
    atoms: &[String],
    literals: &[LiteralRaw],
) -> Result<Vec<NativeRecord>, BeamError> {
    let mut r = Reader::new(data, "Recs");
    let version = r.u32()?;
    if version != 0 {
        return Err(bad("Recs", 0, "unsupported record chunk version"));
    }
    let count = r.u32()? as i32;
    let expected_fields = r.u32()? as usize;
    if count < 0 || count as usize > data.len().saturating_sub(r.pos) {
        return Err(bad("Recs", r.pos, "invalid record count"));
    }
    let mut records = Vec::with_capacity(count as usize);
    let mut total_fields = 0usize;
    for _ in 0..count {
        let offset = r.pos;
        let opcode = Opcode::from_u8(r.u8()?)
            .ok_or_else(|| bad("Recs", offset, "unknown record definition opcode"))?;
        if opcode.name() != "call_last" || opcode.arity() != 3 {
            return Err(bad(
                "Recs",
                offset,
                "expected call_last/3 record definition",
            ));
        }
        let args = (0..3)
            .map(|_| operand(&mut r, atoms.len(), literals.len(), None, 0))
            .collect::<Result<Vec<_>, _>>()?;
        let name = match &args[0] {
            Operand::Atom(index) => atoms
                .get(*index as usize - 1)
                .cloned()
                .ok_or_else(|| bad("Recs", offset, "record name atom out of range"))?,
            _ => return Err(bad("Recs", offset, "record name is not an atom")),
        };
        let is_exported = match &args[1] {
            Operand::Atom(index) => match atoms.get(*index as usize - 1).map(String::as_str) {
                Some("true") => true,
                Some("false") => false,
                _ => return Err(bad("Recs", offset, "invalid record exported flag")),
            },
            _ => return Err(bad("Recs", offset, "invalid record exported flag")),
        };
        let field_operands = match &args[2] {
            Operand::List(items) if items.len() % 2 == 0 => items,
            _ => return Err(bad("Recs", offset, "record fields are not key/value pairs")),
        };
        let mut fields = Vec::with_capacity(field_operands.len() / 2);
        for pair in field_operands.as_chunks::<2>().0 {
            let field_name = match pair[0] {
                Operand::Atom(index) => atoms
                    .get(index as usize - 1)
                    .cloned()
                    .ok_or_else(|| bad("Recs", offset, "record field atom out of range"))?,
                _ => return Err(bad("Recs", offset, "record field name is not an atom")),
            };
            let default = match &pair[1] {
                Operand::U(0) => None,
                value => Some(record_operand_to_owned(value, atoms, literals, offset)?),
            };
            fields.push((field_name, default));
        }
        total_fields = total_fields
            .checked_add(fields.len())
            .ok_or_else(|| bad("Recs", offset, "record field count overflow"))?;
        records.push(NativeRecord {
            name,
            is_exported,
            fields,
        });
    }
    r.done()?;
    if total_fields != expected_fields {
        return Err(bad("Recs", 8, "record field count mismatch"));
    }
    Ok(records)
}

fn record_operand_to_owned(
    operand: &Operand,
    atoms: &[String],
    literals: &[LiteralRaw],
    offset: usize,
) -> Result<OwnedTerm, BeamError> {
    match operand {
        Operand::Atom(index) => atoms
            .get(*index as usize - 1)
            .map(|name| OwnedTerm::Atom(name.clone()))
            .ok_or_else(|| bad("Recs", offset, "default atom out of range")),
        Operand::Int(value) => Ok(OwnedTerm::Int(*value)),
        Operand::BigInt(value) => Ok(OwnedTerm::BigInt((**value).clone())),
        Operand::Literal(index) => literals
            .get(*index as usize)
            .ok_or_else(|| bad("Recs", offset, "default literal out of range"))
            .and_then(|literal| decode(&literal.0).map_err(BeamError::from)),
        Operand::Nil => Ok(OwnedTerm::Nil),
        Operand::Char(value) => Ok(OwnedTerm::Int(i64::from(*value))),
        Operand::U(value) => i64::try_from(*value)
            .map(OwnedTerm::Int)
            .map_err(|_| bad("Recs", offset, "default integer out of range")),
        _ => Err(bad("Recs", offset, "unsupported record default operand")),
    }
}
// Port of erts/emulator/beam/beam_file.c:443 (parse_line_chunk), OTP-29.1.1.
fn parse_lines(data: &[u8]) -> Result<LineTable, BeamError> {
    let mut r = Reader::new(data, "Line");
    let version = r.u32()?;
    if version != 0 {
        return Err(bad("Line", 0, format!("unsupported version {version}")));
    }
    let flags = r.u32()?;
    let instruction_count = r.u32()?;
    let item_count = r.u32()? as usize;
    let name_count = r.u32()? as usize;
    if item_count > data.len() - r.pos || name_count > (data.len() - r.pos) / 2 {
        return Err(bad("Line", r.pos, "count exceeds chunk"));
    }
    let mut items = Vec::with_capacity(item_count);
    let mut current_name = 0;
    while items.len() < item_count {
        let (tag, value) = compact(&mut r)?;
        match tag {
            2 => {
                current_name = u32::try_from(small_u(value, "Line", r.pos)?)
                    .map_err(|_| bad("Line", r.pos, "name index overflow"))?;
                if current_name as usize > name_count {
                    return Err(bad("Line", r.pos, "name index out of range"));
                }
            }
            1 => {
                let line = i64::try_from(&value)
                    .ok()
                    .filter(|&n| n >= 0)
                    .ok_or_else(|| bad("Line", r.pos, "invalid line"))?
                    as u64;
                items.push(LineItem {
                    name_index: current_name,
                    line,
                });
            }
            _ => return Err(bad("Line", r.pos, "invalid line item tag")),
        }
    }
    let mut names = Vec::with_capacity(name_count);
    for _ in 0..name_count {
        let len = r.u16()? as usize;
        names.push(
            std::str::from_utf8(r.take(len)?)
                .map_err(|e| bad("Line", r.pos, e.to_string()))?
                .to_owned(),
        );
    }
    r.done()?;
    Ok(LineTable {
        version,
        flags,
        instruction_count,
        items,
        names,
    })
}
// Port of erts/emulator/beam/beam_file.c:630 (parse_type_chunk_data), OTP-29.1.1.
fn parse_types(data: &[u8]) -> Result<TypeTable, BeamError> {
    let mut r = Reader::new(data, "Type");
    let version = r.u32()?;
    if !matches!(version, 2..=4) {
        return Err(bad("Type", 0, format!("unsupported version {version}")));
    }
    let n = r.count(2)?;
    if n == 0 {
        return Err(bad("Type", r.pos, "empty type table"));
    }
    let mut entries = Vec::with_capacity(n);
    for _ in 0..n {
        let mut bits = r.u16()?;
        if version == 2 {
            bits = (bits & 3) | ((bits & !3) >> 1);
        }
        if version < 4 {
            bits = (bits & 0x0fff) | ((bits << 1) & 0xe000);
        }
        let union_bits = bits & 0x1fff;
        if union_bits == 0 {
            return Err(bad("Type", r.pos, "empty type union"));
        }
        if bits & 0x6000 != 0 && union_bits & 0x28 == 0 {
            return Err(bad("Type", r.pos, "bounds require numeric type"));
        }
        if bits & 0x8000 != 0 && union_bits & 0x02 == 0 {
            return Err(bad("Type", r.pos, "unit requires bitstring type"));
        }
        let lower_bound = if bits & 0x2000 != 0 {
            Some(i64::from_be_bytes(r.take(8)?.try_into().unwrap()))
        } else {
            None
        };
        let upper_bound = if bits & 0x4000 != 0 {
            Some(i64::from_be_bytes(r.take(8)?.try_into().unwrap()))
        } else {
            None
        };
        let unit = if bits & 0x8000 != 0 {
            r.u8()? as u16 + 1
        } else {
            1
        };
        entries.push(BeamType {
            union_bits,
            lower_bound,
            upper_bound,
            unit,
        });
    }
    r.done()?;
    Ok(TypeTable { version, entries })
}

// Port of erts/emulator/beam/beam_file.c:167 (beamreader_read_tagged), OTP-29.1.1.
fn compact(r: &mut Reader<'_>) -> Result<(u8, BigInt), BeamError> {
    compact_inner(r, 0)
}
fn compact_inner(r: &mut Reader<'_>, depth: usize) -> Result<(u8, BigInt), BeamError> {
    if depth > 32 {
        return Err(bad(r.context, r.pos, "compact length nesting too deep"));
    }
    let first = r.u8()?;
    let tag = first & 7;
    let number = if first & 8 == 0 {
        BigInt::from(first >> 4)
    } else if first & 16 == 0 {
        BigInt::from((((first >> 5) as u16) << 8) | r.u8()? as u16)
    } else {
        let code = first >> 5;
        let len = if code < 7 {
            code as usize + 2
        } else {
            let extra = compact_u_inner(r, depth + 1)?;
            let len = extra
                .checked_add(9)
                .ok_or_else(|| bad(r.context, r.pos, "compact length overflow"))?;
            usize::try_from(len).map_err(|_| bad(r.context, r.pos, "compact length overflow"))?
        };
        let bytes = r.take(len)?;
        if tag == 1 {
            BigInt::from_signed_bytes_be(bytes)
        } else {
            BigInt::from_bytes_be(num_bigint::Sign::Plus, bytes)
        }
    };
    Ok((tag, number))
}
fn small_u(n: BigInt, context: &str, offset: usize) -> Result<u64, BeamError> {
    u64::try_from(n)
        .ok()
        .ok_or_else(|| bad(context, offset, "integer out of range"))
}
fn compact_u(r: &mut Reader<'_>) -> Result<u64, BeamError> {
    compact_u_inner(r, 0)
}
fn compact_u_inner(r: &mut Reader<'_>, depth: usize) -> Result<u64, BeamError> {
    let (tag, n) = compact_inner(r, depth)?;
    if tag != 0 {
        return Err(bad(r.context, r.pos, "expected unsigned compact integer"));
    }
    small_u(n, r.context, r.pos)
}
fn register(n: u64, context: &str, offset: usize) -> Result<u32, BeamError> {
    if n >= 1024 {
        Err(bad(context, offset, "register exceeds MAX_REG"))
    } else {
        Ok(n as u32)
    }
}
fn operand(
    r: &mut Reader<'_>,
    atoms: usize,
    literals: usize,
    types: Option<&TypeTable>,
    depth: usize,
) -> Result<Operand, BeamError> {
    if depth > 32 {
        return Err(bad(r.context, r.pos, "operand nesting too deep"));
    }
    let (tag, value) = compact(r)?;
    let u = || small_u(value.clone(), r.context, r.pos);
    match tag {
        0 => Ok(u64::try_from(&value)
            .ok()
            .map_or_else(|| Operand::BigInt(Box::new(value)), Operand::U)),
        1 => Ok(i64::try_from(&value)
            .ok()
            .map_or_else(|| Operand::BigInt(Box::new(value)), Operand::Int)),
        2 => {
            let n = u()?;
            if n == 0 {
                Ok(Operand::Nil)
            } else {
                if n as usize > atoms {
                    return Err(bad(r.context, r.pos, "atom index out of range"));
                }
                Ok(Operand::Atom(u32::try_from(n).map_err(|_| {
                    bad(r.context, r.pos, "atom index overflow")
                })?))
            }
        }
        3 => Ok(Operand::X(register(u()?, r.context, r.pos)?)),
        4 => Ok(Operand::Y(register(u()?, r.context, r.pos)?)),
        5 => Ok(Operand::Label(
            u32::try_from(u()?).map_err(|_| bad(r.context, r.pos, "label overflow"))?,
        )),
        6 => {
            Ok(Operand::Char(u32::try_from(u()?).map_err(|_| {
                bad(r.context, r.pos, "character overflow")
            })?))
        }
        7 => {
            let sub = u()?;
            match sub {
                0 => Err(bad(r.context, r.pos, "obsolete inline float operand")),
                1 => {
                    let n = compact_u(r)? as usize;
                    if n > r.data.len() - r.pos {
                        return Err(bad(r.context, r.pos, "list count exceeds code"));
                    }
                    let mut items = Vec::with_capacity(n);
                    for _ in 0..n {
                        items.push(operand(r, atoms, literals, types, depth + 1)?);
                    }
                    Ok(Operand::List(Box::new(items)))
                }
                2 => Ok(Operand::FR(register(compact_u(r)?, r.context, r.pos)?)),
                3 => {
                    let n = compact_u(r)? as usize;
                    if n > (r.data.len() - r.pos) / 2 {
                        return Err(bad(r.context, r.pos, "allocation count exceeds code"));
                    }
                    let mut items = Vec::with_capacity(n);
                    for _ in 0..n {
                        let kind = match compact_u(r)? {
                            0 => AllocKind::Words,
                            1 => AllocKind::Floats,
                            2 => AllocKind::Funs,
                            _ => return Err(bad(r.context, r.pos, "invalid allocation kind")),
                        };
                        items.push(Allocation {
                            kind,
                            count: compact_u(r)?,
                        });
                    }
                    Ok(Operand::Alloc(Box::new(items)))
                }
                4 => {
                    let index = compact_u(r)?;
                    if index as usize >= literals {
                        return Err(bad(r.context, r.pos, "literal index out of range"));
                    }
                    Ok(Operand::Literal(u32::try_from(index).map_err(|_| {
                        bad(r.context, r.pos, "literal index overflow")
                    })?))
                }
                5 => {
                    let reg = operand(r, atoms, literals, types, depth + 1)?;
                    if !matches!(reg, Operand::X(_) | Operand::Y(_)) {
                        return Err(bad(r.context, r.pos, "typed operand requires register"));
                    }
                    let index = compact_u(r)?;
                    if let Some(table) = types
                        && index as usize >= table.entries.len()
                    {
                        return Err(bad(r.context, r.pos, "type index out of range"));
                    }
                    Ok(Operand::TypedReg {
                        reg: Box::new(reg),
                        type_index: u32::try_from(index)
                            .map_err(|_| bad(r.context, r.pos, "type index overflow"))?,
                    })
                }
                _ => Err(bad(r.context, r.pos, format!("unknown extended tag {sub}"))),
            }
        }
        _ => unreachable!(),
    }
}
// Port of erts/emulator/beam/beam_file.c:1511 (parse_code_chunk), OTP-29.1.1: the header; the
// instructions stay bytes.
fn parse_code_header(data: &[u8]) -> Result<CodeChunk, BeamError> {
    let mut r = Reader::new(data, "Code");
    let header_size = r.u32()?;
    let header_end = 4usize
        .checked_add(header_size as usize)
        .filter(|&end| end <= data.len())
        .ok_or_else(|| bad("Code", r.pos, "invalid header size"))?;
    if header_size < 16 {
        return Err(bad("Code", r.pos, "header too short"));
    }
    let instruction_set = r.u32()?;
    if instruction_set != BEAM_FORMAT_NUMBER {
        return Err(bad(
            "Code",
            r.pos,
            format!("unsupported instruction set {instruction_set}"),
        ));
    }
    let max_opcode = r.u32()?;
    let label_count = r.u32()?;
    let function_count = r.u32()?;
    if max_opcode > Opcode::COUNT as u32 {
        return Err(bad("Code", r.pos, "unsupported max opcode"));
    }
    Ok(CodeChunk {
        header_size,
        instruction_set,
        max_opcode,
        label_count,
        function_count,
        instructions: Vec::new(),
        bytes: data[header_end..].to_vec(),
    })
}

/// The instruction sequence of a Code chunk body (the bytes after its header).
fn decode_instructions(
    data: &[u8],
    max_opcode: u32,
    label_count: u32,
    function_count: u32,
    atoms: usize,
    literals: usize,
    types: Option<&TypeTable>,
) -> Result<Vec<Instr>, BeamError> {
    let mut r = Reader::new(data, "Code");
    let mut instructions = Vec::new();
    while r.pos < data.len() {
        let offset = r.pos;
        let byte = r.u8()?;
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
        let mut args = Vec::with_capacity(op.arity() as usize);
        for index in 0..op.arity() {
            let arg = operand(&mut r, atoms, literals, types, 0)?;
            if matches!(arg, Operand::List(_)) && index + 1 != op.arity() {
                return Err(bad("Code", offset, "list operand must be last"));
            }
            args.push(arg);
        }
        instructions.push(Instr { op, args, offset });
    }
    if !instructions
        .last()
        .is_some_and(|instr| instr.op == Opcode::IntCodeEnd)
    {
        return Err(bad("Code", r.pos, "missing final int_code_end"));
    }
    let actual_functions = instructions
        .iter()
        .filter(|instr| instr.op == Opcode::FuncInfo)
        .count();
    if actual_functions != function_count as usize {
        return Err(bad("Code", r.pos, "function count mismatch"));
    }
    for instr in &instructions {
        for arg in &instr.args {
            validate_labels(arg, label_count, instr.offset)?;
        }
    }
    Ok(instructions)
}

fn validate_labels(arg: &Operand, count: u32, offset: usize) -> Result<(), BeamError> {
    match arg {
        Operand::Label(n) if *n >= count => Err(bad("Code", offset, "label index out of range")),
        Operand::List(items) => {
            for item in items.iter() {
                validate_labels(item, count, offset)?;
            }
            Ok(())
        }
        Operand::TypedReg { reg, .. } => validate_labels(reg, count, offset),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_integer_and_extended_operands() {
        let mut r = Reader::new(&[0x19, 0xff, 0xff], "test");
        assert!(matches!(
            operand(&mut r, 0, 0, None, 0).unwrap(),
            Operand::Int(-1)
        ));
        let mut big = vec![0xf9, 0x00, 0x01];
        big.extend([0; 8]);
        let mut r = Reader::new(&big, "test");
        assert!(matches!(
            operand(&mut r, 0, 0, None, 0).unwrap(),
            Operand::BigInt(_)
        ));
        let mut r = Reader::new(&[0x17, 0x20, 0x03, 0x12], "test");
        assert!(
            matches!(operand(&mut r, 1, 0, None, 0).unwrap(), Operand::List(v) if v.len() == 2)
        );
        let mut r = Reader::new(&[0x57, 0x03, 0x00], "test");
        assert!(matches!(
            operand(&mut r, 0, 0, None, 0).unwrap(),
            Operand::TypedReg { type_index: 0, .. }
        ));
    }

    #[test]
    fn deprecated_opcode_error_names_instruction() {
        let mut code = Vec::new();
        for word in [16u32, 0, 191, 1, 0] {
            code.extend(word.to_be_bytes());
        }
        code.push(Opcode::AllocateZero as u8);
        let header = parse_code_header(&code).unwrap();
        let error = decode_instructions(&header.bytes, 191, 1, 0, 0, 0, None).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("deprecated opcode allocate_zero")
        );
    }

    #[test]
    fn nested_compact_length_is_rejected() {
        let bytes = [0xf8; 100];
        let mut r = Reader::new(&bytes, "test");
        assert!(compact(&mut r).is_err());
    }
}

/// Frame size recorded for a debug item.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DebugFrameSize {
    /// No frame (`none`).
    None,
    /// The frame has not been allocated yet (`entry`).
    Entry,
    /// Number of Y registers.
    Words(u32),
}

/// A variable name or value stored in a debug item.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DebugTerm {
    /// Small integer.
    Int(i64),
    /// One-based atom index.
    Atom(u32),
    /// The empty list.
    Nil,
    /// X register.
    X(u32),
    /// Y register.
    Y(u32),
    /// Zero-based literal index.
    Literal(u32),
}

/// One call recorded by a debug item.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DebugCall {
    /// `{Module, Function, Arity}`; module and function are atoms or variable-name literals.
    Remote(DebugTerm, DebugTerm, u32),
    /// `{Function, Arity}`.
    Local(DebugTerm, u32),
    /// Call of a variable, named by a literal binary.
    Variable(DebugTerm),
}

/// One entry of the `DbgB` chunk written by `+beam_debug_info`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DebugItem {
    /// Stack frame size at the instrumentation point.
    pub frame_size: DebugFrameSize,
    /// Variable names with the register or value holding each.
    pub vars: Vec<(DebugTerm, DebugTerm)>,
    /// Calls reachable from the instrumentation point.
    pub calls: Vec<DebugCall>,
}

const BEAM_DEBUG_INFO_VERSION: u32 = 1;
const MAX_ARG: u64 = 255;

impl BeamFile {
    /// Decodes the `DbgB` chunk. `None` when it is absent, has another version, or is malformed.
    // Port of erts/emulator/beam/beam_file.c:887-1057 (parse_debug_chunk_data), OTP-29.1.1.
    // erts rejects the whole module on a malformed chunk; here the chunk is ignored.
    pub fn debug_items(&self) -> Option<Vec<DebugItem>> {
        let (_, data) = self.other_chunks.iter().find(|(id, _)| id == b"DbgB")?;
        let mut r = Reader::new(data, "DbgB");
        if r.u32().ok()? != BEAM_DEBUG_INFO_VERSION {
            return None;
        }
        let mut count = i32::from_be_bytes(r.take(4).ok()?.try_into().ok()?);
        let mut total = i32::from_be_bytes(r.take(4).ok()?.try_into().ok()?);
        if count < 0 || total < 0 {
            return None;
        }
        let call_opcode = Opcode::Call as u8;
        let mut items: Vec<DebugItem> = Vec::new();
        let mut last_entry = i64::MAX;
        while count > 0 || total > 0 {
            if r.u8().ok()? != call_opcode {
                return None;
            }
            let entry =
                match operand(&mut r, self.atoms.len(), self.literals.len(), None, 0).ok()? {
                    Operand::U(entry) => i64::try_from(entry).ok()?,
                    _ => return None,
                };
            let argument = operand(&mut r, self.atoms.len(), self.literals.len(), None, 0).ok()?;
            if entry == 0 {
                if count == 0 {
                    return None;
                }
                count -= 1;
                last_entry = entry;
                let frame_size = match argument {
                    Operand::Nil => DebugFrameSize::None,
                    Operand::Atom(atom) if self.atom(atom) == Some("entry") => {
                        DebugFrameSize::Entry
                    }
                    Operand::U(words) => DebugFrameSize::Words(u32::try_from(words).ok()?),
                    _ => return None,
                };
                items.push(DebugItem {
                    frame_size,
                    vars: Vec::new(),
                    calls: Vec::new(),
                });
                continue;
            }
            if entry < last_entry {
                return None;
            }
            last_entry = entry;
            let Operand::List(terms) = argument else {
                return None;
            };
            total -= i32::try_from(terms.len()).ok()?;
            if total < 0 {
                return None;
            }
            let item = items.last_mut()?;
            match entry {
                1 => {
                    if terms.len() % 2 != 0 {
                        return None;
                    }
                    for pair in terms.chunks(2) {
                        let name = match &pair[0] {
                            Operand::Int(value) => DebugTerm::Int(*value),
                            Operand::U(value) => DebugTerm::Int(i64::try_from(*value).ok()?),
                            Operand::Literal(index) => DebugTerm::Literal(*index),
                            _ => return None,
                        };
                        item.vars.push((name, debug_value(&pair[1])?));
                    }
                }
                2 => item.calls = debug_calls(&terms)?,
                _ => {}
            }
        }
        Some(items)
    }
}

fn debug_value(operand: &Operand) -> Option<DebugTerm> {
    Some(match operand {
        Operand::Int(value) => DebugTerm::Int(*value),
        Operand::U(value) => DebugTerm::Int(i64::try_from(*value).ok()?),
        Operand::Atom(atom) => DebugTerm::Atom(*atom),
        Operand::Nil => DebugTerm::Nil,
        Operand::X(index) => DebugTerm::X(*index),
        Operand::Y(index) => DebugTerm::Y(*index),
        Operand::Literal(index) => DebugTerm::Literal(*index),
        _ => return None,
    })
}

// Port of erts/emulator/beam/beam_file.c:818-885 (parse_debug_chunk_calls) and
// beam_bif_load.c:1400-1440 (code_get_debug_info_1), OTP-29.1.1.
fn debug_calls(terms: &[Operand]) -> Option<Vec<DebugCall>> {
    let name = |operand: &Operand| match operand {
        Operand::Atom(atom) => Some(DebugTerm::Atom(*atom)),
        Operand::Literal(index) => Some(DebugTerm::Literal(*index)),
        _ => None,
    };
    let mut calls = Vec::new();
    let mut index = 0;
    while index < terms.len() {
        match &terms[index] {
            Operand::U(value) if *value <= MAX_ARG => {
                let module = name(terms.get(index + 1)?)?;
                let function = name(terms.get(index + 2)?)?;
                calls.push(DebugCall::Remote(module, function, *value as u32));
                index += 3;
            }
            Operand::U(value) if *value <= 2 * MAX_ARG + 1 => {
                let function = name(terms.get(index + 1)?)?;
                calls.push(DebugCall::Local(function, (*value - (MAX_ARG + 1)) as u32));
                index += 2;
            }
            other => {
                calls.push(DebugCall::Variable(name(other)?));
                index += 1;
            }
        }
    }
    Some(calls)
}
