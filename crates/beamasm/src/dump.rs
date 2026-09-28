//! Optional machine-code dump support for assembled BeamAsm modules.

use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

/// A BEAM operation and the byte range emitted for it.
#[derive(Clone, Debug)]
pub struct InstructionRecord {
    /// Operation name and its specialized operands.
    pub text: String,
    /// Inclusive start byte offset in the module.
    pub start: usize,
    /// Exclusive end byte offset in the module.
    pub end: usize,
}

/// A function and its recorded BEAM operation ranges.
#[derive(Clone, Debug)]
pub struct FunctionRecord {
    /// BEAM function name.
    pub name: String,
    /// Function arity.
    pub arity: u8,
    /// Recorded operations in emission order.
    pub instructions: Vec<InstructionRecord>,
}

/// Failure while creating an optional assembler dump.
#[derive(Debug)]
pub struct DumpError(String);

impl std::fmt::Display for DumpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DumpError {}

impl From<io::Error> for DumpError {
    fn from(error: io::Error) -> Self {
        Self(error.to_string())
    }
}

/// Writes a raw code image, operation offset map, and annotated AArch64 listing.
pub fn write_module(
    directory: &Path,
    module: &str,
    functions: &[FunctionRecord],
    bytes: &[u8],
) -> Result<(), DumpError> {
    fs::create_dir_all(directory)?;
    let base = safe_module_name(module)?;
    fs::write(directory.join(format!("{base}.bin")), bytes)?;
    let decoded = disassemble(bytes)?;
    let mut listing = String::new();
    let mut offsets = String::new();
    let mut covered = BTreeMap::new();

    for function in functions {
        listing.push_str(&format!(
            "# {module}:{}/{}\n",
            function.name, function.arity
        ));
        for instruction in &function.instructions {
            listing.push_str(&format!("# {}\n", instruction.text));
            offsets.push_str(&format!(
                "{}:{}/{}  {}..{}  {}\n",
                function.name,
                function.arity,
                module,
                instruction.start,
                instruction.end,
                instruction.text
            ));
            let mut offset = instruction.start;
            while offset.saturating_add(4) <= instruction.end {
                if let Some((word, mnemonic)) = decoded.get(&offset) {
                    listing.push_str(&format!("    {offset:08x}: {word}  {mnemonic}\n"));
                    covered.insert(offset, (word.clone(), mnemonic.clone()));
                }
                offset += 4;
            }
        }
    }

    if covered.len() * 4 < bytes.len() {
        listing.push_str("# assembler epilogue and unassociated code\n");
        for (&offset, (word, mnemonic)) in &decoded {
            if !covered.contains_key(&offset) {
                listing.push_str(&format!("    {offset:08x}: {word}  {mnemonic}\n"));
            }
        }
    }

    fs::write(directory.join(format!("{base}.map")), offsets)?;
    fs::write(directory.join(format!("{base}.asm")), listing)?;
    Ok(())
}

/// Creates the required shared-fragment note once when no read-only code image is exposed.
pub fn write_global_note(directory: &Path) -> Result<(), DumpError> {
    fs::create_dir_all(directory)?;
    let path = directory.join("global.asm");
    let mut file = match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    file.write_all(b"# Shared runtime fragments are not exposed as a read-only code image; only their executable entry addresses are available.\n")?;
    Ok(())
}

fn safe_module_name(module: &str) -> Result<&str, DumpError> {
    if !module
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'@')
    {
        return Err(DumpError("invalid module name for dump path".to_owned()));
    }
    Ok(module)
}

fn disassemble(bytes: &[u8]) -> Result<BTreeMap<usize, (String, String)>, DumpError> {
    let temp = TempDirectory::new()?;
    let assembly = temp.path.join("code.s");
    let object = temp.path.join("code.o");
    let mut source = String::from(
        ".section __TEXT,__text,regular,pure_instructions\n.globl _arinsal_dump\n_arinsal_dump:\n",
    );
    for chunk in bytes.chunks(16) {
        source.push_str(".byte ");
        for (index, byte) in chunk.iter().enumerate() {
            if index != 0 {
                source.push_str(", ");
            }
            source.push_str(&format!("0x{byte:02x}"));
        }
        source.push('\n');
    }
    fs::write(&assembly, source)?;
    let clang = Command::new("clang")
        .args(["-target", "arm64-apple-macos", "-c"])
        .arg(&assembly)
        .arg("-o")
        .arg(&object)
        .output()?;
    if !clang.status.success() {
        return Err(DumpError(format!(
            "clang could not wrap dump bytes: {}",
            String::from_utf8_lossy(&clang.stderr).trim()
        )));
    }
    let objdump = Command::new("/usr/bin/objdump")
        .args(["-D", "--disassemble-zeroes", "--arch=arm64"])
        .arg(&object)
        .output()?;
    if !objdump.status.success() {
        return Err(DumpError(format!(
            "objdump could not disassemble dump bytes: {}",
            String::from_utf8_lossy(&objdump.stderr).trim()
        )));
    }
    Ok(parse_disassembly(&String::from_utf8_lossy(&objdump.stdout)))
}

fn parse_disassembly(output: &str) -> BTreeMap<usize, (String, String)> {
    let mut decoded = BTreeMap::new();
    for line in output.lines() {
        let Some((address, rest)) = line.trim().split_once(':') else {
            continue;
        };
        let Ok(address) = usize::from_str_radix(address.trim(), 16) else {
            continue;
        };
        let mut fields = rest.split_whitespace();
        let Some(word) = fields.next() else { continue };
        if word.len() != 8 || !word.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            continue;
        }
        let mnemonic = fields.collect::<Vec<_>>().join(" ");
        decoded.insert(address, (word.to_owned(), mnemonic));
    }
    decoded
}

struct TempDirectory {
    path: PathBuf,
}

impl TempDirectory {
    fn new() -> Result<Self, DumpError> {
        for _ in 0..8 {
            let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "arinsal-beamasm-dump-{}-{serial}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(DumpError(
            "could not allocate temporary dump directory".to_owned(),
        ))
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::parse_disassembly;

    #[test]
    fn parses_llvm_arm64_disassembly_lines() {
        let decoded = parse_disassembly(
            "       0: d65f03c0      ret\n       4: 910043e0      add x0, sp, #0x10\n",
        );
        assert_eq!(decoded[&0], ("d65f03c0".to_owned(), "ret".to_owned()));
        assert_eq!(decoded[&4].1, "add x0, sp, #0x10");
    }
}
