use std::{env, fs, path::PathBuf};

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/otp-29.1.1");
    let genop = root.join("genop.tab");
    let bif = root.join("bif.tab");
    println!("cargo:rerun-if-changed={}", genop.display());
    println!("cargo:rerun-if-changed={}", bif.display());
    let ops = fs::read_to_string(genop).expect("genop.tab");
    let bifs = fs::read_to_string(bif).expect("bif.tab");
    let format_number: u32 = ops
        .lines()
        .find_map(|line| line.trim().strip_prefix("BEAM_FORMAT_NUMBER="))
        .expect("BEAM_FORMAT_NUMBER")
        .parse()
        .expect("format number");
    assert_eq!(format_number, 0, "unsupported BEAM format");
    let mut entries = Vec::new();
    for line in ops.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() || !line.as_bytes()[0].is_ascii_digit() {
            continue;
        }
        let (number, rest) = line.split_once(':').expect("opcode colon");
        let number: usize = number.parse().expect("opcode number");
        assert_eq!(number, entries.len() + 1, "opcodes must be contiguous");
        let rest = rest.trim();
        let deprecated = rest.starts_with('-');
        let (name, arity) = rest
            .trim_start_matches('-')
            .split_once('/')
            .expect("opcode arity");
        let arity: u8 = arity.trim().parse().expect("opcode arity integer");
        entries.push((name.trim().to_owned(), arity, deprecated));
    }
    assert_eq!(entries.len(), 191);
    let mut out = format!(
        "/// Generic BEAM instruction set identifier.\npub const BEAM_FORMAT_NUMBER: u32 = {format_number};\n"
    );
    out.push_str(&format!(
        "/// FNV-1a checksum of genop.tab.\npub const GENOP_TAB_HASH: &str = \"{:016x}\";\n",
        checksum(ops.as_bytes())
    ));
    out.push_str(&format!(
        "/// FNV-1a checksum of bif.tab.\npub const BIF_TAB_HASH: &str = \"{:016x}\";\n",
        checksum(bifs.as_bytes())
    ));
    out.push_str("/// An OTP 29.1.1 generic BEAM opcode.\n#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]\n#[repr(u8)]\npub enum Opcode {\n");
    for (i, (name, _, _)) in entries.iter().enumerate() {
        let variant = camel(name);
        out.push_str(&format!("    /// `{name}`.\n    {variant} = {},\n", i + 1));
    }
    out.push_str("}\nimpl Opcode {\n    /// Number of generic opcodes.\n    pub const COUNT: usize = 191;\n    /// Decode an opcode byte.\n    pub fn from_u8(n: u8) -> Option<Self> { Some(match n {\n");
    for (i, (name, _, _)) in entries.iter().enumerate() {
        out.push_str(&format!("        {} => Self::{},\n", i + 1, camel(name)));
    }
    out.push_str("        _ => return None,\n    }) }\n    /// Source mnemonic.\n    pub fn name(self) -> &'static str { match self {\n");
    for (name, _, _) in &entries {
        out.push_str(&format!("        Self::{} => {:?},\n", camel(name), name));
    }
    out.push_str(
        "    } }\n    /// Generic operand count.\n    pub fn arity(self) -> u8 { match self {\n",
    );
    for (name, arity, _) in &entries {
        out.push_str(&format!("        Self::{} => {arity},\n", camel(name)));
    }
    out.push_str("    } }\n    /// The loader rejects obsolete opcodes.\n    pub fn is_deprecated(self) -> bool { matches!(self,\n");
    let deprecated: Vec<_> = entries
        .iter()
        .filter(|e| e.2)
        .map(|e| format!("Self::{}", camel(&e.0)))
        .collect();
    out.push_str(&format!(
        "        {}\n    ) }}\n}}\n",
        deprecated.join(" | ")
    ));
    let mut bif_entries = Vec::new();
    for line in bifs.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<_> = line.split_whitespace().collect();
        assert!((2..=3).contains(&parts.len()), "bad bif line: {line}");
        let kind = match parts[0] {
            "bif" => "Bif",
            "ubif" => "Ubif",
            "hbif" => "Hbif",
            _ => panic!("bad bif kind"),
        };
        let (module, rest) = parts[1].split_once(':').expect("bif module");
        let (name, arity) = rest.rsplit_once('/').expect("bif arity");
        let name = name.trim_matches('\'');
        let arity: u8 = arity.parse().expect("bif arity integer");
        bif_entries.push((kind, module, name, arity, parts.get(2).copied()));
    }
    assert_eq!(bif_entries.len(), 553);
    out.push_str("/// BIFs in the original table order.\npub static BIFS: [BifSpec; 553] = [\n");
    for (i, (kind, module, name, arity, c_name)) in bif_entries.iter().enumerate() {
        let c_name = c_name.map_or("None".to_owned(), |s| format!("Some({s:?})"));
        out.push_str(&format!("    BifSpec {{ index: {i}, kind: BifKind::{kind}, module: {module:?}, name: {name:?}, arity: {arity}, c_name: {c_name} }},\n"));
    }
    out.push_str("];\n");
    let path = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR")).join("tables.rs");
    fs::write(path, out).expect("write tables");
}

fn camel(name: &str) -> String {
    name.split('_')
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect()
}

fn checksum(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf29ce484222325u64, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
    })
}
