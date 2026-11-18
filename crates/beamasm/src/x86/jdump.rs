//! Test support: erts 29.1.1's own x86 code (`erl +JDdump true`) and GNU `as`, the reference
//! the x86 emitters are byte-compared against (docs/design/x86_ibox_guide.md).

use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The directory holding the `.asm` files of `erl +JDdump true -noshell -eval 'halt().'`,
/// shared by all test processes: the first one dumps into a private directory and renames it
/// into place. `None` without `erl`.
fn dump_dir() -> Option<&'static PathBuf> {
    static DIR: OnceLock<Option<PathBuf>> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = std::env::temp_dir().join("arinsal-x86-jdump-otp29");
        if dir.join("beam_asm_global.asm").exists() {
            return Some(dir);
        }
        let private =
            std::env::temp_dir().join(format!("arinsal-x86-jdump-{}", std::process::id()));
        std::fs::create_dir_all(&private).ok()?;
        let dumped = Command::new("erl")
            .args(["+JDdump", "true", "-noshell", "-eval", "halt()."])
            .current_dir(&private)
            .status()
            .is_ok_and(|status| status.success());
        // Another process may have won the rename; its dump is the same.
        if !dumped || std::fs::rename(&private, &dir).is_err() {
            let _ = std::fs::remove_dir_all(&private);
        }
        dir.join("beam_asm_global.asm").exists().then_some(dir)
    })
    .as_ref()
}

/// The `<module>.asm` erts emitted for a module loaded at boot (`lists`, `beam_asm_global`, ...).
pub(crate) fn erts_dump(module: &str) -> Option<String> {
    // Atom and string comments may hold bytes that are not UTF-8.
    let bytes = std::fs::read(dump_dir()?.join(format!("{module}.asm"))).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// The instruction lines of every `# <op>` block in a module dump. A block ends at the next
/// instruction header or label; `# comment text` lines inside it are dropped.
pub(crate) fn op_blocks(dump: &str, op: &str) -> Vec<Vec<String>> {
    let is_header = |line: &str| {
        line.strip_prefix("# ").is_some_and(|name| {
            !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
    };
    let mut blocks = Vec::new();
    let mut current: Option<Vec<String>> = None;
    for line in dump.lines() {
        if is_header(line) || (!line.starts_with(' ') && !line.starts_with('#')) {
            blocks.extend(current.take());
            if line == format!("# {op}") {
                current = Some(Vec::new());
            }
        } else if let Some(block) = current.as_mut()
            && !line.starts_with('#')
        {
            block.push(line.trim().to_string());
        }
    }
    blocks.extend(current);
    blocks
}

static SEQ: AtomicUsize = AtomicUsize::new(0);

/// Assembles erts' Intel-syntax dump `lines` with GNU `as`; `None` without binutils. asmjit's
/// `long` prefix (forced imm64) is spelled `movabs`.
pub(crate) fn gnu_as(lines: &[String]) -> Option<Vec<u8>> {
    let dir = std::env::temp_dir().join(format!(
        "arinsal-x86-as-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).ok()?;
    let text: Vec<String> = lines
        .iter()
        .map(|l| {
            l.replace("long mov ", "movabs ")
                .trim_start_matches("rex ")
                .to_string()
        })
        .collect();
    let src = format!(".intel_syntax noprefix\n.text\n{}\n", text.join("\n"));
    let (s, o, bin) = (dir.join("f.s"), dir.join("f.o"), dir.join("f.bin"));
    std::fs::write(&s, src).ok()?;
    let ok = |cmd: &mut Command| cmd.status().map(|s| s.success()).unwrap_or(false);
    let built = ok(Command::new("as").arg("--64").arg("-o").arg(&o).arg(&s))
        && ok(Command::new("objcopy")
            .args(["-O", "binary", "-j", ".text"])
            .arg(&o)
            .arg(&bin));
    let bytes = if built {
        std::fs::read(&bin).ok()
    } else {
        None
    };
    let _ = std::fs::remove_dir_all(&dir);
    bytes
}

/// The X or Y register a dump operand `qword ptr [rbx+N]` / `[rsp+N]` addresses.
pub(crate) fn beam_register(operand: &str) -> Option<crate::common::args::ArgVal> {
    use crate::common::args::ArgVal;
    let inner = operand.strip_prefix("qword ptr [")?.strip_suffix(']')?;
    let (base, disp) = match inner.split_once('+') {
        Some((base, disp)) => (base, disp.parse::<u32>().ok()?),
        None => (inner, 0),
    };
    if disp % 8 != 0 {
        return None;
    }
    match base {
        "rbx" => Some(ArgVal::X(disp / 8)),
        "rsp" => Some(ArgVal::Y(disp / 8)),
        _ => None,
    }
}
