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

/// erts 29.1.1 x86-64 `Process` field offsets in the dumps (`[r13+N]`), with Arinsal's
/// `ProcessHeader` offset of the same field.
pub(crate) const ERTS_PROCESS_OFFSETS: [(i32, i32); 18] = {
    use crate::x86::beam_asm::process;
    [
        (0, process::SELF_PID),
        (80, process::HTOP),
        (88, process::STOP),
        (104, process::FREASON),
        (112, process::FVALUE),
        (120, process::FCALLS),
        (133, process::ARITY),
        (248, process::I),
        (288, process::FTRACE),
        (464, process::CURRENT),
        (96, process::HEAP),
        (256, process::CATCHES),
        (124, process::FLAGS),
        (528, process::OFF_HEAP_OVERHEAD),
        (544, process::MBUF),
        (568, process::MBUF_SZ),
        (584, process::BIN_VHEAP_SZ),
        (
            488,
            core::mem::offset_of!(crate::ProcessHeader, high_water) as i32,
        ),
    ]
};

/// asmjit's `kOptimizeForSize` choices the dump text does not show (x86assembler.cpp,
/// kEncodingX86Arith and kEncodingX86Mov): `and r64, imm` and `mov r64, imm` with an unsigned
/// 32-bit immediate are encoded with the 32-bit register, which zero-extends.
fn asmjit_size_optimized(line: &str) -> String {
    const R64: [(&str, &str); 16] = [
        ("rax", "eax"),
        ("rcx", "ecx"),
        ("rdx", "edx"),
        ("rbx", "ebx"),
        ("rsp", "esp"),
        ("rbp", "ebp"),
        ("rsi", "esi"),
        ("rdi", "edi"),
        ("r8", "r8d"),
        ("r9", "r9d"),
        ("r10", "r10d"),
        ("r11", "r11d"),
        ("r12", "r12d"),
        ("r13", "r13d"),
        ("r14", "r14d"),
        ("r15", "r15d"),
    ];
    let Some((op, operands)) = line.split_once(' ') else {
        return line.to_string();
    };
    let Some((dst, imm)) = operands.split_once(", ") else {
        return line.to_string();
    };
    if (op == "and" || op == "mov")
        && imm.parse::<u32>().is_ok()
        && let Some((_, r32)) = R64.iter().find(|(r64, _)| *r64 == dst)
    {
        return format!("{op} {r32}, {imm}");
    }
    line.to_string()
}

/// Rewrites one erts dump line to Arinsal's layouts: `Process` fields (`[r13+N]`) and the
/// scheduler registers' auxiliary area (`[rbx-N]`: erts' `runtime_stack` is at -64 and
/// `TMP_MEM1..5` follow it; Arinsal's start at -128).
pub(crate) fn erts_to_arinsal(line: &str) -> String {
    use crate::x86::beam_asm::{get_runtime_stack_ref, tmp_mem_q_disp};
    let mut line = asmjit_size_optimized(line.trim_start_matches("rex ")).replace(".db ", ".byte ");
    // A short jump to a local label: GNU `as` picks rel8 itself for a label in reach.
    if line.starts_with("short j") && !line.contains("global::") {
        line = line.trim_start_matches("short ").to_string();
    } else if line.starts_with('j') && line.contains(" L") && !line.starts_with("jmp r") {
        // asmjit's dump marks every rel8 jump `short`; any other local jump is rel32, which
        // GNU `as` would relax to rel8 when in reach.
        line = format!("{{disp32}} {line}");
    }
    for (erts, ours) in ERTS_PROCESS_OFFSETS {
        let from = if erts == 0 {
            "[r13]".to_string()
        } else {
            format!("[r13+{erts}]")
        };
        if line.contains(&from) {
            line = line.replace(&from, &format!("[r13+{ours}]"));
            break;
        }
    }
    let aux = |disp: i32| format!("[rbx{disp}]");
    if line.contains(&aux(-64)) {
        line = line.replace(&aux(-64), &aux(get_runtime_stack_ref().disp));
    }
    for index in 0..5u32 {
        let erts = -56 + 8 * index as i32;
        if line.contains(&aux(erts)) {
            line = line.replace(&aux(erts), &aux(tmp_mem_q_disp(index)));
            break;
        }
    }
    // `aux_regs.d.erl_bits_state` follows TMP_MEM5.
    if line.contains(&aux(-16)) {
        line = line.replace(&aux(-16), &aux(crate::ERL_BITS_STATE_DISP));
    }
    line
}

/// Compares `ours` with erts' fragment text, ignoring the displacements of jumps to other
/// fragments (`jmp global::x`, `short jmp global::x`, `jz global::x`), whose targets lie
/// elsewhere in each layout. `None` without binutils.
pub(crate) fn matches_with_global_jumps(
    lines: &[String],
    ours: &[u8],
    unbound: &[&str],
) -> Option<bool> {
    // `emit_leave_runtime<eCodeIndex>` loads `the_active_code_index` by its process-local
    // address. This symbol moves between the short-lived reference `erl` and this test process.
    let active_code_index = &raw const crate::x86::rt::the_active_code_index as u64;
    let normalized: Vec<String> = lines
        .iter()
        .enumerate()
        .map(|(index, line)| {
            if line.starts_with("mov rdi, ")
                && lines
                    .get(index + 1)
                    .is_some_and(|next| next == "mov edi, dword ptr [rdi]")
            {
                format!("movabs rdi, {active_code_index}")
            } else {
                line.clone()
            }
        })
        .collect();
    let placeholder = |fill: u8, all_near: bool| -> Vec<String> {
        normalized
            .iter()
            .map(|line| {
                // `runtime_call` / `abs_jmp`: asmjit's 6-byte `REX call/jmp rel32` to an
                // absolute address, relocated at load; the address is erts' own.
                if let Some((op, target)) = line.split_once(' ')
                    && (op == "call" || op == "jmp")
                    && target.parse::<u64>().is_ok()
                {
                    let opcode = if op == "call" { 0xe8 } else { 0xe9 };
                    return format!(
                        ".byte 0x40, {opcode:#04x}, {fill:#04x}, {fill:#04x}, {fill:#04x}, {fill:#04x}"
                    );
                }
                let Some((op, target)) = line.split_once(" global::") else {
                    return line.clone();
                };
                // A fragment Arinsal does not emit yet is unbound here, so asmjit's rule gives
                // the near form where erts reached it backward with rel8; with fragments
                // missing, the layout also moves bound targets out of rel8 reach
                // (`all_near`).
                let op = match op.strip_prefix("short ") {
                    Some(near) if all_near || unbound.contains(&target) => near,
                    _ => op,
                };
                let condition = match op.strip_prefix("short ").unwrap_or(op) {
                    "jo" => 0x80,
                    "jno" => 0x81,
                    "jb" | "jc" | "jnae" => 0x82,
                    "jae" | "jnb" | "jnc" => 0x83,
                    "je" | "jz" => 0x84,
                    "jne" | "jnz" => 0x85,
                    "jbe" | "jna" => 0x86,
                    "ja" | "jnbe" => 0x87,
                    "js" => 0x88,
                    "jns" => 0x89,
                    "jp" | "jpe" => 0x8a,
                    "jnp" | "jpo" => 0x8b,
                    "jl" | "jnge" => 0x8c,
                    "jge" | "jnl" => 0x8d,
                    "jle" | "jng" => 0x8e,
                    "jg" | "jnle" => 0x8f,
                    _ => 0,
                };
                let opcode: Vec<u8> = if op == "short jmp" {
                    vec![0xeb]
                } else if op == "call" {
                    vec![0xe8]
                } else if op == "jmp" {
                    vec![0xe9]
                } else if op.starts_with("short ") {
                    // The short-branch opcode is 0x70 + the low four condition bits.
                    vec![0x70 + (condition - 0x80)]
                } else if condition != 0 {
                    vec![0x0f, condition]
                } else {
                    panic!("unknown jump `{op}`")
                };
                let width = if op.starts_with("short") { 1 } else { 4 };
                let bytes: Vec<String> = opcode
                    .iter()
                    .copied()
                    .chain(std::iter::repeat_n(fill, width))
                    .map(|b| format!("{b:#04x}"))
                    .collect();
                format!(".byte {}", bytes.join(", "))
            })
            .collect()
    };
    let matches = |all_near: bool| -> Option<bool> {
        let zeros = gnu_as(&placeholder(0, all_near))?;
        let ones = gnu_as(&placeholder(0xff, all_near))?;
        Some(
            ours.len() == zeros.len()
                && ours
                    .iter()
                    .zip(zeros.iter().zip(&ones))
                    .all(|(o, (z, f))| z != f || o == z),
        )
    };
    Some(matches(false)? || (!unbound.is_empty() && matches(true)?))
}
