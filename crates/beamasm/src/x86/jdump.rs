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

/// Emits old-style BEAM instructions that OTP 29's compiler no longer generates.
pub(crate) fn generated_misc_emitters_dump() -> Option<String> {
    static DUMP: OnceLock<Option<String>> = OnceLock::new();
    DUMP.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!(
            "arinsal-x86-jdump-misc-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).ok()?;
        let set_tuple_eval = concat!(
            "M=arinsal_port_misc_fixture,",
            "Forms=[{attribute,1,module,M},{attribute,1,export,[{f,0}]},",
            "{function,1,f,0,[{clause,1,[],[],[{integer,1,1}]}]}],",
            "{ok,M,{M,Ex,Attr,Anno,Fs,NL}}=compile:forms(Forms,[to_asm]),",
            "Fs1=[case F of {function,f,0,Entry,Ins}->",
            "{function,f,0,Entry,lists:sublist(Ins,length(Ins)-1)++",
            "[{set_tuple_element,{x,0},{x,1},1},return]}; _->F end || F<-Fs],",
            "{ok,B}=beam_asm:module({M,Ex,Attr,Anno,Fs1,NL},[],[],[]),",
            "{module,M}=code:load_binary(M,\"fixture.beam\",B),halt()."
        );
        let debug_line_eval = concat!(
            "M=arinsal_port_debug_line_fixture,",
            "Forms=[{attribute,1,module,M},{attribute,1,export,[{f,2}]},",
            "{function,1,f,2,[{clause,1,[{var,1,'X'},{var,1,'Y'}],[],[{integer,1,1}]}]}],",
            "{ok,M,{M,Ex,Attr,Anno,Fs,NL}}=compile:forms(Forms,[to_asm]),",
            "Fs1=[case F of {function,f,2,Entry,Ins}->",
            "{function,f,2,Entry,lists:sublist(Ins,length(Ins)-1)++",
            "[{debug_line,{atom,am_line},[{location,\"fixture.erl\",1}],1,2,[]},return]};",
            "_ -> F end || F<-Fs],",
            "{ok,B}=beam_asm:module({M,Ex,Attr,Anno,Fs1,NL},[],[],[]),",
            "code:load_binary(M,\"debug_line.beam\",B),halt()."
        );
        let compare_eval = concat!(
            "M2=arinsal_port_compare_fixture,",
            "Forms2=[{attribute,1,module,M2},{attribute,1,export,[{f,2}]},",
            "{function,1,f,2,[{clause,1,[{var,1,'X'},{var,1,'Y'}],[],[{integer,1,1}]}]}],",
            "{ok,M2,{M2,Ex2,Attr2,Anno2,Fs2,NL2}}=compile:forms(Forms2,[to_asm]),",
            "Fs3=[case F of {function,f,2,Entry,Ins}->",
            "{function,f,2,Entry,lists:sublist(Ins,length(Ins)-1)++",
            "[{is_eq,{f,3},{x,0},{x,1}},return,{label,3},return]}; _->F end || F<-Fs2],",
            "{ok,B2}=beam_asm:module({M2,Ex2,Attr2,Anno2,Fs3,NL2},[],[],[]),",
            "code:load_binary(M2,\"compare.beam\",B2),halt()."
        );
        let i_get_eval = concat!(
            "M=arinsal_port_i_get_fixture,",
            "Forms=[{attribute,1,module,M},{attribute,1,export,[{f,1}]},",
            "{function,1,f,1,[{clause,1,[{var,1,'Key'}],[],",
            "[{call,1,{remote,1,{atom,1,erlang},{atom,1,get}},[{var,1,'Key'}]}]}]}],",
            "{ok,M,{M,Ex,Attr,Anno,Fs,NL}}=compile:forms(Forms,[to_asm]),",
            "{ok,B}=beam_asm:module({M,Ex,Attr,Anno,Fs,NL},[],[],[]),",
            "{module,M}=code:load_binary(M,\"i_get.beam\",B),halt()."
        );
        let run = |options: &[&str], eval: &str| {
            Command::new("timeout")
                .args(["30", "erl", "+JDdump", "true"])
                .args(options)
                .args(["-noshell", "-eval", eval])
                .current_dir(&dir)
                .output()
        };
        let set_tuple_output = run(&[], set_tuple_eval).ok()?;
        assert!(
            set_tuple_output.status.success(),
            "OTP failed to emit the set_tuple_element fixture: {}",
            String::from_utf8_lossy(&set_tuple_output.stderr)
        );
        let debug_line_output = run(&["+D", "+Dibpl", "true"], debug_line_eval).ok()?;
        assert!(
            debug_line_output.status.success(),
            "OTP failed to emit the debug_line fixture: {}",
            String::from_utf8_lossy(&debug_line_output.stderr)
        );
        let compare_output = run(&[], compare_eval).ok()?;
        assert!(
            compare_output.status.success(),
            "OTP failed to emit the comparison fixture: {}",
            String::from_utf8_lossy(&compare_output.stderr)
        );
        let i_get_output = run(&[], i_get_eval).ok()?;
        assert!(
            i_get_output.status.success(),
            "OTP failed to emit the process dictionary fixture: {}",
            String::from_utf8_lossy(&i_get_output.stderr)
        );
        let first = std::fs::read(dir.join("arinsal_port_misc_fixture.asm")).ok()?;
        let debug_line = std::fs::read(dir.join("arinsal_port_debug_line_fixture.asm")).ok()?;
        let second = std::fs::read(dir.join("arinsal_port_compare_fixture.asm")).unwrap_or_else(|error| {
            panic!(
                "OTP did not dump comparison fixture ({error}); status {:?}; stdout: {}; stderr: {}",
                compare_output.status,
                String::from_utf8_lossy(&compare_output.stdout),
                String::from_utf8_lossy(&compare_output.stderr)
            )
        });
        let i_get = std::fs::read(dir.join("arinsal_port_i_get_fixture.asm")).ok()?;
        let _ = std::fs::remove_dir_all(&dir);
        Some(format!(
            "{}\n{}\n{}\n{}",
            String::from_utf8_lossy(&first),
            String::from_utf8_lossy(&debug_line),
            String::from_utf8_lossy(&second),
            String::from_utf8_lossy(&i_get)
        ))
    })
    .clone()
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

fn asmjit_compact_qword_cmp(line: &str) -> Option<String> {
    use arinsal_x64::enc::{
        R8, R9, R10, R11, R12, R13, R14, R15, RAX, RBP, RBX, RCX, RDI, RDX, RSI, RSP, qword_ptr,
    };
    let operands = line.strip_prefix("cmp qword ptr [")?;
    let (address, immediate) = operands.split_once("], ")?;
    let immediate = immediate.parse::<i64>().ok()?;
    i8::try_from(immediate).ok()?;
    let (base, disp) = match address.split_once('+') {
        Some((base, disp)) => (base, disp.parse::<i32>().ok()?),
        None => (address, 0),
    };
    let base = match base {
        "rax" => RAX,
        "rbx" => RBX,
        "rcx" => RCX,
        "rdx" => RDX,
        "rsp" => RSP,
        "rbp" => RBP,
        "rsi" => RSI,
        "rdi" => RDI,
        "r8" => R8,
        "r9" => R9,
        "r10" => R10,
        "r11" => R11,
        "r12" => R12,
        "r13" => R13,
        "r14" => R14,
        "r15" => R15,
        _ => return None,
    };
    let mut assembler = crate::x86::beam_asm::BeamAssembler::new();
    assembler
        .emit(|e| e.cmp_mi(qword_ptr(base, disp), immediate))
        .ok()?;
    Some(format!(
        ".byte {}",
        assembler
            .a
            .bytes(arinsal_x64::buf::Section::Code)
            .iter()
            .map(|byte| format!("{byte:#04x}"))
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

/// Rewrites one erts dump line to Arinsal's layouts: `Process` fields (`[r13+N]`) and the
/// scheduler registers' auxiliary area (`[rbx-N]`: erts' `runtime_stack` is at -64 and
/// `TMP_MEM1..5` follow it; Arinsal's start at -128).
pub(crate) fn erts_to_arinsal(line: &str) -> String {
    use crate::x86::beam_asm::{get_runtime_stack_ref, tmp_mem_q_disp};
    let mut line = asmjit_size_optimized(line.trim_start_matches("rex "))
        .replace(".db ", ".byte ")
        // asmjit's explicit no-base marker has no GNU `as` spelling.
        .replace("[abs ", "[");
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
    asmjit_compact_qword_cmp(&line).unwrap_or(line)
}

fn branch_placeholder(op: &str, fill: u8) -> String {
    let op = op.strip_prefix("{disp32} ").unwrap_or(op);
    let (short, condition) = if let Some(jump) = op.strip_prefix("short j") {
        (true, jump)
    } else if let Some(jump) = op.strip_prefix("j") {
        (false, jump)
    } else {
        (false, op)
    };
    let condition = match condition {
        "mp" => None,
        "o" => Some(0),
        "no" => Some(1),
        "b" | "c" | "nae" => Some(2),
        "ae" | "nb" | "nc" => Some(3),
        "e" | "z" => Some(4),
        "ne" | "nz" => Some(5),
        "be" | "na" => Some(6),
        "a" | "nbe" => Some(7),
        "s" => Some(8),
        "ns" => Some(9),
        "p" | "pe" => Some(10),
        "np" | "po" => Some(11),
        "l" | "nge" => Some(12),
        "ge" | "nl" => Some(13),
        "le" | "ng" => Some(14),
        "g" | "nle" => Some(15),
        _ => None,
    };
    let (opcode, width): (Vec<u8>, usize) = match (short, condition) {
        (_, None) if op == "call" => (vec![0xe8], 4),
        (_, None) if op == "jmp" => (vec![0xe9], 4),
        (true, None) if op == "short jmp" => (vec![0xeb], 1),
        (true, Some(cc)) => (vec![0x70 | cc], 1),
        (false, Some(cc)) => (vec![0x0f, 0x80 | cc], 4),
        _ => panic!("unknown jump `{op}`"),
    };
    let bytes = opcode
        .into_iter()
        .chain(std::iter::repeat_n(fill, width))
        .map(|byte| format!("{byte:#04x}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!(".byte {bytes}")
}

/// Compares `ours` with erts' assembler text, ignoring out-of-span branch relocations,
/// absolute runtime-call targets and process-local atom indices. `None` without binutils.
pub(crate) fn matches_with_global_jumps(
    lines: &[String],
    ours: &[u8],
    unbound: &[&str],
) -> Option<bool> {
    matches_with_global_jumps_at(lines, ours, unbound, 0)
}

/// Compares a module instruction at its real code-section offset, preserving erts' alignment.
pub(crate) fn matches_with_global_jumps_at(
    lines: &[String],
    ours: &[u8],
    unbound: &[&str],
    code_offset: usize,
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
    let labels: std::collections::HashSet<&str> = lines
        .iter()
        .filter_map(|line| line.strip_suffix(':'))
        .collect();
    let external_label = lines.iter().any(|line| {
        let Some((_, target)) = line.rsplit_once(' ') else {
            return false;
        };
        (target.starts_with('L') || target.starts_with("label_")) && !labels.contains(target)
    });
    let placeholder = |fill: u8, all_near: bool, atom_variant: usize| -> Vec<String> {
        normalized
            .iter()
            .map(|line| {
                // Atom table indices are process-local. Keep the two tag bytes fixed and vary
                // only the index bits while comparing the x86 instruction encoding.
                if let Some((instruction, immediate)) = line.split_once(", ")
                    && (instruction.starts_with("mov ") || instruction.starts_with("cmp "))
                    && let Ok(value) = immediate.parse::<u32>()
                    && value & 0x3f == 0x0b
                {
                    let index_bits = match atom_variant {
                        0 => 0x80,
                        1 => 0x7fff_ffc0 & !0x80,
                        2 => 0x100,
                        _ => unreachable!(),
                    };
                    let value = (value & 0x3f) | index_bits;
                    return format!("{instruction}, {value}");
                }
                if line.contains("ptr [rip + 0]") && fill != 0 {
                    return line.replace("ptr [rip + 0]", "ptr [rip - 1]");
                }
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
                if let Some((op, target)) = line.split_once(" global::") {
                    // A fragment Arinsal does not emit yet is unbound here, so asmjit's rule gives
                    // the near form where erts reached it backward with rel8; with fragments
                    // missing, the layout also moves bound targets out of rel8 reach
                    // (`all_near`).
                    let op = match op.strip_prefix("short ") {
                        Some(near) if all_near || unbound.contains(&target) => near,
                        _ => op,
                    };
                    return branch_placeholder(op, fill);
                }
                let (prefix, operation) = match line.strip_prefix("{disp32} ") {
                    Some(near) => ("{disp32} ", near),
                    None => ("", line.as_str()),
                };
                let Some((op, target)) = operation.split_once(' ') else {
                    return line.clone();
                };
                if (op != "call" && !op.starts_with('j'))
                    || !(target.starts_with('L') || target.starts_with("label_"))
                    || labels.contains(target)
                {
                    return line.clone();
                }
                let op = match op.strip_prefix("short ") {
                    Some(near) if all_near => near,
                    _ => op,
                };
                let op = format!("{prefix}{op}");
                branch_placeholder(&op, fill)
            })
            .collect()
    };
    let matches = |all_near: bool| -> Option<bool> {
        let assemble = |fill, atom_variant| {
            let mut lines = placeholder(fill, all_near, atom_variant);
            if code_offset != 0 {
                lines.insert(0, format!(".fill {code_offset}, 1, 0"));
            }
            let bytes = gnu_as(&lines)?;
            Some(bytes.get(code_offset..)?.to_vec())
        };
        let baseline = assemble(0, 0)?;
        let mut varying_bits = vec![0; baseline.len()];
        for atom_variant in 0..3 {
            for fill in [0, 0xff] {
                let bytes = assemble(fill, atom_variant)?;
                if bytes.len() != baseline.len() {
                    return Some(false);
                }
                for (mask, (base, byte)) in varying_bits.iter_mut().zip(baseline.iter().zip(bytes))
                {
                    *mask |= base ^ byte;
                }
            }
        }
        let matched = ours.len() == baseline.len()
            && ours
                .iter()
                .zip(baseline.iter().zip(&varying_bits))
                .all(|(ours, (base, mask))| (ours ^ base) & !mask == 0);
        Some(matched)
    };
    Some(matches(false)? || ((!unbound.is_empty() || external_label) && matches(true)?))
}
