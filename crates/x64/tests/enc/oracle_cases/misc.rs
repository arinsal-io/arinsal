//! Exchange, locked increment, string, trap, NOP, and alignment cases.

use super::*;

type XchgR = fn(&mut Emitter, Gp, Gp) -> Result<(), EncodeError>;
type XchgRm = fn(&mut Emitter, Gp, Mem) -> Result<(), EncodeError>;
type XchgMr = fn(&mut Emitter, Mem, Gp) -> Result<(), EncodeError>;

pub fn cases(out: &mut Vec<OCase>) {
    out.push(case("bt ax, r13w", |e| e.bt_rr(AX, R13W)));
    out.push(case("bt r9d, r11d", |e| e.bt_rr(R9D, R11D)));
    out.push(case("bt r15, rcx", |e| e.bt_rr(R15, RCX)));
    out.push(case("bt rax, 3", |e| e.bt_ri(RAX, 3)));
    out.push(case("bt ax, 7", |e| e.bt_ri(AX, 7)));
    out.push(case("bt r9, 31", |e| e.bt_ri(R9, 31)));
    out.push(case("bt r15, 63", |e| e.bt_ri(R15, 63)));
    let xchg_rr: XchgR = Emitter::xchg_rr;
    let xchg_rm: XchgRm = Emitter::xchg_rm;
    let xchg_mr: XchgMr = Emitter::xchg_mr;
    for size in [1, 2, 4, 8] {
        let regs = gps(size);
        for (dst_name, dst) in regs.iter().map(|(name, reg)| (name.clone(), *reg)) {
            for (src_name, src) in regs.iter().map(|(name, reg)| (name.clone(), *reg)) {
                out.push(case(format!("xchg {dst_name}, {src_name}"), move |e| {
                    xchg_rr(e, dst, src)
                }));
            }
        }
        for (reg_name, reg) in gps_few(size) {
            for mem_size in [0, 1, 2, 4, 8, 16, 32] {
                for (mem_name, mem) in mems(mem_size).into_iter().step_by(17) {
                    out.push(case(format!("xchg {reg_name}, {mem_name}"), move |e| {
                        xchg_rm(e, reg, mem)
                    }));
                    out.push(case(format!("xchg {mem_name}, {reg_name}"), move |e| {
                        xchg_mr(e, mem, reg)
                    }));
                }
            }
        }
    }

    for size in [0, 1, 2, 4, 8, 16, 32] {
        for (name, mem) in mems(size).into_iter().step_by(11) {
            out.push(case(format!("lock inc {name}"), move |e| e.lock_inc_m(mem)));
        }
    }
    out.push(case("stosq", |e| e.stosq()));
    out.push(case("rep stosq", |e| e.rep_stosq()));
    out.push(case("ud2", |e| e.ud2()));
    out.push(case("hlt", |e| e.hlt()));
    out.push(case("int3", |e| e.int3()));
    out.push(case("nop", |e| e.nop()));

    // Padding lengths 1 through 15 exercise each optimized 1-to-9-byte NOP and greedy sequences.
    for padding in 1..=15usize {
        let leading_nops = 16 - padding;
        let mut text = "nop; ".repeat(leading_nops);
        text.push_str("align 16");
        out.push(case(text, move |e| {
            for _ in 0..leading_nops {
                e.nop()?;
            }
            e.align_code(16)
        }));
    }
    for alignment in [1, 2, 4, 8, 16, 32, 64] {
        out.push(case(format!("nop; align {alignment}"), move |e| {
            e.nop()?;
            e.align_code(alignment)
        }));
    }
    for alignment in [0, 3, 65] {
        out.push(case(format!("align {alignment}"), move |e| {
            e.align_code(alignment)
        }));
    }
}
