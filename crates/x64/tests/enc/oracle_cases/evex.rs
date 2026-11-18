//! EVEX zmm forms used by OTP's x86 `emit_copy_words` implementation.

use super::*;

type Zm = fn(&mut Emitter, Zmm, Mem) -> Result<(), EncodeError>;
type Mz = fn(&mut Emitter, Mem, Zmm) -> Result<(), EncodeError>;

pub fn cases(out: &mut Vec<OCase>) {
    let loads: Zm = Emitter::vmovups_zm;
    let stores: Mz = Emitter::vmovups_mz;
    let mut operands = mems(64);
    for disp in [64, 8128, 8192, -8128, -8192] {
        operands.push((format!("[rax{disp:+}]"), Mem::base_disp(RAX, disp, 64)));
    }

    for id in [0, 16, 31] {
        for (mem_name, mem) in &operands {
            let (mem_name, mem) = (mem_name.clone(), *mem);
            out.push(case(format!("vmovups zmm{id}, {mem_name}"), move |e| {
                loads(e, Zmm(id), mem)
            }));
            out.push(case(format!("vmovups {mem_name}, zmm{id}"), move |e| {
                stores(e, mem, Zmm(id))
            }));
        }
    }
}
