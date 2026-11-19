//! Port of erts/emulator/beam/jit/arm/: the AArch64 BeamAsm emitters, global fragments,
//! module emission and native entry/return, selected at build time like erts selects
//! jit/arm versus jit/x86.

pub mod arith;
pub(crate) mod beam_asm;
pub mod bif;
pub mod bs_construct;
pub(crate) mod bs_fast;
pub mod bs_match;
pub mod bs_segments;
pub mod catch;
pub(crate) mod compare;
pub mod construct;
pub mod dispatch;
pub(crate) mod dump;
pub mod float;
pub mod fun;
pub mod guard;
pub mod map;
pub mod misc;
pub mod module;
pub mod raise_frag;
pub mod receive;
pub mod receive_frag;
pub mod records;
pub(crate) mod regcache;
#[allow(unsafe_code)]
pub mod rt;
pub mod select;
pub mod yield_frag;

pub use beam_asm::*;
pub use dump::{DumpError, write_global_note};

use crate::{ExitReason, ProcessHeader, SchedulerRegisters};

pub use rt::{enter_native_raw, set_process_main_labels};

/// Enters finalized generated code through the reviewed native ABI bridge.
pub fn enter_native(
    header: &mut ProcessHeader,
    regs: &mut SchedulerRegisters,
    entry: &NativeEntry<'_>,
) -> ExitReason {
    rt::enter_native(header, regs, entry)
}

/// A native function whose executable mapping is kept alive by this borrow.
pub struct NativeEntry<'a> {
    pub(crate) memory: &'a arinsal_a64::exec::CodeMemory,
    pub(crate) offset: usize,
}
