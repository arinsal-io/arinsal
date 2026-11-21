//! The BIFs of erl_init.c.
//!
//! Port of erts/emulator/beam/erl_init.c (erts_internal_spawn_system_process_3), OTP-29.1.1.

use crate::natives::bif::bif_ret;
use crate::natives::erl_process::{CreateError, ErlSpawnOpts, erl_create_process};
use arinsal_beamasm::ProcessHeader;

/// `erts_internal:spawn_system_process/3`: `erl_spawn_system_process` with the default
/// spawn options.
// Port of erts/emulator/beam/erl_init.c (erts_internal_spawn_system_process_3,
// erl_spawn_system_process: `so->flags |= SPO_SYSTEM_PROC`), OTP-29.1.1.
pub(crate) extern "C" fn erts_internal_spawn_system_process_3(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    let [module, function, args] = crate::bif_table::bif_args::<3>(reg);
    let mut so = ErlSpawnOpts::new(process.runtime);
    so.system_proc = true;
    let result = erl_create_process(process, reg, module, function, args, &mut so)
        .map_err(CreateError::into_bif_error);
    bif_ret(c_p, i, result)
}
