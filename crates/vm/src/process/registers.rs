//! `esdp->registers`: the register file of one scheduler.
//!
//! erts allocates the block with the scheduler data and hands `reg = esdp->registers->x_reg_array.d`
//! to generated code for the whole slice; native helpers reach the same block through
//! `erts_proc_sched_data(c_p)->registers`. The block is therefore reached through a shared
//! reference to the scheduler data and lent mutably only by the scheduler loop's own steps.
// Port of erts/emulator/beam/erl_process.h (ErtsSchedulerRegisters, ErtsSchedulerData_.registers)
// and erl_process.c (init_scheduler_data), OTP-29.1.1.

mod raw;

pub(crate) use raw::RegisterBlock;
