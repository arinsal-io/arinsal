//! Byte-test scheduler for the generated `process_main` (erts/emulator/beam/jit/x86/
//! process_main.cpp, emit_process_main), OTP-29.1.1: native code under test runs the way the
//! VM runs it, in a scheduler thread's `process_main` with the register file on that
//! thread's stack. The test's `erts_schedule` (the link fixture of `x86::rt`'s tests) hands
//! each job's process to the loop; the test's `arinsal_slice_step` enters it and reports the
//! exit back.

use std::cell::RefCell;
use std::sync::OnceLock;
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};

use super::beam_asm_global::{BeamGlobalAssembler, GLOBAL_LABELS, GlobalLabels};
use crate::{ExitReason, ProcessHeader, SchedulerRegisters};

/// One native entry: the process `header` enters `entry` with the register state of
/// `regs` (copied in and back out); the exit comes back on `done`.
struct Job {
    header: usize,
    regs: usize,
    entry: usize,
    done: SyncSender<ExitReason>,
}

struct Runner {
    jobs: Receiver<Job>,
    /// `esdp->registers` of this scheduler thread, filled by the `process_main` prologue.
    registers: *mut *mut SchedulerRegisters,
    current: Option<Job>,
    /// The running job's process: its header followed by the erts `Process` fields the loop
    /// reads or writes (`state`, `def_arg_reg[5]`), zero apart from the header.
    process: Box<[u64; PROCESS_WORDS]>,
}

/// Words of [`Runner::process`]: past `offsetof(Process, state)` of
/// `ProcessOffsets::ERTS_X86_64`.
const PROCESS_WORDS: usize = 128;
const HEADER_WORDS: usize = core::mem::size_of::<ProcessHeader>() / 8;

thread_local! {
    static RUNNER: RefCell<Option<Runner>> = const { RefCell::new(None) };
}

/// The process-wide global code with `process_main`, and the job queue of its scheduler
/// thread.
fn scheduler() -> &'static std::sync::Mutex<SyncSender<Job>> {
    static SCHEDULER: OnceLock<std::sync::Mutex<SyncSender<Job>>> = OnceLock::new();
    SCHEDULER.get_or_init(|| {
        let mut ga =
            BeamGlobalAssembler::new(crate::common::process_offsets::ProcessOffsets::ERTS_X86_64)
                .unwrap();
        for label in GLOBAL_LABELS {
            let l = ga.label(label);
            if ga.asm.a.label_location(l).is_none() {
                ga.asm.align_code(8).unwrap();
                ga.asm.bind(l).unwrap();
                ga.asm.emit(|e| e.ud2()).unwrap();
            }
        }
        // erts never releases the global code.
        Box::leak(Box::new(ga.codegen().unwrap()));
        super::rt::set_process_main_labels(ga.native_exit_ptr().unwrap());
        let process_main = ga.get_ptr(GlobalLabels::ProcessMain).unwrap();
        let (tx, rx) = sync_channel::<Job>(0);
        std::thread::Builder::new()
            .name("test_process_main".into())
            .spawn(move || {
                let registers = Box::leak(Box::new(core::ptr::null_mut::<SchedulerRegisters>()));
                let registers: *mut *mut SchedulerRegisters = registers;
                RUNNER.with(|runner| {
                    *runner.borrow_mut() = Some(Runner {
                        jobs: rx,
                        registers,
                        current: None,
                        process: Box::new([0; PROCESS_WORDS]),
                    });
                });
                // SAFETY: `process_main` is the emitted `void process_main(ErtsSchedulerData
                // *)` taking `&esdp->registers`; it runs for the thread's life on this
                // thread's outermost frame, and the fixture `erts_schedule` below serves it.
                let process_main: extern "C" fn(*mut *mut SchedulerRegisters) -> ! =
                    unsafe { core::mem::transmute(process_main) };
                process_main(registers)
            })
            .unwrap();
        std::sync::Mutex::new(tx)
    })
}

/// Runs native code at `entry` for the process `header` with the register state `regs`
/// (X and float registers, `tmp_mem`, `entry_return`, `active_code_ix`), through the
/// generated `process_main`; returns the exit and leaves the register state in `regs`.
pub(crate) fn enter(
    header: &mut ProcessHeader,
    regs: &mut SchedulerRegisters,
    entry: usize,
) -> ExitReason {
    let (done, exit) = sync_channel(1);
    scheduler()
        .lock()
        .unwrap()
        .send(Job {
            header: std::ptr::from_mut(header) as usize,
            regs: std::ptr::from_mut(regs) as usize,
            entry,
            done,
        })
        .unwrap();
    exit.recv().unwrap()
}

fn copy_state(to: &mut SchedulerRegisters, from: &SchedulerRegisters) {
    to.x_reg_array = from.x_reg_array;
    to.f_reg_array = from.f_reg_array;
    to.tmp_mem = from.tmp_mem;
    to.entry_return = from.entry_return;
    to.active_code_ix = from.active_code_ix;
}

/// The register file of this scheduler thread, and the register state and header of `job`.
fn job_parts<'a>(
    registers: *mut *mut SchedulerRegisters,
    job: &Job,
) -> (
    &'a mut SchedulerRegisters,
    &'a mut SchedulerRegisters,
    &'a mut [u64],
) {
    // SAFETY: the prologue stored the stack address of the register file before the first
    // `erts_schedule`, and this thread is its only user; the job's sender blocks in `enter`
    // until `done`, so its registers and `HEADER_WORDS`-word header outlive the job and are
    // not touched meanwhile.
    unsafe {
        (
            &mut **registers,
            &mut *(job.regs as *mut SchedulerRegisters),
            std::slice::from_raw_parts_mut(job.header as *mut u64, HEADER_WORDS),
        )
    }
}

/// The fixture `erts_schedule(NULL, p, calls)`: waits for the next job and returns its
/// process.
pub(crate) fn erts_schedule(p: *mut ProcessHeader) -> *mut ProcessHeader {
    RUNNER.with(|runner| {
        let mut runner = runner.borrow_mut();
        let runner = runner
            .as_mut()
            .expect("erts_schedule on the test scheduler");
        assert!(runner.current.is_none(), "the slice of {p:p} ended");
        let job = runner.jobs.recv().expect("test scheduler queue");
        let (file, regs, header) = job_parts(runner.registers, &job);
        copy_state(file, regs);
        file.tmp_mem[3] = 0;
        runner.process[..HEADER_WORDS].copy_from_slice(header);
        runner.process[core::mem::offset_of!(ProcessHeader, i) / 8] = job.entry as u64;
        runner.current = Some(job);
        runner.process.as_mut_ptr().cast::<ProcessHeader>()
    })
}

/// The fixture `arinsal_slice_step(c_p, resume)`: the slice of a job is one native entry;
/// on its exit the state goes back to the job and the exit is reported.
pub(crate) fn arinsal_slice_step(p: *mut ProcessHeader, resume: bool) -> i32 {
    if !resume {
        return 1;
    }
    RUNNER.with(|runner| {
        let mut runner = runner.borrow_mut();
        let runner = runner.as_mut().expect("slice step on the test scheduler");
        assert_eq!(p, runner.process.as_mut_ptr().cast::<ProcessHeader>());
        let job = runner.current.take().expect("a job is running");
        let (file, regs, header) = job_parts(runner.registers, &job);
        let exit = super::rt::take_native_exit(file);
        copy_state(regs, file);
        header.copy_from_slice(&runner.process[..HEADER_WORDS]);
        job.done.send(exit).unwrap();
        0
    })
}
