//! `re:run` BIFs and their hidden continuation export.
//!
//! Port of erts/emulator/beam/erl_bif_re.c (re_run, re_run_2, re_run_3,
//! re_internal_run_4, re_match_trap), OTP-29.1.1. The PCRE2 restart state lives in a magic
//! binary; the BIF traps through the ordinary `erlang:re_run_trap/3` bif_table export.

use crate::bif_table::bif_args;
use crate::bif_traps::TrapContext;
use crate::natives::bif::bif_ret;
use crate::{ExportTrap, Process, VmError};
use arinsal_beamasm::ProcessHeader;
use arinsal_bifs::{BifError, Ctx, ProcessHeapHandle};
use arinsal_term::{MagicBin, Term, TermBuilder};

const CONTEXT_REDS: i32 = 4_000;
const ERTS_REGEX_RESTART_CONTEXT_SIZE: usize = 64;
const RE_RUN_CONTINUATION: &str = "erlang:re_run_trap/3";
const RE_GRUN_CONTINUATION: &str = "re:grun/3";
const RE_URUN_CONTINUATION: &str = "re:urun/3";

type RestartContext = TrapContext<Option<Box<arinsal_re::RunState>>>;

arinsal_term::magic_payload!(RestartContext => cleanup_restart_context_bin);

/// `re:run/2`.
// Port of erts/emulator/beam/erl_bif_re.c (re_run_2), OTP-29.1.1.
pub(crate) extern "C" fn re_run_2(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let [subject, pattern] = bif_args::<2>(reg);
    run(c_p, i, "run", &[subject, pattern], None)
}

/// `re:run/3`.
// Port of erts/emulator/beam/erl_bif_re.c (re_run_3), OTP-29.1.1.
pub(crate) extern "C" fn re_run_3(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let [subject, pattern, options] = bif_args::<3>(reg);
    run(c_p, i, "run", &[subject, pattern, options], None)
}

/// `re:internal_run/4`.
// Port of erts/emulator/beam/erl_bif_re.c (re_internal_run_4), OTP-29.1.1.
pub(crate) extern "C" fn re_internal_run_4(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let [subject, pattern, options, first] = bif_args::<4>(reg);
    run(
        c_p,
        i,
        "internal_run",
        &[subject, pattern, options, first],
        None,
    )
}

/// `erlang:re_run_trap/3`.
// Port of erts/emulator/beam/erl_bif_re.c (re_match_trap), OTP-29.1.1.
pub(crate) extern "C" fn re_run_trap_3(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let [subject, pattern, restart] = bif_args::<3>(reg);
    let prior =
        restart.with_magic_payload::<RestartContext, _>(|context| context.lock().ok()?.take());
    let Some(Some(prior)) = prior else {
        let Some(process) = crate::native_hooks::process_from_header(c_p) else {
            return 0;
        };
        process.heap.note_bif_entry();
        return fail(
            c_p,
            i,
            process,
            ("erlang", "re_run_trap"),
            &[subject, pattern, restart],
            BifError::BADARG,
        );
    };
    run(
        c_p,
        i,
        "run",
        &[subject, pattern, restart],
        Some((restart, prior)),
    )
}

/// Runs the PCRE2 slice and reports its BIF result through the ordinary native ABI.
// Port of erts/emulator/beam/erl_bif_re.c (re_run), OTP-29.1.1.
fn run(
    c_p: *mut ProcessHeader,
    i: u64,
    name: &str,
    args: &[Term],
    resume: Option<(Term, Box<arinsal_re::RunState>)>,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let reds_initial = process.heap.abi.fcalls.clamp(1, CONTEXT_REDS);
    let loop_limit = reds_initial * arinsal_re::LOOP_FACTOR;
    let restart_term = resume.as_ref().map(|(restart, _)| *restart);
    let prior = resume.map(|(_, prior)| prior);
    let result = {
        let mut heap = ProcessHeapHandle(&mut process.heap);
        let mut state = arinsal_bifs::BifState::default();
        let mut ctx = Ctx::new(&mut heap, &mut state);
        arinsal_re::run_slice_or_global(&mut ctx, name, args, prior, loop_limit)
    };
    let dispatch = match result {
        Ok(dispatch) => dispatch,
        Err(error) => {
            let (module, function) = if name == "internal_run" {
                ("re", "internal_run")
            } else {
                ("re", "run")
            };
            return fail(c_p, i, process, (module, function), args, error);
        }
    };

    match dispatch {
        arinsal_re::RunDispatch::Run { progress, loops } => {
            let reductions =
                (loops / arinsal_re::LOOP_FACTOR as u64).min(u64::from(u32::MAX)) as u32;
            bump_reds(process, reductions);
            match progress {
                arinsal_re::Progress::Done(value) => crate::native_hooks::raw(value),
                arinsal_re::Progress::Yield(run) => {
                    let restart = if let Some(restart) = restart_term {
                        if restart
                            .with_magic_payload::<RestartContext, _>(|context| {
                                let mut context = context.lock().ok()?;
                                *context = Some(run);
                                Some(())
                            })
                            .flatten()
                            .is_none()
                        {
                            return fail(
                                c_p,
                                i,
                                process,
                                ("erlang", "re_run_trap"),
                                args,
                                BifError::BADARG,
                            );
                        }
                        crate::bif_traps::vbump_all_reds(process);
                        restart
                    } else {
                        let state = MagicBin::with_erts_payload_size_and_refn(
                            TrapContext::new(Some(run)),
                            ERTS_REGEX_RESTART_CONTEXT_SIZE,
                            arinsal_bifs::next_ref_words(),
                        );
                        crate::bif_traps::vbump_all_reds(process);
                        match TermBuilder::new(&mut ProcessHeapHandle(&mut process.heap))
                            .magic_ref(state)
                        {
                            Ok(restart) => restart,
                            Err(_) => {
                                return fail(
                                    c_p,
                                    i,
                                    process,
                                    ("re", "run"),
                                    args,
                                    BifError::SystemLimit,
                                );
                            }
                        }
                    };
                    let trap = ExportTrap::new(
                        process,
                        RE_RUN_CONTINUATION,
                        vec![args[0], args[1], restart],
                    );
                    bif_ret(c_p, i, Err(VmError::TrapExport(trap)))
                }
            }
        }
        arinsal_re::RunDispatch::Global(arinsal_re::GlobalRun::Return(value)) => {
            crate::native_hooks::raw(value)
        }
        arinsal_re::RunDispatch::Global(arinsal_re::GlobalRun::UnicodeTrap) => {
            let trap = ExportTrap::new(
                process,
                RE_URUN_CONTINUATION,
                vec![args[0], args[1], args.get(2).copied().unwrap_or(Term::NIL)],
            );
            bif_ret(c_p, i, Err(VmError::TrapExport(trap)))
        }
        arinsal_re::RunDispatch::Global(arinsal_re::GlobalRun::Trap { pattern, options }) => {
            let trap = ExportTrap::new(
                process,
                RE_GRUN_CONTINUATION,
                vec![args[0], pattern, options],
            );
            bif_ret(c_p, i, Err(VmError::TrapExport(trap)))
        }
    }
}

fn bump_reds(process: &mut Process, reductions: u32) {
    process.heap.abi.fcalls = process
        .heap
        .abi
        .fcalls
        .saturating_sub(reductions.min(i32::MAX as u32) as i32)
        .max(0);
}

#[cold]
#[inline(never)]
fn fail(
    c_p: *mut ProcessHeader,
    i: u64,
    process: &mut Process,
    (module, function): (&str, &str),
    args: &[Term],
    error: BifError,
) -> u64 {
    let error = crate::exceptions::bif_error(process, module, function, args, error);
    bif_ret(c_p, i, Err(error))
}
