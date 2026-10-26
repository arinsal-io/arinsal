use crate::process::Message;
use crate::{Process, Vm, VmError, exceptions};
use arinsal_bifs::{Ctx, ProcessHeapHandle};
use arinsal_sched::RunCtx;
use arinsal_term::Term;

/// `re` BIFs. These are the `arinsal_re::lookup` arms this family invokes.
pub(crate) const IMPLEMENTED: &[(&str, &str, u8)] = &[
    ("re", "version", 0),
    ("re", "compile", 1),
    ("re", "compile", 2),
    ("re", "run", 2),
    ("re", "run", 3),
    ("re", "internal_run", 4),
    ("re", "inspect", 2),
    ("re", "import", 1),
];

pub(crate) fn recognizes(module: &str, function: &str, arity: u8) -> bool {
    super::listed(IMPLEMENTED, module, function, arity)
}

pub(crate) fn call(
    _vm: &mut Vm,
    process: &mut Process,
    _ctx: &mut RunCtx<'_, Message>,
    module: &str,
    function: &str,
    args: super::NativeArgs<'_>,
) -> Option<Result<Term, VmError>> {
    args.with_values(process, |process, values| {
        call_values(process, module, function, values)
    })
}

fn call_values(
    process: &mut Process,
    module: &str,
    function: &str,
    args: &[Term],
) -> Option<Result<Term, VmError>> {
    let arity = args.len() as u8;
    if !recognizes(module, function, arity) {
        return None;
    }
    arinsal_re::lookup(module, function, arity)?;
    let result = {
        let mut heap = ProcessHeapHandle(&mut process.heap);
        let mut state = arinsal_bifs::BifStateGuard::new(&mut process.reductions);
        let mut ctx = Ctx::with_fcalls(&mut heap, &mut state);
        arinsal_re::invoke(&mut ctx, function, args)
    };
    Some(result.map_err(|error| exceptions::bif_error(process, module, function, args, error)))
}
