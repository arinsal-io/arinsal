//! Adapter for the differential testing contract.
use crate::{Vm, VmError};
use arinsal_difftest::{CallResult, Error};
use arinsal_etf::OwnedTerm;
use arinsal_term::{VecHeap, from_owned, to_owned};

impl arinsal_difftest::Vm for Vm {
    fn call(&mut self, module: &str, function: &str, args: &[OwnedTerm]) -> CallResult {
        let mut argument_heap = VecHeap::new();
        let mut terms = Vec::with_capacity(args.len());
        for arg in args {
            match from_owned(arg, &mut argument_heap) {
                Ok(term) => terms.push(term),
                Err(error) => return CallResult::TransportError(format!("argument: {error:?}")),
            }
        }
        let direct_bif = arinsal_bifs::lookup(module, function, args.len() as u8).is_some();
        let direct_vm_fun = module == "erlang"
            && matches!(
                (function, args.len()),
                ("apply", 2 | 3) | ("make_fun", 3) | ("fun_info", 1 | 2)
            );
        let result = if direct_bif
            || direct_vm_fun
            || std::env::var_os("ARINSAL_DIFFTEST_UNSCHEDULED").is_some()
        {
            self.eval(module, function, &terms).and_then(|outcome| {
                to_owned(outcome.term)
                    .map_err(|error| VmError::Unsupported(format!("result: {error:?}")))
            })
        } else {
            self.eval_scheduled(module, function, &terms, 1, None)
                .map(|outcome| outcome.term)
        };
        match result {
            Ok(term) => CallResult::Ok(term),
            Err(VmError::Exception { reason, .. }) => CallResult::Exception {
                class: "error".into(),
                reason: OwnedTerm::Atom(reason),
                stack_top: None,
            },
            Err(VmError::Raised(raised)) => CallResult::Exception {
                class: format!("{:?}", raised.class).to_lowercase(),
                reason: raised.reason,
                stack_top: Some(raised.stack),
            },
            Err(error) => CallResult::TransportError(error.to_string()),
        }
    }

    fn load(&mut self, _module: &str, beam: &[u8]) -> Result<(), Error> {
        self.load_bytes(beam)
            .map(|_| ())
            .map_err(|e| Error::Protocol(e.to_string()))
    }
}
