use arinsal_bifs::{BifError, Class, Ctx, FragmentingHeap, lookup};
use arinsal_difftest::CallResult;
use arinsal_etf::OwnedTerm;
use arinsal_term::{ProcessHeap, from_owned, to_owned};

pub fn call(module: &str, name: &str, args: &[OwnedTerm]) -> CallResult {
    let Some(bif) = lookup(module, name, args.len() as u8) else {
        return CallResult::TransportError(format!("missing {module}:{name}/{}", args.len()));
    };
    let mut heap = ProcessHeap::with_words(1024);
    let mut allocator = FragmentingHeap(&mut heap);
    let terms = args
        .iter()
        .map(|value| from_owned(value, &mut allocator).expect("test argument"))
        .collect::<Vec<_>>();
    let mut ctx = Ctx::new(&mut allocator);
    match bif(&mut ctx, &terms) {
        Ok(value) => CallResult::Ok(to_owned(value).expect("BIF result")),
        Err(error) => {
            let (class, reason) = match error {
                BifError::Badarg { .. } => ("error", OwnedTerm::atom("badarg")),
                BifError::Badarith => ("error", OwnedTerm::atom("badarith")),
                BifError::SystemLimit => ("error", OwnedTerm::atom("system_limit")),
                BifError::Error(value) => ("error", to_owned(value).expect("error term")),
                BifError::Raise { class, reason, .. } => (
                    match class {
                        Class::Error => "error",
                        Class::Exit => "exit",
                        Class::Throw => "throw",
                    },
                    to_owned(reason).expect("raise term"),
                ),
                BifError::Unsupported(reason) => {
                    return CallResult::TransportError(format!("unsupported: {reason}"));
                }
            };
            CallResult::Exception {
                class: class.to_owned(),
                reason,
                stack_top: None,
            }
        }
    }
}

pub fn equivalent(actual: &CallResult, expected: &CallResult) -> bool {
    match (actual, expected) {
        (CallResult::Ok(a), CallResult::Ok(b)) => a == b,
        (CallResult::Exception { class: a, .. }, CallResult::Exception { class: b, .. }) => a == b,
        _ => false,
    }
}
