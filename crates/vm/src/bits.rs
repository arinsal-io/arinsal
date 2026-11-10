//! BEAM bit syntax instruction handlers.

use crate::VmError;
use arinsal_bits::BitsError;
use arinsal_etf::OwnedTerm;
use arinsal_term::to_owned;

trait FrameName {
    fn to_frame_string(&self) -> String;
}

impl FrameName for str {
    fn to_frame_string(&self) -> String {
        self.to_owned()
    }
}

impl FrameName for String {
    fn to_frame_string(&self) -> String {
        self.clone()
    }
}

impl<F: Fn() -> String> FrameName for F {
    fn to_frame_string(&self) -> String {
        self()
    }
}

/// The exception reason and `error_info` of a failed bit syntax operation in native code.
pub(crate) fn native_error(error: BitsError) -> (String, Option<Box<arinsal_etf::OwnedTerm>>) {
    match self::error(error, "") {
        VmError::ExceptionInfo { reason, info, .. } => (reason, Some(info)),
        VmError::Exception { reason, .. } => (reason, None),
        _ => ("badarg".into(), None),
    }
}

fn error(error: BitsError, frame: &(impl FrameName + ?Sized)) -> VmError {
    match error {
        BitsError::Detailed {
            segment,
            reason,
            ty,
            field,
            value,
        } => {
            let Some(value) = to_owned(value).ok() else {
                return VmError::Exception {
                    reason: reason.into(),
                    frame: frame.to_frame_string(),
                };
            };
            let atom = |name: &str| OwnedTerm::Atom(name.to_owned());
            let info = OwnedTerm::Map(vec![
                (
                    atom("cause"),
                    OwnedTerm::Tuple(vec![
                        OwnedTerm::Int(segment as i64),
                        atom(ty),
                        atom(field),
                        value,
                    ]),
                ),
                (atom("function"), atom("format_bs_fail")),
                (atom("module"), atom("erl_erts_errors")),
            ]);
            VmError::ExceptionInfo {
                reason: reason.into(),
                frame: frame.to_frame_string(),
                info: Box::new(info),
            }
        }
        BitsError::BadArg { .. } => VmError::Exception {
            reason: "badarg".into(),
            frame: frame.to_frame_string(),
        },
        BitsError::SystemLimit { .. } => VmError::Exception {
            reason: "system_limit".into(),
            frame: frame.to_frame_string(),
        },
        BitsError::HeapFull { .. } => VmError::Unsupported("bit syntax heap".into()),
    }
}

#[cfg(test)]
mod tests {
    use arinsal_difftest::RefErl;
    use arinsal_term::{Term, TermBuilder, VecHeap};

    use crate::Vm;

    #[test]
    fn utf8_tail_matches_survive_repeated_collection() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping utf8 match collection test");
            return;
        };
        let beam = reference
            .compile_named(
                "utf8_len",
                r#"
                -module(utf8_len).
                -export([repeat/2]).
                len(<<>>) -> 0;
                len(<<_/utf8, Rest/binary>>) -> 1 + len(Rest).
                repeat(0, _) -> 0;
                repeat(N, Bin) when N > 0 -> len(Bin) + repeat(N - 1, Bin).
                "#,
                &[],
            )
            .unwrap();
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let bytes = "Привіт, Elixir 123. ".repeat(8).into_bytes();
        let mut source_heap = VecHeap::new();
        let source = TermBuilder::new(&mut source_heap).binary(&bytes).unwrap();
        let times = Term::small(40).unwrap();
        let result = vm
            .eval_exported("utf8_len", "repeat", &[times, source])
            .unwrap();
        assert_eq!(result.term.as_small(), Some(40 * 160));
        assert!(result.stats.gc.collections > 0);
    }
}
