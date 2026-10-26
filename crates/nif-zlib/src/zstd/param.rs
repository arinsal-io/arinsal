//! `set_compress_parameter_nif`, `get_compress_parameter_nif`,
//! `set_decompress_parameter_nif` and `get_decompress_parameter_nif`.
//!
//! The key atoms and the checks run in the order of zstd_nif.c: the context first (`badarg`
//! or `not_on_controlling_process`), then the key (`{badarg, {invalid_key, Key}}`), then the
//! value (`{badarg, {invalid_value, Value}}`), then zstd itself (`{zstd_error, Message}`).
//! `set_decompress_parameter_nif` reads the integer value before it looks at the key, so a
//! value that is not an `int` is a plain `badarg` whatever the key is.

use arinsal_bifs::{BifError, Ctx};
use arinsal_term::Term;
use zstd_sys as z;

use super::{
    Kind, atom_name, atom_term, get_int, get_zstd_context, invalid_key, invalid_value, is_error,
    zstd_error,
};

use z::ZSTD_cParameter as C;
use z::ZSTD_strategy as S;

/// `get_cparam`: the parameter atoms, in the order of the C comparison chain.
const CPARAMS: [(&str, z::ZSTD_cParameter); 17] = [
    ("compressionLevel", C::ZSTD_c_compressionLevel),
    ("windowLog", C::ZSTD_c_windowLog),
    ("hashLog", C::ZSTD_c_hashLog),
    ("chainLog", C::ZSTD_c_chainLog),
    ("searchLog", C::ZSTD_c_searchLog),
    ("minMatch", C::ZSTD_c_minMatch),
    ("targetLength", C::ZSTD_c_targetLength),
    ("strategy", C::ZSTD_c_strategy),
    ("targetCBlockSize", C::ZSTD_c_targetCBlockSize),
    (
        "enableLongDistanceMatching",
        C::ZSTD_c_enableLongDistanceMatching,
    ),
    ("ldmHashLog", C::ZSTD_c_ldmHashLog),
    ("ldmMinMatch", C::ZSTD_c_ldmMinMatch),
    ("ldmBucketSizeLog", C::ZSTD_c_ldmBucketSizeLog),
    ("ldmHashRateLog", C::ZSTD_c_ldmHashRateLog),
    ("contentSizeFlag", C::ZSTD_c_contentSizeFlag),
    ("checksumFlag", C::ZSTD_c_checksumFlag),
    ("dictIDFlag", C::ZSTD_c_dictIDFlag),
];

/// The strategy atoms and their `ZSTD_strategy` values. `default` is 0, which is no strategy.
const STRATEGIES: [(&str, i32); 10] = [
    ("default", 0),
    ("fast", S::ZSTD_fast as i32),
    ("dfast", S::ZSTD_dfast as i32),
    ("greedy", S::ZSTD_greedy as i32),
    ("lazy", S::ZSTD_lazy as i32),
    ("lazy2", S::ZSTD_lazy2 as i32),
    ("btlazy2", S::ZSTD_btlazy2 as i32),
    ("btopt", S::ZSTD_btopt as i32),
    ("btultra", S::ZSTD_btultra as i32),
    ("btultra2", S::ZSTD_btultra2 as i32),
];

/// `get_cparam`: `None` is the C function's 0, no parameter.
fn get_cparam(key: Term) -> Option<z::ZSTD_cParameter> {
    let name = atom_name(key)?;
    CPARAMS
        .iter()
        .find_map(|(atom, param)| (*atom == name).then_some(*param))
}

/// `get_dparam`: `windowLogMax` is the only decompress parameter.
fn get_dparam(key: Term) -> Option<z::ZSTD_dParameter> {
    (atom_name(key) == Some("windowLogMax")).then_some(z::ZSTD_dParameter::ZSTD_d_windowLogMax)
}

/// The parameters that take `true` or `false`.
fn is_boolean(param: z::ZSTD_cParameter) -> bool {
    matches!(
        param,
        C::ZSTD_c_enableLongDistanceMatching
            | C::ZSTD_c_contentSizeFlag
            | C::ZSTD_c_checksumFlag
            | C::ZSTD_c_dictIDFlag
    )
}

/// The value switch of `set_compress_parameter_nif`: a strategy atom, a boolean atom, or an
/// `int`. `None` is an invalid value.
fn cparam_value(param: z::ZSTD_cParameter, value: Term) -> Option<i32> {
    if param == C::ZSTD_c_strategy {
        let name = atom_name(value)?;
        STRATEGIES
            .iter()
            .find_map(|(atom, number)| (*atom == name).then_some(*number))
    } else if is_boolean(param) {
        match atom_name(value)? {
            "true" => Some(1),
            "false" => Some(0),
            _ => None,
        }
    } else {
        get_int(value)
    }
}

pub(super) fn set_compress_parameter_nif(
    ctx: &mut Ctx<'_>,
    args: &[Term],
) -> Result<Term, BifError> {
    let context = get_zstd_context(args[0], Kind::Compress)?;
    let p = get_cparam(args[1]).ok_or_else(|| invalid_key(ctx, args[1]))?;
    let value = cparam_value(p, args[2]).ok_or_else(|| invalid_value(ctx, args[2]))?;
    // SAFETY: the resource contains a live compression context.
    let result = unsafe { z::ZSTD_CCtx_setParameter(context.lock().ptr.cast(), p, value) };
    if is_error(result) {
        return Err(zstd_error(ctx, result));
    }
    atom_term("ok")
}

pub(super) fn get_compress_parameter_nif(
    ctx: &mut Ctx<'_>,
    args: &[Term],
) -> Result<Term, BifError> {
    let context = get_zstd_context(args[0], Kind::Compress)?;
    let p = get_cparam(args[1]).ok_or_else(|| invalid_key(ctx, args[1]))?;
    let mut value = 0;
    // SAFETY: the resource contains a live compression context.
    let result = unsafe { z::ZSTD_CCtx_getParameter(context.lock().ptr.cast(), p, &mut value) };
    if is_error(result) {
        return Err(zstd_error(ctx, result));
    }
    if is_boolean(p) {
        // The NIF converts the zstd return code, which is 0 after the error check, instead of
        // the fetched value: a boolean parameter always reads back as `false`.
        return atom_term(if result != 0 { "true" } else { "false" });
    }
    if p == C::ZSTD_c_strategy {
        return match STRATEGIES.iter().find(|(_, number)| *number == value) {
            Some((atom, _)) => atom_term(atom),
            None => Err(BifError::BADARG),
        };
    }
    Term::small(i64::from(value)).ok_or(BifError::SystemLimit)
}

pub(super) fn set_decompress_parameter_nif(
    ctx: &mut Ctx<'_>,
    args: &[Term],
) -> Result<Term, BifError> {
    let context = get_zstd_context(args[0], Kind::Decompress)?;
    let value = get_int(args[2]).ok_or(BifError::BADARG)?;
    let p = get_dparam(args[1]).ok_or_else(|| invalid_key(ctx, args[1]))?;
    // SAFETY: the resource contains a live decompression context.
    let result = unsafe { z::ZSTD_DCtx_setParameter(context.lock().ptr.cast(), p, value) };
    if is_error(result) {
        return Err(zstd_error(ctx, result));
    }
    atom_term("ok")
}

pub(super) fn get_decompress_parameter_nif(
    ctx: &mut Ctx<'_>,
    args: &[Term],
) -> Result<Term, BifError> {
    let context = get_zstd_context(args[0], Kind::Decompress)?;
    let p = get_dparam(args[1]).ok_or_else(|| invalid_key(ctx, args[1]))?;
    let mut value = 0;
    // SAFETY: the resource contains a live decompression context.
    let result = unsafe { z::ZSTD_DCtx_getParameter(context.lock().ptr.cast(), p, &mut value) };
    if is_error(result) {
        return Err(zstd_error(ctx, result));
    }
    Term::small(i64::from(value)).ok_or(BifError::SystemLimit)
}

#[cfg(test)]
mod tests {
    use arinsal_bifs::{BifError, Ctx, ProcessHeapHandle};
    use arinsal_etf::OwnedTerm as O;
    use arinsal_term::{ProcessHeap, Term, TermBuilder, to_owned};

    use super::super::{atom_term, get_uint64, lookup};
    use super::{CPARAMS, STRATEGIES, get_cparam, get_dparam};

    #[derive(Debug, PartialEq)]
    enum Out {
        Ok(O),
        Error(O),
        Badarg,
    }

    fn atom(name: &str) -> Term {
        atom_term(name).expect("atom")
    }

    fn small(value: i64) -> Term {
        Term::small(value).expect("small")
    }

    fn err(reason: &str, term: O) -> Out {
        Out::Error(O::Tuple(vec![
            crate::atom("badarg"),
            O::Tuple(vec![crate::atom(reason), term]),
        ]))
    }

    fn call(ctx: &mut Ctx<'_>, name: &str, args: &[Term]) -> Out {
        let entry = lookup(name, args.len() as u8).expect("zstd NIF entry");
        match entry(ctx, args) {
            Ok(term) => Out::Ok(to_owned(term).expect("owned")),
            Err(BifError::Error(reason)) => Out::Error(to_owned(reason).expect("owned")),
            Err(BifError::Badarg { cause: None }) => Out::Badarg,
            Err(other) => panic!("unexpected BIF error {other:?}"),
        }
    }

    fn with_ctx<R>(body: impl FnOnce(&mut Ctx<'_>) -> R) -> R {
        let mut heap = ProcessHeap::with_words(1 << 16);
        let mut alloc = ProcessHeapHandle(&mut heap);
        let mut state = arinsal_bifs::BifState::default();
        let mut ctx = Ctx::new(&mut alloc, &mut state);
        body(&mut ctx)
    }

    fn resource(ctx: &mut Ctx<'_>, name: &str) -> Term {
        let entry = lookup(name, 0).expect("init entry");
        entry(ctx, &[]).expect("context")
    }

    #[test]
    fn key_tables_hold_every_parameter_of_c_once() {
        let names: Vec<&str> = CPARAMS.iter().map(|(name, _)| *name).collect();
        assert_eq!(
            names,
            [
                "compressionLevel",
                "windowLog",
                "hashLog",
                "chainLog",
                "searchLog",
                "minMatch",
                "targetLength",
                "strategy",
                "targetCBlockSize",
                "enableLongDistanceMatching",
                "ldmHashLog",
                "ldmMinMatch",
                "ldmBucketSizeLog",
                "ldmHashRateLog",
                "contentSizeFlag",
                "checksumFlag",
                "dictIDFlag"
            ]
        );
        let numbers: Vec<i32> = CPARAMS.iter().map(|(_, param)| *param as i32).collect();
        let mut unique = numbers.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            unique.len(),
            numbers.len(),
            "every atom maps to its own parameter"
        );
        for (name, param) in CPARAMS {
            assert_eq!(get_cparam(atom(name)), Some(param));
        }
        let strategies: Vec<(&str, i32)> = STRATEGIES.to_vec();
        assert_eq!(
            strategies,
            [
                ("default", 0),
                ("fast", 1),
                ("dfast", 2),
                ("greedy", 3),
                ("lazy", 4),
                ("lazy2", 5),
                ("btlazy2", 6),
                ("btopt", 7),
                ("btultra", 8),
                ("btultra2", 9)
            ]
        );
        assert_eq!(
            get_dparam(atom("windowLogMax")),
            Some(zstd_sys::ZSTD_dParameter::ZSTD_d_windowLogMax)
        );
        for other in ["compressionLevel", "WindowLogMax", "windowLogmax", "foo"] {
            assert_eq!(get_dparam(atom(other)), None);
        }
        for other in [
            "CompressionLevel",
            "windowLogMax",
            "dictionary",
            "pledgedSrcSize",
        ] {
            assert_eq!(get_cparam(atom(other)), None);
        }
        assert_eq!(get_cparam(small(100)), None);
        assert_eq!(get_dparam(small(100)), None);
    }

    #[test]
    fn every_compress_parameter_round_trips() {
        let cases: [(&str, Term, Out); 17] = [
            ("compressionLevel", small(7), Out::Ok(O::Int(7))),
            ("windowLog", small(20), Out::Ok(O::Int(20))),
            ("hashLog", small(15), Out::Ok(O::Int(15))),
            ("chainLog", small(14), Out::Ok(O::Int(14))),
            ("searchLog", small(3), Out::Ok(O::Int(3))),
            ("minMatch", small(4), Out::Ok(O::Int(4))),
            ("targetLength", small(32), Out::Ok(O::Int(32))),
            ("strategy", atom("lazy2"), Out::Ok(crate::atom("lazy2"))),
            ("targetCBlockSize", small(2048), Out::Ok(O::Int(2048))),
            (
                "enableLongDistanceMatching",
                atom("true"),
                Out::Ok(crate::atom("false")),
            ),
            ("ldmHashLog", small(16), Out::Ok(O::Int(16))),
            ("ldmMinMatch", small(32), Out::Ok(O::Int(32))),
            ("ldmBucketSizeLog", small(4), Out::Ok(O::Int(4))),
            ("ldmHashRateLog", small(5), Out::Ok(O::Int(5))),
            (
                "contentSizeFlag",
                atom("true"),
                Out::Ok(crate::atom("false")),
            ),
            ("checksumFlag", atom("true"), Out::Ok(crate::atom("false"))),
            ("dictIDFlag", atom("true"), Out::Ok(crate::atom("false"))),
        ];
        with_ctx(|ctx| {
            for (key, value, read_back) in cases {
                let c = resource(ctx, "init_compress_nif");
                let key = atom(key);
                assert_eq!(
                    call(ctx, "set_compress_parameter_nif", &[c, key, value]),
                    Out::Ok(crate::atom("ok")),
                    "set {key:?}"
                );
                assert_eq!(
                    call(ctx, "get_compress_parameter_nif", &[c, key]),
                    read_back,
                    "get {key:?}"
                );
            }
        });
    }

    #[test]
    fn every_strategy_atom_is_set_and_read_back() {
        with_ctx(|ctx| {
            for (name, _) in STRATEGIES {
                let c = resource(ctx, "init_compress_nif");
                let set = call(
                    ctx,
                    "set_compress_parameter_nif",
                    &[c, atom("strategy"), atom(name)],
                );
                assert_eq!(set, Out::Ok(crate::atom("ok")), "set {name}");
                let get = call(ctx, "get_compress_parameter_nif", &[c, atom("strategy")]);
                assert_eq!(get, Out::Ok(crate::atom(name)), "get {name}");
            }
        });
    }

    #[test]
    fn boolean_parameters_read_back_false() {
        with_ctx(|ctx| {
            let c = resource(ctx, "init_compress_nif");
            for key in [
                "enableLongDistanceMatching",
                "contentSizeFlag",
                "checksumFlag",
                "dictIDFlag",
            ] {
                for value in ["true", "false"] {
                    assert_eq!(
                        call(
                            ctx,
                            "set_compress_parameter_nif",
                            &[c, atom(key), atom(value)]
                        ),
                        Out::Ok(crate::atom("ok"))
                    );
                    assert_eq!(
                        call(ctx, "get_compress_parameter_nif", &[c, atom(key)]),
                        Out::Ok(crate::atom("false")),
                        "{key} {value}"
                    );
                }
            }
        });
    }

    #[test]
    fn compress_set_checks_key_then_value_then_zstd() {
        with_ctx(|ctx| {
            let c = resource(ctx, "init_compress_nif");
            let set = |ctx: &mut Ctx<'_>, key, value| {
                call(ctx, "set_compress_parameter_nif", &[c, key, value])
            };
            assert_eq!(
                set(ctx, atom("foo"), atom("bar")),
                err("invalid_key", crate::atom("foo"))
            );
            assert_eq!(set(ctx, small(1), small(1)), err("invalid_key", O::Int(1)));
            assert_eq!(
                set(ctx, atom("strategy"), atom("nope")),
                err("invalid_value", crate::atom("nope"))
            );
            assert_eq!(
                set(ctx, atom("strategy"), small(1)),
                err("invalid_value", O::Int(1))
            );
            assert_eq!(
                set(ctx, atom("checksumFlag"), small(1)),
                err("invalid_value", O::Int(1))
            );
            assert_eq!(
                set(ctx, atom("compressionLevel"), atom("a")),
                err("invalid_value", crate::atom("a"))
            );
            assert_eq!(
                set(ctx, atom("windowLog"), small(1 << 40)),
                err("invalid_value", O::Int(1 << 40))
            );
            assert_eq!(
                set(ctx, atom("windowLog"), small(1 << 31)),
                err("invalid_value", O::Int(1 << 31))
            );
            let Out::Error(O::Tuple(ref reason)) = set(ctx, atom("windowLog"), small(99)) else {
                panic!("windowLog 99 is out of bound")
            };
            assert_eq!(reason[0], crate::atom("zstd_error"));
            assert_eq!(reason[1], O::Binary(b"Parameter is out of bound".to_vec()));
            assert_eq!(
                set(ctx, atom("windowLog"), small((1 << 31) - 1)),
                set(ctx, atom("windowLog"), small(99)),
                "an int in range reaches zstd"
            );
            assert_eq!(
                call(ctx, "get_compress_parameter_nif", &[c, atom("foo")]),
                err("invalid_key", crate::atom("foo"))
            );
        });
    }

    #[test]
    fn decompress_set_reads_the_value_before_the_key() {
        with_ctx(|ctx| {
            let d = resource(ctx, "init_decompress_nif");
            let set = |ctx: &mut Ctx<'_>, key, value| {
                call(ctx, "set_decompress_parameter_nif", &[d, key, value])
            };
            assert_eq!(set(ctx, atom("windowLogMax"), atom("foo")), Out::Badarg);
            assert_eq!(set(ctx, atom("nokey"), atom("foo")), Out::Badarg);
            assert_eq!(set(ctx, atom("nokey"), small(1 << 31)), Out::Badarg);
            assert_eq!(
                set(ctx, atom("nokey"), small(1)),
                err("invalid_key", crate::atom("nokey"))
            );
            assert_eq!(set(ctx, small(5), small(1)), err("invalid_key", O::Int(5)));
            let Out::Error(O::Tuple(ref reason)) = set(ctx, atom("windowLogMax"), small(100))
            else {
                panic!("windowLogMax 100 is out of bound")
            };
            assert_eq!(reason[0], crate::atom("zstd_error"));
            assert_eq!(
                call(
                    ctx,
                    "get_decompress_parameter_nif",
                    &[d, atom("windowLogMax")]
                ),
                Out::Ok(O::Int(27))
            );
            assert_eq!(
                set(ctx, atom("windowLogMax"), small(20)),
                Out::Ok(crate::atom("ok"))
            );
            assert_eq!(
                call(
                    ctx,
                    "get_decompress_parameter_nif",
                    &[d, atom("windowLogMax")]
                ),
                Out::Ok(O::Int(20))
            );
            assert_eq!(
                call(ctx, "get_decompress_parameter_nif", &[d, atom("nokey")]),
                err("invalid_key", crate::atom("nokey"))
            );
        });
    }

    #[test]
    fn the_context_is_checked_before_key_and_value() {
        with_ctx(|ctx| {
            let c = resource(ctx, "init_compress_nif");
            let d = resource(ctx, "init_decompress_nif");
            assert_eq!(
                call(
                    ctx,
                    "set_compress_parameter_nif",
                    &[d, atom("foo"), atom("bar")]
                ),
                Out::Badarg
            );
            assert_eq!(
                call(ctx, "get_compress_parameter_nif", &[d, atom("foo")]),
                Out::Badarg
            );
            assert_eq!(
                call(
                    ctx,
                    "set_decompress_parameter_nif",
                    &[c, atom("foo"), atom("bar")]
                ),
                Out::Badarg
            );
            assert_eq!(
                call(ctx, "get_decompress_parameter_nif", &[c, atom("foo")]),
                Out::Badarg
            );
            assert_eq!(
                call(
                    ctx,
                    "get_compress_parameter_nif",
                    &[atom("ok"), atom("foo")]
                ),
                Out::Badarg
            );
        });
    }

    #[test]
    fn closed_and_foreign_contexts_raise_before_key_and_value() {
        with_ctx(|ctx| {
            let c = resource(ctx, "init_compress_nif");
            let d = resource(ctx, "init_decompress_nif");
            crate::set_caller(Some(small(77)));
            for args in [
                (
                    "set_compress_parameter_nif",
                    vec![c, atom("foo"), atom("bar")],
                ),
                ("get_compress_parameter_nif", vec![c, atom("foo")]),
                (
                    "set_decompress_parameter_nif",
                    vec![d, atom("foo"), atom("bar")],
                ),
                ("get_decompress_parameter_nif", vec![d, atom("foo")]),
            ] {
                assert_eq!(
                    call(ctx, args.0, &args.1),
                    Out::Error(crate::atom("not_on_controlling_process")),
                    "{}",
                    args.0
                );
            }
            crate::set_caller(None);
            assert_eq!(
                call(ctx, "compress_close_nif", &[c]),
                Out::Ok(crate::atom("ok"))
            );
            assert_eq!(
                call(ctx, "decompress_close_nif", &[d]),
                Out::Ok(crate::atom("ok"))
            );
            for args in [
                (
                    "set_compress_parameter_nif",
                    vec![c, atom("foo"), atom("bar")],
                ),
                ("get_compress_parameter_nif", vec![c, atom("foo")]),
                (
                    "set_decompress_parameter_nif",
                    vec![d, atom("foo"), atom("bar")],
                ),
                ("get_decompress_parameter_nif", vec![d, atom("foo")]),
            ] {
                assert_eq!(call(ctx, args.0, &args.1), Out::Badarg, "{}", args.0);
            }
        });
    }

    #[test]
    fn get_uint64_accepts_exactly_the_unsigned_64_bit_range() {
        let mut heap = ProcessHeap::with_words(1 << 12);
        let mut alloc = ProcessHeapHandle(&mut heap);
        let mut builder = TermBuilder::new(&mut alloc);
        let mut int = |value: i128| builder.int_from_i128(value).expect("integer");
        assert_eq!(get_uint64(int(0)), Some(0));
        assert_eq!(get_uint64(int((1 << 59) + 1)), Some((1 << 59) + 1));
        assert_eq!(get_uint64(int((1 << 64) - 1)), Some(u64::MAX));
        assert_eq!(get_uint64(int(1 << 64)), None);
        assert_eq!(get_uint64(int(1 << 100)), None);
        assert_eq!(get_uint64(int(-1)), None);
        assert_eq!(get_uint64(int(-(1 << 63))), None);
        assert_eq!(get_uint64(int(-(1 << 64))), None);
        assert_eq!(get_uint64(atom("a")), None);
        let big = builder.binary(&[7; 4096]).expect("binary");
        assert_eq!(get_uint64(big), None);
    }
}
