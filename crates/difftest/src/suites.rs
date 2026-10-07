//! Data driven stage-1 function inventory and deterministic seeds.
use crate::CompareMode;
use arinsal_etf::OwnedTerm;

/// One registered function and the argument generators future VM agents should use.
#[derive(Debug, Clone)]
pub struct FunctionSpec {
    pub module: &'static str,
    pub function: &'static str,
    pub generators: &'static str,
    pub mode: CompareMode,
}
/// One concrete differential case.
#[derive(Debug, Clone)]
pub struct Case {
    pub name: String,
    pub spec: FunctionSpec,
    pub args: Vec<OwnedTerm>,
}
fn a(s: &str) -> OwnedTerm {
    OwnedTerm::Atom(s.into())
}
fn i(n: i64) -> OwnedTerm {
    OwnedTerm::Int(n)
}
fn b(xs: &[u8]) -> OwnedTerm {
    OwnedTerm::Binary(xs.to_vec())
}
fn t(xs: Vec<OwnedTerm>) -> OwnedTerm {
    OwnedTerm::Tuple(xs)
}
fn l(xs: Vec<OwnedTerm>) -> OwnedTerm {
    if xs.is_empty() {
        OwnedTerm::Nil
    } else {
        OwnedTerm::List {
            elems: xs,
            tail: Box::new(OwnedTerm::Nil),
        }
    }
}
fn s(text: &str) -> OwnedTerm {
    l(text.chars().map(|ch| i(ch as i64)).collect())
}
fn map(xs: Vec<(OwnedTerm, OwnedTerm)>) -> OwnedTerm {
    OwnedTerm::Map(xs)
}
fn add(
    cases: &mut Vec<Case>,
    m: &'static str,
    f: &'static str,
    generators: &'static str,
    args: Vec<OwnedTerm>,
) {
    let name = format!("{m}:{f}/{}", args.len());
    cases.push(Case {
        name,
        spec: FunctionSpec {
            module: m,
            function: f,
            generators,
            mode: CompareMode::Exact,
        },
        args,
    });
}
/// Registered stage-1 cases. Each function retains its generator description.
pub fn stage1() -> Vec<Case> {
    let mut c = Vec::new();
    let nums = l(vec![i(1), i(2), i(3)]);
    for (f, args, g) in [
        ("reverse", vec![nums.clone()], "proper_list"),
        ("sort", vec![l(vec![i(3), i(1), i(2)])], "proper_list"),
        ("seq", vec![i(1), i(10)], "integer,integer"),
        ("member", vec![i(2), nums.clone()], "any_term,proper_list"),
        (
            "nth",
            vec![i(2), nums.clone()],
            "positive_integer,proper_list",
        ),
        (
            "flatten",
            vec![l(vec![i(1), l(vec![i(2)]), i(3)])],
            "nested_list",
        ),
        ("sum", vec![nums.clone()], "numeric_list"),
        (
            "duplicate",
            vec![i(3), a("x")],
            "nonnegative_integer,any_term",
        ),
        (
            "sublist",
            vec![nums.clone(), i(2)],
            "proper_list,nonnegative_integer",
        ),
    ] {
        add(&mut c, "lists", f, g, args);
    }
    let m = map(vec![(a("a"), i(1)), (a("b"), i(2))]);
    let one = map(vec![(a("a"), i(1))]);
    for (f, args, g) in [
        (
            "put",
            vec![a("c"), i(3), m.clone()],
            "any_term,any_term,small_map",
        ),
        ("get", vec![a("a"), m.clone()], "existing_key,small_map"),
        ("find", vec![a("x"), m.clone()], "any_term,small_map"),
        ("remove", vec![a("b"), m.clone()], "any_term,small_map"),
        ("keys", vec![one.clone()], "small_map"),
        ("values", vec![one.clone()], "small_map"),
        ("size", vec![m.clone()], "small_map"),
        ("to_list", vec![one.clone()], "small_map"),
        (
            "from_list",
            vec![l(vec![t(vec![a("a"), i(1)]), t(vec![a("b"), i(2)])])],
            "pair_list",
        ),
        (
            "merge",
            vec![m.clone(), map(vec![(a("b"), i(4))])],
            "small_map,small_map",
        ),
    ] {
        add(&mut c, "maps", f, g, args);
    }
    for (f, args, g) in [
        ("at", vec![b(b"hello"), i(1)], "binary,valid_index"),
        ("first", vec![b(b"hello")], "nonempty_binary"),
        ("last", vec![b(b"hello")], "nonempty_binary"),
        (
            "part",
            vec![b(b"hello"), i(1), i(3)],
            "binary,offset,length",
        ),
        ("match", vec![b(b"hello"), b(b"ll")], "binary,binary"),
        ("split", vec![b(b"a,b"), b(b",")], "binary,binary"),
        ("copy", vec![b(b"xy"), i(3)], "binary,nonnegative_integer"),
        ("encode_hex", vec![b(b"ab")], "binary"),
    ] {
        add(&mut c, "binary", f, g, args);
    }
    for (f, args, g) in [
        ("length", vec![s("héllo")], "unicode_charlist"),
        ("trim", vec![s("  hi  ")], "charlist"),
        ("uppercase", vec![s("hello")], "charlist"),
        ("lowercase", vec![s("HELLO")], "charlist"),
        ("split", vec![s("a,b"), s(",")], "charlist,charlist"),
        ("tokens", vec![s("a b"), s(" ")], "charlist,charlist"),
    ] {
        add(&mut c, "string", f, g, args);
    }
    for (f, args, g) in [
        ("characters_to_binary", vec![s("héllo")], "unicode_charlist"),
        (
            "characters_to_list",
            vec![b("héllo".as_bytes())],
            "utf8_binary",
        ),
        ("bin_is_7bit", vec![b(b"ascii")], "binary"),
    ] {
        add(&mut c, "unicode", f, g, args);
    }
    for (fmt, args) in [
        ("~p", vec![one.clone()]),
        ("~w", vec![t(vec![a("x"), i(1)])]),
        ("~s", vec![s("hello")]),
        ("~ts", vec![s("héllo")]),
        ("~b", vec![i(42)]),
        ("~.16B", vec![i(255)]),
        ("~e", vec![OwnedTerm::Float(1.25)]),
        ("~f", vec![OwnedTerm::Float(1.25)]),
        ("~g", vec![OwnedTerm::Float(1.25)]),
        ("~c", vec![i(65)]),
        ("~-10s", vec![s("hi")]),
        ("~10.3f", vec![OwnedTerm::Float(1.25)]),
        ("~tp", vec![s("hé")]),
        ("~P", vec![nums.clone(), i(4)]),
    ] {
        add(
            &mut c,
            "io_lib",
            "format",
            "format_string,term_list",
            vec![s(fmt), l(args)],
        );
    }
    for (f, args, g) in [
        (
            "element",
            vec![i(2), t(vec![a("a"), a("b")])],
            "positive_integer,tuple",
        ),
        (
            "setelement",
            vec![i(1), t(vec![a("a"), a("b")]), a("z")],
            "positive_integer,tuple,any_term",
        ),
        ("tuple_to_list", vec![t(vec![i(1), a("a")])], "tuple"),
        ("atom_to_list", vec![a("café")], "atom"),
        ("integer_to_list", vec![i(255), i(16)], "integer,base"),
        ("list_to_integer", vec![s("ff"), i(16)], "digit_list,base"),
        ("binary_to_list", vec![b(b"abc")], "binary"),
        ("term_to_binary", vec![one.clone()], "any_term"),
        (
            "binary_to_term",
            vec![b(&[131, 97, 42])],
            "valid_etf_binary",
        ),
        ("phash2", vec![m.clone()], "any_term"),
        ("abs", vec![i(-9)], "number"),
        ("trunc", vec![OwnedTerm::Float(-1.9)], "number"),
        ("round", vec![OwnedTerm::Float(2.5)], "number"),
        ("float", vec![i(42)], "number"),
        ("+", vec![i(2), i(3)], "number,number"),
        ("-", vec![i(2), i(3)], "number,number"),
        ("*", vec![i(2), i(3)], "number,number"),
        ("/", vec![i(7), i(2)], "number,number"),
        ("<", vec![i(2), i(3)], "any_term,any_term"),
        ("==", vec![i(2), OwnedTerm::Float(2.0)], "any_term,any_term"),
        (
            "=:=",
            vec![i(2), OwnedTerm::Float(2.0)],
            "any_term,any_term",
        ),
        ("bsl", vec![i(1), i(8)], "integer,integer"),
        ("bsr", vec![i(256), i(4)], "integer,integer"),
        ("band", vec![i(7), i(3)], "integer,integer"),
        ("bor", vec![i(4), i(3)], "integer,integer"),
        ("bxor", vec![i(7), i(3)], "integer,integer"),
        ("bnot", vec![i(7)], "integer"),
        ("div", vec![i(7), i(2)], "integer,nonzero_integer"),
        ("rem", vec![i(7), i(2)], "integer,nonzero_integer"),
    ] {
        add(&mut c, "erlang", f, g, args);
    }
    c
}
