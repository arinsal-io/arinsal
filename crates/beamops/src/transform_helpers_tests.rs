//! Tests of the ported predicate and generator bodies on operations built by hand, with the
//! results the C bodies give (beam/generators.tab, beam/predicates.tab, beam_transform_helpers.c).

use crate::beam_op::*;
use crate::erts_tables::*;
use crate::loader_state::{LoaderState, RestArgs, am, bif_id};
use crate::transform_helpers::{generators, predicates};
use arinsal_beam::{BeamFile, parse};
use arinsal_term::{atoms, global_atoms};

fn arg(ty: u8, val: u64) -> BeamOpArg {
    BeamOpArg::new(ty, val)
}

fn lists_beam() -> Option<BeamFile> {
    let output = std::process::Command::new("erl")
        .args([
            "-noshell",
            "-eval",
            "io:format(\"~s\", [code:which(lists)]), halt().",
        ])
        .output()
        .ok()?;
    let path = String::from_utf8(output.stdout).ok()?;
    parse(&std::fs::read(path.trim()).ok()?).ok()
}

/// An operation with the given operands, as a rule leaves it for a generator.
fn op_with(st: &mut LoaderState, args: &[BeamOpArg]) -> RestArgs {
    let id = st.new_op(GENOP_SELECT_VAL_3, args.len());
    st.ops.op_mut(id).spill(args.len(), 0);
    for (at, value) in args.iter().enumerate() {
        st.ops.op_mut(id).set_a(at, *value);
    }
    RestArgs {
        op: id,
        start: 0,
        len: args.len(),
    }
}

fn pairs(values: &[(u64, u64)]) -> Vec<BeamOpArg> {
    values
        .iter()
        .flat_map(|(v, l)| [arg(TAG_I, *v), arg(TAG_F, *l)])
        .collect()
}

#[test]
fn am_constants_are_the_atom_table_indexes() {
    assert_eq!(am("all"), u64::from(atoms::ALL.0));
    assert_eq!(am("erlang"), u64::from(atoms::ERLANG.0));
    assert_eq!(am("no_fail"), u64::from(atoms::NO_FAIL.0));
    for name in [
        "perf_counter",
        "call_on_load_function",
        "=:=",
        "ensure_exactly",
    ] {
        assert_eq!(
            u64::from(global_atoms().intern(name).unwrap().0),
            am(name),
            "{name}"
        );
    }
}

#[test]
fn bif_ids_name_the_bif_table_entries() {
    let spec = |id: u16| &arinsal_spec::BIFS[usize::from(id)];
    assert_eq!(spec(bif_id("splus_2")).name, "+");
    assert_eq!(spec(bif_id("and_2")).name, "and");
    assert_eq!(spec(bif_id("tuple_size_1")).name, "tuple_size");
    assert_eq!(spec(bif_id("node_0")).arity, 0);
}

#[test]
fn select_val_sorts_the_values_and_splits_the_labels() {
    let Some(beam) = lists_beam() else {
        eprintln!("erl unavailable; skipping");
        return;
    };
    let mut st = LoaderState::new(&beam, None, 0).unwrap();
    let rest = op_with(&mut st, &pairs(&[(5, 50), (3, 30), (9, 90)]));
    let op =
        generators::select_val(&mut st, arg(TAG_X, 0), arg(TAG_F, 1), arg(TAG_U, 6), rest).unwrap();
    let o = st.ops.op(op);
    assert_eq!(o.op, GENOP_I_SELECT_VAL_LINS_3);
    let vals: Vec<(u8, u64)> = o.args().iter().map(|a| (a.ty, a.val)).collect();
    assert_eq!(
        vals,
        [
            (TAG_X, 0),
            (TAG_F, 1),
            (TAG_U, 6),
            (TAG_I, 3),
            (TAG_I, 5),
            (TAG_I, 9),
            (TAG_F, 30),
            (TAG_F, 50),
            (TAG_F, 90)
        ]
    );
}

#[test]
fn jump_tab_fills_gaps_with_the_failure_label() {
    let Some(beam) = lists_beam() else {
        eprintln!("erl unavailable; skipping");
        return;
    };
    let mut st = LoaderState::new(&beam, None, 0).unwrap();
    let rest = op_with(&mut st, &pairs(&[(10, 1), (12, 2), (13, 3)]));
    assert!(predicates::use_jump_tab(&mut st, arg(TAG_U, 6), rest, 3));
    let op =
        generators::jump_tab(&mut st, arg(TAG_X, 0), arg(TAG_F, 99), arg(TAG_U, 6), rest).unwrap();
    let o = st.ops.op(op);
    assert_eq!(o.op, GENOP_I_JUMP_ON_VAL_4);
    let table: Vec<u64> = o.args()[4..].iter().map(|a| a.val).collect();
    assert_eq!(table, [1, 99, 2, 3]);
    assert_eq!((o.a(2).val, o.a(3).val), (10, 4));
}

#[test]
fn map_key_sort_orders_keys_like_a_flatmap() {
    let Some(beam) = lists_beam() else {
        eprintln!("erl unavailable; skipping");
        return;
    };
    let mut st = LoaderState::new(&beam, None, 0).unwrap();
    let rest = op_with(
        &mut st,
        &[
            arg(TAG_I, 7),
            arg(TAG_X, 1),
            arg(TAG_N, 0),
            arg(TAG_X, 2),
            arg(TAG_I, 3),
            arg(TAG_X, 3),
        ],
    );
    assert!(predicates::map_key_sort(&mut st, arg(TAG_U, 6), rest));
    let keys: Vec<(u8, u64)> = (0..3)
        .map(|k| {
            let a = rest.get(&st, 2 * k);
            (a.ty, a.val)
        })
        .collect();
    // Numbers sort before NIL in term order.
    assert_eq!(keys, [(TAG_I, 3), (TAG_I, 7), (TAG_N, 0)]);
    assert_eq!(rest.get(&st, 1).val, 3);
    assert_eq!(rest.get(&st, 5).val, 2);
    // A variable key among several is refused.
    let bad = op_with(
        &mut st,
        &[arg(TAG_X, 0), arg(TAG_X, 1), arg(TAG_I, 3), arg(TAG_X, 3)],
    );
    assert!(!predicates::map_key_sort(&mut st, arg(TAG_U, 4), bad));
}

#[test]
fn registers_compare_without_their_type_index() {
    let Some(beam) = lists_beam() else {
        eprintln!("erl unavailable; skipping");
        return;
    };
    let mut st = LoaderState::new(&beam, None, 0).unwrap();
    let typed = arg(TAG_X, 3 | (5 << 10));
    assert!(predicates::equal(&mut st, typed, arg(TAG_X, 3)));
    assert!(!predicates::distinct(&mut st, typed, arg(TAG_X, 3)));
    assert!(predicates::equal(&mut st, arg(TAG_N, 0), arg(TAG_N, 5)));
    assert!(predicates::consecutive_xregs(
        &mut st,
        arg(TAG_X, 6),
        arg(TAG_X, 7)
    ));
    assert!(!predicates::consecutive_xregs(
        &mut st,
        arg(TAG_X, 5),
        arg(TAG_X, 6)
    ));
}

#[test]
fn bs_match_with_an_unknown_command_becomes_bad_bs_match() {
    let Some(beam) = lists_beam() else {
        eprintln!("erl unavailable; skipping");
        return;
    };
    let mut st = LoaderState::new(&beam, None, 0).unwrap();
    let unknown = arg(TAG_A, am("hibernate"));
    let rest = op_with(&mut st, &[unknown]);
    let op =
        generators::bs_match(&mut st, arg(TAG_F, 1), arg(TAG_X, 0), arg(TAG_U, 1), rest).unwrap();
    assert_eq!(st.ops.op(op).op, GENOP_BAD_BS_MATCH_1);
    assert_eq!(st.ops.op(op).a(0), unknown);
}
