//! The bodies of the predicates (`pred.*`) and generators (`gen.*`) of the transformation rules.
//! In erts they are C blocks of the `.tab` files that `beam_makeops` copies into
//! `beam_opcodes.c` as `static int name(LoaderState* S, ...)` and `static BeamOp* name(...)`;
//! here they are ported by hand under the same names and parameter order (OTP-29.1.1:
//! beam/predicates.tab, beam/generators.tab, beam/jit/arm/predicates.tab,
//! beam/jit/arm/generators.tab, beam/beam_transform_helpers.c).

use crate::beam_op::*;
use crate::erts_tables::*;
use crate::loader_state::{LoaderState, RestArgs, am};
use crate::{LiteralElement, NewLiteral};
use arinsal_etf::OwnedTerm;
use arinsal_spec::BifKind;
use arinsal_term::{Atom, Term, flat_key_cmp, global_atoms, internal_hash};

/// `MAP_SMALL_MAP_LIMIT` (erl_map.h).
const MAP_SMALL_MAP_LIMIT: u64 = 32;
/// `REG_MASK` (erl_vm.h).
const REG_MASK: u64 = 1023;
/// `SCRATCH_X_REG`.
const SCRATCH_X_REG: u64 = 1023;
/// `BSF_LITTLE` and `BSF_NATIVE` (erl_bits.h).
const BSF_LITTLE: u64 = 2;
const BSF_NATIVE: u64 = 16;

const AM_ERLANG: u64 = am("erlang");
const AM_EQ: u64 = am("=:=");
const AM_NEQ: u64 = am("=/=");
const AM_LT: u64 = am("<");
const AM_GE: u64 = am(">=");
const AM_ERROR: u64 = am("error");
const AM_EXIT: u64 = am("exit");
const AM_THROW: u64 = am("throw");
const AM_NIF_ERROR: u64 = am("nif_error");
const AM_IS_FUNCTION: u64 = am("is_function");
const AM_ENSURE_EXACTLY: u64 = am("ensure_exactly");
const AM_SKIP: u64 = am("skip");
const AM_ENSURE_AT_LEAST: u64 = am("ensure_at_least");
const AM_GET_TAIL: u64 = am("get_tail");
const AM_BINARY: u64 = am("binary");
const AM_INTEGER: u64 = am("integer");
const AM_STRING: u64 = am("string");
const AM_PRIVATE_APPEND: u64 = am("private_append");
const AM_BADRECORD: u64 = am("badrecord");

/// `nofail_bifs` of `never_fails`.
const NOFAIL_BIFS: [u64; 21] = [
    am("/="),
    am("<"),
    am("=/="),
    am("=:="),
    am("=<"),
    am("=="),
    am(">"),
    am(">="),
    am("is_atom"),
    am("is_boolean"),
    am("is_binary"),
    am("is_bitstring"),
    am("is_float"),
    am("is_integer"),
    am("is_list"),
    am("is_map"),
    am("is_number"),
    am("is_pid"),
    am("is_port"),
    am("is_reference"),
    am("is_tuple"),
];

fn arg(ty: u8, val: u64) -> BeamOpArg {
    BeamOpArg::new(ty, val)
}

/// `Rest[k].val` as the C `Sint` the helpers compare with.
fn sint(value: u64) -> i64 {
    value as i64
}

/// The `BSF_NATIVE` fix-up macro of generators.tab (`fix_native_endian`) for a little-endian
/// host.
fn fix_native_endian(flags: u64) -> u64 {
    if flags & BSF_NATIVE != 0 {
        (flags & !BSF_NATIVE) | BSF_LITTLE
    } else {
        flags
    }
}

/// `erts_pd_make_hx` (erl_process_dict.c, `MAKE_HASH`).
fn pd_make_hx(term: Term) -> u64 {
    if let Some(small) = term.as_small() {
        small as u64 & ((1 << 60) - 1)
    } else if let Some(atom) = term.as_atom() {
        u64::from(atom.0)
    } else {
        internal_hash(term)
    }
}

/// `hashmap_make_hash` (erl_map.h, `erts_map_hash`).
fn hashmap_make_hash(term: Term) -> u64 {
    internal_hash(term)
}

/// `beam_load_sort_select_vals` (beam_transform_helpers.c): sorts `n` (value, label) pairs by the
/// value; `qsort` is unstable, but the values of a valid select are distinct.
fn sort_select_vals(args: &mut [BeamOpArg], n: usize) {
    let mut pairs: Vec<[BeamOpArg; 2]> = args[..2 * n].chunks(2).map(|c| [c[0], c[1]]).collect();
    pairs.sort_by_key(|pair| pair[0].val);
    for (at, pair) in pairs.iter().enumerate() {
        args[2 * at] = pair[0];
        args[2 * at + 1] = pair[1];
    }
}

/// The import an operand designates, if it is a valid import index.
fn import_of(st: &LoaderState, bif: BeamOpArg) -> Option<crate::loader_state::ImportEntry> {
    if bif.ty == TAG_U {
        st.imports.get(bif.val as usize).copied()
    } else {
        None
    }
}

fn is_erlang_function_of_arity_2(st: &LoaderState, bif: BeamOpArg, function: u64) -> bool {
    import_of(st, bif)
        .is_some_and(|e| e.module == AM_ERLANG && e.function == function && e.arity == 2)
}

pub(crate) mod predicates {
    use super::*;

    pub(crate) fn consecutive_words(_st: &mut LoaderState, a1: BeamOpArg, a2: BeamOpArg) -> bool {
        a1.ty == a2.ty && a1.val + 1 == a2.val
    }

    pub(crate) fn consecutive_xregs(_st: &mut LoaderState, a1: BeamOpArg, a2: BeamOpArg) -> bool {
        // The following value must be the same as in beam_asm.hpp.
        const NUM_REGISTER_BACKED_XREGS: u64 = 6;
        a1.ty == TAG_X
            && a2.ty == TAG_X
            && a1.val + 1 == a2.val
            && a1.val >= NUM_REGISTER_BACKED_XREGS
    }

    pub(crate) fn distinct(_st: &mut LoaderState, val1: BeamOpArg, val2: BeamOpArg) -> bool {
        if val1.ty != val2.ty {
            true
        } else if val1.ty == TAG_X || val1.ty == TAG_Y {
            // We must not compare the type indices (if any).
            (val1.val & REG_MASK) != (val2.val & REG_MASK)
        } else if val1.ty == TAG_N {
            // NIL has no associated value.
            false
        } else {
            val1.val != val2.val
        }
    }

    pub(crate) fn equal(_st: &mut LoaderState, val1: BeamOpArg, val2: BeamOpArg) -> bool {
        if val1.ty != val2.ty {
            false
        } else if val1.ty == TAG_X || val1.ty == TAG_Y {
            // We must not compare the type indices (if any).
            (val1.val & REG_MASK) == (val2.val & REG_MASK)
        } else if val1.ty == TAG_N {
            // NIL has no associated value.
            true
        } else {
            val1.val == val2.val
        }
    }

    pub(crate) fn fixed_size_values(st: &mut LoaderState, size: BeamOpArg, rest: RestArgs) -> bool {
        if size.val < 2 || !size.val.is_multiple_of(2) {
            return false;
        }
        let mut i = 0;
        while i < size.val as usize {
            if rest.get(st, i + 1).ty != TAG_F {
                return false;
            }
            match rest.get(st, i).ty {
                TAG_A | TAG_I | TAG_V => {}
                TAG_Q => {
                    let literal = rest.get(st, i).val;
                    return matches!(st.literals.owned(literal), Some(OwnedTerm::Float(_)));
                }
                _ => return false,
            }
            i += 2;
        }
        true
    }

    pub(crate) fn floats_or_bignums(st: &mut LoaderState, size: BeamOpArg, rest: RestArgs) -> bool {
        if size.val < 2 || !size.val.is_multiple_of(2) {
            return false;
        }
        let mut i = 0;
        while i < size.val as usize {
            if rest.get(st, i).ty != TAG_Q {
                return false;
            }
            if rest.get(st, i + 1).ty != TAG_F {
                return false;
            }
            i += 2;
        }
        true
    }

    pub(crate) fn instrumenting_line_breakpoints(st: &mut LoaderState) -> bool {
        st.line_breakpoints_enabled()
    }

    pub(crate) fn is_empty_map(st: &mut LoaderState, lit: BeamOpArg) -> bool {
        if lit.ty != TAG_Q {
            return false;
        }
        matches!(st.literals.owned(lit.val), Some(OwnedTerm::Map(pairs)) if pairs.is_empty())
    }

    pub(crate) fn is_eq_exact_bif(st: &mut LoaderState, bif: BeamOpArg) -> bool {
        is_erlang_function_of_arity_2(st, bif, AM_EQ)
    }

    pub(crate) fn is_exit_bif(st: &mut LoaderState, bif: BeamOpArg) -> bool {
        let Some(import) = import_of(st, bif) else {
            return false;
        };
        if import.module != AM_ERLANG {
            return false;
        }
        match import.function {
            AM_ERROR => (1..=3).contains(&import.arity),
            AM_EXIT => import.arity == 1,
            AM_THROW => import.arity == 1,
            AM_NIF_ERROR => import.arity == 1 || import.arity == 2,
            _ => false,
        }
    }

    pub(crate) fn is_ge_bif(st: &mut LoaderState, bif: BeamOpArg) -> bool {
        is_erlang_function_of_arity_2(st, bif, AM_GE)
    }

    pub(crate) fn is_heavy_bif(st: &mut LoaderState, bif: BeamOpArg) -> bool {
        // `erts_active_export_entry(...)->bif_number`, which `bif_imports` caches per import.
        if import_of(st, bif).is_none() {
            return false;
        }
        match st.bif_imports[bif.val as usize] {
            Some(number) => arinsal_spec::BIFS[usize::from(number)].kind == BifKind::Hbif,
            None => false,
        }
    }

    pub(crate) fn is_lt_bif(st: &mut LoaderState, bif: BeamOpArg) -> bool {
        is_erlang_function_of_arity_2(st, bif, AM_LT)
    }

    pub(crate) fn is_mfa_bif(
        _st: &mut LoaderState,
        m: BeamOpArg,
        f: BeamOpArg,
        a: BeamOpArg,
    ) -> bool {
        debug_assert!(m.ty == TAG_A && f.ty == TAG_A && a.ty == TAG_U);
        let table = global_atoms();
        let (Some(module), Some(function), Ok(arity)) = (
            table.text(Atom(m.val as u32)),
            table.text(Atom(f.val as u32)),
            u8::try_from(a.val),
        ) else {
            return false;
        };
        arinsal_spec::bif_lookup(module, function, arity).is_some()
    }

    pub(crate) fn is_ne_exact_bif(st: &mut LoaderState, bif: BeamOpArg) -> bool {
        is_erlang_function_of_arity_2(st, bif, AM_NEQ)
    }

    pub(crate) fn is_small_map_literal_keys(
        st: &mut LoaderState,
        size: BeamOpArg,
        rest: RestArgs,
    ) -> bool {
        let pair_count = size.val / 2;
        if pair_count > MAP_SMALL_MAP_LIMIT {
            return false;
        }
        // Operations with non-literals have always only one key.
        if pair_count != 1 {
            return true;
        }
        matches!(rest.get(st, 0).ty, TAG_A | TAG_I | TAG_N | TAG_Q)
    }

    pub(crate) fn map_key_sort(st: &mut LoaderState, size: BeamOpArg, rest: RestArgs) -> bool {
        beam_load_map_key_sort(st, size, rest)
    }

    pub(crate) fn mixed_types(st: &mut LoaderState, size: BeamOpArg, rest: RestArgs) -> bool {
        if size.val < 2 || !size.val.is_multiple_of(2) {
            return false;
        }
        let ty = rest.get(st, 0).ty;
        let mut i = 0;
        while i < size.val as usize {
            if rest.get(st, i).ty != ty {
                return true;
            }
            i += 2;
        }
        false
    }

    pub(crate) fn never(_st: &mut LoaderState) -> bool {
        false
    }

    pub(crate) fn never_fails(st: &mut LoaderState, bif: BeamOpArg) -> bool {
        let Some(entry) = import_of(st, bif) else {
            return false;
        };
        if entry.module != AM_ERLANG {
            return false;
        }
        if entry.function == AM_IS_FUNCTION {
            // Note that is_function/2 may fail.
            return entry.arity == 1;
        }
        NOFAIL_BIFS.contains(&entry.function)
    }

    pub(crate) fn smp_already_locked(st: &mut LoaderState, l: BeamOpArg) -> bool {
        debug_assert!(l.ty == TAG_U);
        st.labels[l.val as usize].looprec_targeted
    }

    pub(crate) fn smp_mark_target_label(st: &mut LoaderState, l: BeamOpArg) -> bool {
        debug_assert!(l.ty == TAG_F);
        st.labels[l.val as usize].looprec_targeted = true;
        true
    }

    pub(crate) fn use_jump_tab(
        st: &mut LoaderState,
        size: BeamOpArg,
        rest: RestArgs,
        min_size: u64,
    ) -> bool {
        if size.val < 2 * min_size || !size.val.is_multiple_of(2) {
            return false;
        }
        if rest.get(st, 0).ty != TAG_I || rest.get(st, 1).ty != TAG_F {
            // Atoms. Can't use a jump table.
            return false;
        }
        let mut min = sint(rest.get(st, 0).val);
        let mut max = min;
        let mut i = 2;
        while i < size.val as usize {
            let key = rest.get(st, i);
            if key.ty != TAG_I || rest.get(st, i + 1).ty != TAG_F {
                return false;
            }
            if sint(key.val) < min {
                min = sint(key.val);
            } else if max < sint(key.val) {
                max = sint(key.val);
            }
            i += 2;
        }
        (max - min) as u64 <= size.val
    }
}

/// `beam_load_map_key_sort` (beam_transform_helpers.c): sorts the key/value pairs of `rest` in
/// place by the order of flatmap keys; `false` when a key is not a literal.
fn beam_load_map_key_sort(st: &mut LoaderState, size: BeamOpArg, rest: RestArgs) -> bool {
    let size = size.val as usize;
    if size == 2 {
        return true; // Already sorted.
    }
    let mut keyed: Vec<(Term, BeamOpArg, BeamOpArg)> = Vec::with_capacity(size / 2);
    let mut i = 0;
    while i < size {
        let key = rest.get(st, i);
        let term = match key.ty {
            TAG_A | TAG_I | TAG_N | TAG_Q => st.get_term(key),
            // Not a literal key. Not allowed. Only a single variable key is allowed in each map
            // instruction.
            _ => return false,
        };
        let Some(term) = term else { return false };
        keyed.push((term, key, rest.get(st, i + 1)));
        i += 2;
    }
    keyed.sort_by(|a, b| flat_key_cmp(a.0, b.0));
    for (at, (_, key, value)) in keyed.into_iter().enumerate() {
        let op = st.ops.op_mut(rest.op);
        op.set_a(rest.start + 2 * at, key);
        op.set_a(rest.start + 2 * at + 1, value);
    }
    true
}

#[allow(clippy::too_many_arguments)]
pub(crate) mod generators {
    use super::*;

    pub(crate) fn bs_match(
        st: &mut LoaderState,
        fail: BeamOpArg,
        ctx: BeamOpArg,
        n: BeamOpArg,
        list: RestArgs,
    ) -> Option<OpId> {
        // If a BEAM file produced by a later version of Erlang/OTP is accidentally loaded into
        // an earlier version, ensure that the loading fails (as opposed to crashing the runtime)
        // if there are any unknown sub commands.
        let mut i = 0usize;
        while i < n.val as usize {
            let current = list.get(st, i);
            i += 1;
            let known = current.ty == TAG_A
                && match current.val {
                    AM_ENSURE_EXACTLY | AM_SKIP => {
                        i += 1;
                        true
                    }
                    AM_ENSURE_AT_LEAST => {
                        i += 2;
                        true
                    }
                    AM_GET_TAIL | AM_EQ => {
                        i += 3;
                        true
                    }
                    AM_BINARY | AM_INTEGER => {
                        i += 5;
                        true
                    }
                    _ => false,
                };
            if !known {
                let op = st.new_op(GENOP_BAD_BS_MATCH_1, 1);
                st.ops.op_mut(op).set_a(0, current);
                return Some(op);
            }
        }

        // Make sure that we don't attempt to pass any overflow tags to the JIT.
        let op = st.new_op(GENOP_I_BS_MATCH_2, 2);
        let fixed_args = 2;
        debug_assert!(st.ops.op(op).uses_def_args());
        st.ops.op_mut(op).spill(n.val as usize + fixed_args, 0);
        st.ops.op_mut(op).set_a(0, fail);
        st.ops.op_mut(op).set_a(1, ctx);
        for i in 0..n.val as usize {
            let current = list.get(st, i);
            if current.ty == TAG_O {
                // An overflow tag (in ensure_at_least or ensure_exactly) means that the match
                // will always fail.
                let o = st.ops.op_mut(op);
                o.op = GENOP_JUMP_1;
                o.arity = 1;
                o.set_a(0, fail);
                return Some(op);
            }
            st.ops.op_mut(op).set_a(i + fixed_args, current);
        }
        Some(op)
    }

    pub(crate) fn create_bin(
        st: &mut LoaderState,
        fail: BeamOpArg,
        alloc: BeamOpArg,
        live: BeamOpArg,
        unit: BeamOpArg,
        dst: BeamOpArg,
        n: BeamOpArg,
        segments: RestArgs,
    ) -> Option<OpId> {
        let _ = unit;
        let mut op = st.new_op(GENOP_I_BS_CREATE_BIN_4, 4);
        let fixed_args = 4;
        debug_assert!(st.ops.op(op).uses_def_args());
        st.ops.op_mut(op).spill(n.val as usize + fixed_args, 0);
        {
            let o = st.ops.op_mut(op);
            o.set_a(0, fail);
            o.set_a(1, alloc);
            o.set_a(2, live);
            o.set_a(3, dst);
        }

        let mut i = 0usize;
        while i < n.val as usize {
            let mut flags_value = 0u64;

            // Copy all but flags.
            for k in [0, 1, 2, 4, 5] {
                let value = segments.get(st, i + k);
                st.ops.op_mut(op).set_a(i + fixed_args + k, value);
            }

            // Translate flags.
            let flags = segments.get(st, i + 3);
            if flags.ty == TAG_Q
                && let Some(OwnedTerm::List { elems, tail }) = st.literals.owned(flags.val)
            {
                for elem in elems {
                    match elem {
                        OwnedTerm::Atom(name) if name == "little" => flags_value |= BSF_LITTLE,
                        OwnedTerm::Atom(name) if name == "native" => flags_value |= BSF_NATIVE,
                        _ => {}
                    }
                }
                debug_assert!(matches!(**tail, OwnedTerm::Nil));
            }
            let flags = arg(TAG_U, fix_native_endian(flags_value));
            st.ops.op_mut(op).set_a(i + fixed_args + 3, flags);

            // Replace short string segments with integer segments. Integer segments can be
            // combined with adjacent integer segments for better performance.
            if st.ops.op(op).a(i + fixed_args).val == AM_STRING {
                let mut num_chars = st.ops.op(op).a(i + fixed_args + 5).val as i64;
                if num_chars <= 4 {
                    let index = st.ops.op(op).a(i + fixed_args + 4).val as usize;
                    let mut num = 0u64;
                    let o = st.ops.op_mut(op);
                    let mut ty = o.a(i + fixed_args);
                    ty.val = AM_INTEGER;
                    o.set_a(i + fixed_args, ty);
                    let mut size = o.a(i + fixed_args + 2);
                    size.val = 8;
                    o.set_a(i + fixed_args + 2, size);
                    let mut count = o.a(i + fixed_args + 5);
                    count.val = num_chars as u64;
                    o.set_a(i + fixed_args + 5, count);
                    let mut at = index;
                    while num_chars > 0 {
                        num_chars -= 1;
                        num = num << 8 | u64::from(st.beam.strings[at]);
                        at += 1;
                    }
                    st.ops.op_mut(op).set_a(i + fixed_args + 4, arg(TAG_I, num));
                }
            }
            i += 6;
        }

        if st.ops.op(op).arity > 4 && st.ops.op(op).a(4).val == AM_PRIVATE_APPEND && alloc.val != 0
        {
            let th = st.new_op(GENOP_TEST_HEAP_2, 2);
            {
                let t = st.ops.op_mut(th);
                t.set_a(0, alloc);
                t.set_a(1, live);
                t.next = Some(op);
            }
            let mut a1 = st.ops.op(op).a(1);
            a1.val = 0;
            st.ops.op_mut(op).set_a(1, a1);
            op = th;
        }
        Some(op)
    }

    pub(crate) fn create_local_record(
        st: &mut LoaderState,
        name: BeamOpArg,
        dst: BeamOpArg,
        live: BeamOpArg,
        size: BeamOpArg,
        new: RestArgs,
    ) -> Option<OpId> {
        let mut def: Option<u64> = None;
        let wanted = global_atoms().text(Atom(name.val as u32));
        for (i, record) in st.beam.records.iter().enumerate() {
            if wanted == Some(record.name.as_str()) {
                def = Some(st.literals.record_defs[i]);
                break;
            }
        }

        debug_assert!(size.ty == TAG_U);
        let n = size.val as usize;

        let op = st.new_op(GENOP_CREATE_LOCAL_NATIVE_RECORD_4, 4);
        debug_assert!(st.ops.op(op).uses_def_args());
        st.ops.op_mut(op).spill(4 + n, 0);

        let first = match def {
            Some(index) => arg(TAG_Q, index),
            // This record does not have a definition. This should not happen. Force an error at
            // load-time.
            None => arg(TAG_A, AM_BADRECORD),
        };
        {
            let o = st.ops.op_mut(op);
            o.set_a(0, first);
            o.set_a(1, dst);
            o.set_a(2, live);
            o.set_a(3, arg(TAG_U, n as u64));
        }
        for i in 0..n {
            let value = new.get(st, i);
            st.ops.op_mut(op).set_a(4 + i, value);
        }
        Some(op)
    }

    pub(crate) fn func_end(
        st: &mut LoaderState,
        _func_label: BeamOpArg,
        entry_label: BeamOpArg,
    ) -> Option<OpId> {
        let mut op: Option<OpId> = None;

        if let Some(index) = st.labels[entry_label.val as usize].lambda_index {
            let (arity, num_free) = {
                let lambda_entry = &st.beam.lambdas[index];
                (lambda_entry.arity, lambda_entry.num_free)
            };
            if num_free > 0 {
                let lambda = st.new_op(GENOP_I_LAMBDA_TRAMPOLINE_4, 4);
                {
                    let l = st.ops.op_mut(lambda);
                    l.set_a(0, arg(TAG_U, index as u64));
                    l.set_a(1, entry_label);
                    l.set_a(2, arg(TAG_U, u64::from(arity)));
                    l.set_a(3, arg(TAG_U, u64::from(num_free)));
                    l.next = op;
                }
                op = Some(lambda);
            }
        }

        if st.may_load_nif
            && st
                .are_nifs
                .as_ref()
                .is_none_or(|are_nifs| are_nifs[st.function_number - 1])
        {
            let padding = st.new_op(GENOP_I_NIF_PADDING_0, 0);
            st.ops.op_mut(padding).next = op;
            op = Some(padding);
        }

        if op.is_none() {
            // Workaround for the fact that we have to return an instruction from generators. The
            // loader will remove this dummy instruction.
            op = Some(st.new_op(GENOP_DELETE_ME_0, 0));
        }
        op
    }

    pub(crate) fn get(st: &mut LoaderState, src: BeamOpArg, dst: BeamOpArg) -> Option<OpId> {
        let op = st.new_op(0, 0);
        match st.get_term(src) {
            Some(key_term) => {
                let o = st.ops.op_mut(op);
                o.op = GENOP_I_GET_HASH_3;
                o.arity = 3;
                o.set_a(0, src);
                o.set_a(1, arg(TAG_U, pd_make_hx(key_term)));
                o.set_a(2, dst);
            }
            None => {
                let o = st.ops.op_mut(op);
                o.op = GENOP_I_GET_2;
                o.arity = 2;
                o.set_a(0, src);
                o.set_a(1, dst);
            }
        }
        Some(op)
    }

    pub(crate) fn get_float2(
        st: &mut LoaderState,
        fail: BeamOpArg,
        ms: BeamOpArg,
        live: BeamOpArg,
        size: BeamOpArg,
        unit: BeamOpArg,
        flags: BeamOpArg,
        dst: BeamOpArg,
    ) -> Option<OpId> {
        let flags = fix_native_endian(flags.val);
        let op = st.new_op(GENOP_I_BS_GET_FLOAT2_6, 6);
        let o = st.ops.op_mut(op);
        o.set_a(0, ms);
        o.set_a(1, fail);
        o.set_a(2, live);
        o.set_a(3, size);
        o.set_a(4, arg(TAG_U, (unit.val << 3) | flags));
        o.set_a(5, dst);
        Some(op)
    }

    pub(crate) fn get_map_element(
        st: &mut LoaderState,
        fail: BeamOpArg,
        src: BeamOpArg,
        size: BeamOpArg,
        rest: RestArgs,
    ) -> Option<OpId> {
        debug_assert!(size.ty == TAG_U);
        let op = st.new_op(0, 0);
        let key = rest.get(st, 0);
        let value = rest.get(st, 1);
        {
            let o = st.ops.op_mut(op);
            o.set_a(0, fail);
            o.set_a(1, src);
            o.set_a(2, key);
        }
        match st.get_term(key) {
            Some(key_term) => {
                let o = st.ops.op_mut(op);
                o.op = GENOP_I_GET_MAP_ELEMENT_HASH_5;
                o.arity = 5;
                o.set_a(3, arg(TAG_U, hashmap_make_hash(key_term)));
                o.set_a(4, value);
            }
            None => {
                let o = st.ops.op_mut(op);
                o.op = GENOP_I_GET_MAP_ELEMENT_4;
                o.arity = 4;
                o.set_a(3, value);
            }
        }
        Some(op)
    }

    pub(crate) fn get_map_elements(
        st: &mut LoaderState,
        fail: BeamOpArg,
        src: BeamOpArg,
        size: BeamOpArg,
        rest: RestArgs,
    ) -> Option<OpId> {
        debug_assert!(size.ty == TAG_U);
        let op = st.new_op(GENOP_I_GET_MAP_ELEMENTS_3, 3);
        let pairs = size.val as usize / 2;
        debug_assert!(st.ops.op(op).uses_def_args());
        st.ops.op_mut(op).spill(3 + 3 * pairs, 0);
        {
            let o = st.ops.op_mut(op);
            o.set_a(0, fail);
            o.set_a(1, src);
            o.set_a(2, arg(TAG_U, 3 * pairs as u64));
        }
        let mut dst = 3;
        for i in 0..pairs {
            let key = rest.get(st, 2 * i);
            let value = rest.get(st, 2 * i + 1);
            // The rules guarantee literal keys; a non-literal key has no hash to store.
            let hash = st.get_term(key).map_or(0, hashmap_make_hash);
            let o = st.ops.op_mut(op);
            o.set_a(dst, key);
            o.set_a(dst + 1, value);
            o.set_a(dst + 2, arg(TAG_U, hash));
            dst += 3;
        }
        Some(op)
    }

    pub(crate) fn get_utf16(
        st: &mut LoaderState,
        fail: BeamOpArg,
        ms: BeamOpArg,
        flags: BeamOpArg,
        dst: BeamOpArg,
    ) -> Option<OpId> {
        let mut flags = flags;
        flags.val = fix_native_endian(flags.val);
        let op = st.new_op(GENOP_I_BS_GET_UTF16_4, 4);
        let o = st.ops.op_mut(op);
        o.set_a(0, ms);
        o.set_a(1, fail);
        o.set_a(2, flags);
        o.set_a(3, dst);
        Some(op)
    }

    pub(crate) fn has_map_fields(
        st: &mut LoaderState,
        fail: BeamOpArg,
        src: BeamOpArg,
        size: BeamOpArg,
        rest: RestArgs,
    ) -> Option<OpId> {
        debug_assert!(size.ty == TAG_U);
        let n = size.val as usize;
        let op = st.new_op(GENOP_GET_MAP_ELEMENTS_3, 3);
        debug_assert!(st.ops.op(op).uses_def_args());
        st.ops.op_mut(op).spill(3 + 2 * n, 0);
        {
            let o = st.ops.op_mut(op);
            o.set_a(0, fail);
            o.set_a(1, src);
            o.set_a(2, arg(TAG_U, 2 * n as u64));
        }
        for i in 0..n {
            let key = rest.get(st, i);
            let o = st.ops.op_mut(op);
            o.set_a(3 + 2 * i, key);
            // Ignore result.
            o.set_a(3 + 2 * i + 1, arg(TAG_X, SCRATCH_X_REG));
        }
        Some(op)
    }

    pub(crate) fn init_yregs_move(
        st: &mut LoaderState,
        size: BeamOpArg,
        rest: RestArgs,
    ) -> Option<OpId> {
        debug_assert!(size.val == 1);
        let op = st.new_op(GENOP_MOVE_2, 2);
        let value = rest.get(st, 0);
        let o = st.ops.op_mut(op);
        o.set_a(0, arg(TAG_N, 0));
        o.set_a(1, value);
        Some(op)
    }

    pub(crate) fn jump_tab(
        st: &mut LoaderState,
        src: BeamOpArg,
        fail: BeamOpArg,
        size: BeamOpArg,
        rest: RestArgs,
    ) -> Option<OpId> {
        // The rule in ops.tab must ensure that there are more than two values.
        debug_assert!(size.val > 2);
        debug_assert!(size.val.is_multiple_of(2));

        // Calculate the minimum and maximum values and size of jump table.
        debug_assert!(rest.get(st, 0).ty == TAG_I);
        let mut min = sint(rest.get(st, 0).val);
        let mut max = min;
        let mut i = 2;
        while i < size.val as usize {
            let key = rest.get(st, i);
            debug_assert!(key.ty == TAG_I && rest.get(st, i + 1).ty == TAG_F);
            if sint(key.val) < min {
                min = sint(key.val);
            } else if max < sint(key.val) {
                max = sint(key.val);
            }
            i += 2;
        }
        let table_size = max - min + 1;

        // Allocate structure and fill in the fixed fields.
        let op = st.new_op(GENOP_I_JUMP_ON_VAL_4, 4);
        let fixed_args = 4usize;
        let arity = fixed_args + table_size as usize;
        debug_assert!(st.ops.op(op).uses_def_args());
        st.ops.op_mut(op).spill(arity, 0);
        {
            let o = st.ops.op_mut(op);
            o.set_a(0, src);
            o.set_a(1, fail);
            o.set_a(2, arg(TAG_U, min as u64));
            o.set_a(3, arg(TAG_U, table_size as u64));
            // Fill in the jump table.
            for i in fixed_args..arity {
                o.set_a(i, fail);
            }
        }
        let mut i = 0;
        while i < size.val as usize {
            let key = rest.get(st, i);
            let label = rest.get(st, i + 1);
            let index = fixed_args as i64 + sint(key.val) - min;
            debug_assert!(fixed_args as i64 <= index && (index as usize) < arity);
            st.ops.op_mut(op).set_a(index as usize, label);
            i += 2;
        }
        Some(op)
    }

    pub(crate) fn make_fun3(
        st: &mut LoaderState,
        idx: BeamOpArg,
        dst: BeamOpArg,
        num_free: BeamOpArg,
        env: RestArgs,
    ) -> Option<OpId> {
        let op = st.new_op(0, 0);

        if (idx.val as usize) < st.beam.lambdas.len() {
            let (entry_arity, entry_num_free) = {
                let entry = &st.beam.lambdas[idx.val as usize];
                (entry.arity, entry.num_free)
            };
            if num_free.val == u64::from(entry_num_free) {
                if entry_num_free == 0 {
                    // If we haven't already done so, we need to create a placeholder for the
                    // lambda.
                    let literal = match st.lambda_literals[idx.val as usize] {
                        Some(literal) => literal,
                        None => {
                            let literal = st.literals.add(NewLiteral::FunPlaceholder {
                                lambda: idx.val as u32,
                            });
                            st.lambda_literals[idx.val as usize] = Some(literal);
                            literal
                        }
                    };
                    let o = st.ops.op_mut(op);
                    o.op = GENOP_MOVE_2;
                    o.arity = 2;
                    o.set_a(0, arg(TAG_Q, literal));
                    o.set_a(1, dst);
                } else {
                    {
                        let o = st.ops.op_mut(op);
                        o.op = GENOP_I_MAKE_FUN3_4;
                        o.arity = 4;
                    }
                    debug_assert!(st.ops.op(op).uses_def_args());
                    st.ops.op_mut(op).spill(4 + entry_num_free as usize, 0);
                    {
                        let o = st.ops.op_mut(op);
                        o.set_a(0, arg(TAG_U, idx.val));
                        o.set_a(1, dst);
                        o.set_a(2, arg(TAG_U, u64::from(entry_arity - entry_num_free)));
                        o.set_a(3, arg(TAG_U, u64::from(entry_num_free)));
                    }
                    for i in 0..entry_num_free as usize {
                        let value = env.get(st, i);
                        st.ops.op_mut(op).set_a(4 + i, value);
                    }
                }
                return Some(op);
            }
        }

        let o = st.ops.op_mut(op);
        o.op = GENOP_I_LAMBDA_ERROR_1;
        o.arity = 1;
        o.set_a(0, arg(TAG_O, 0));
        Some(op)
    }

    pub(crate) fn new_small_map_lit(
        st: &mut LoaderState,
        dst: BeamOpArg,
        live: BeamOpArg,
        size: BeamOpArg,
        rest: RestArgs,
    ) -> Option<OpId> {
        let size = size.val as usize;
        let op = st.new_op(GENOP_I_NEW_SMALL_MAP_LIT_4, 4);
        debug_assert!(st.ops.op(op).uses_def_args());
        st.ops.op_mut(op).spill(4 + size / 2, 0);

        // The key tuple: erts builds it in a temporary heap and adds it as a literal; here the
        // literal is the recipe of the tuple (`NewLiteral::Tuple`), which the consumer builds in
        // the module's literal area.
        let mut elements: Vec<LiteralElement> = Vec::with_capacity(size / 2);
        let mut i = 0;
        while i < size {
            let key = rest.get(st, i);
            match key.ty {
                TAG_A => elements.push(LiteralElement::Atom(key.val as u32)),
                TAG_I => elements.push(LiteralElement::Small(key.val as i64)),
                TAG_N => elements.push(LiteralElement::Nil),
                TAG_Q => elements.push(LiteralElement::Literal(key.val as u32)),
                _ => {}
            }
            let value = rest.get(st, i + 1);
            st.ops.op_mut(op).set_a(4 + i / 2, value);
            i += 2;
        }
        let lit = st.literals.add(NewLiteral::Tuple(elements));

        let o = st.ops.op_mut(op);
        o.set_a(0, dst);
        o.set_a(1, live);
        o.set_a(2, arg(TAG_Q, lit));
        o.set_a(3, arg(TAG_U, (size / 2) as u64));
        Some(op)
    }

    pub(crate) fn select_literals(
        st: &mut LoaderState,
        src: BeamOpArg,
        fail: BeamOpArg,
        size: BeamOpArg,
        rest: RestArgs,
    ) -> Option<OpId> {
        let mut head: Option<OpId> = None;
        let mut last: Option<OpId> = None;
        let mut i = 0;
        while i < size.val as usize {
            debug_assert!(rest.get(st, i).ty == TAG_Q);
            let op = st.new_op(GENOP_IS_NE_EXACT_3, 3);
            let label = rest.get(st, i + 1);
            let literal = rest.get(st, i);
            {
                let o = st.ops.op_mut(op);
                o.set_a(0, label);
                o.set_a(1, src);
                o.set_a(2, literal);
            }
            match last {
                Some(previous) => st.ops.op_mut(previous).next = Some(op),
                None => head = Some(op),
            }
            last = Some(op);
            i += 2;
        }

        let jump = st.new_op(GENOP_JUMP_1, 1);
        st.ops.op_mut(jump).set_a(0, fail);
        match last {
            Some(previous) => st.ops.op_mut(previous).next = Some(jump),
            None => head = Some(jump),
        }
        head
    }

    pub(crate) fn select_tuple_arity(
        st: &mut LoaderState,
        src: BeamOpArg,
        fail: BeamOpArg,
        size: BeamOpArg,
        rest: RestArgs,
    ) -> Option<OpId> {
        let n = size.val as usize / 2;
        let arity = size.val as usize + 3;

        // Verify the validity of the list.
        if !size.val.is_multiple_of(2) {
            return None;
        }
        let mut i = 0;
        while i < size.val as usize {
            if rest.get(st, i).ty != TAG_U || rest.get(st, i + 1).ty != TAG_F {
                return None;
            }
            i += 2;
        }

        // Generate the generic instruction. Assumption: few different tuple arities to select on
        // (fewer than 20). Use linear scan approach.
        let op = st.new_op(GENOP_I_SELECT_TUPLE_ARITY_3, 3);
        debug_assert!(st.ops.op(op).uses_def_args());
        st.ops.op_mut(op).spill(arity, 0);
        {
            let o = st.ops.op_mut(op);
            o.set_a(0, src);
            o.set_a(1, fail);
            // Variable argument count
            o.set_a(2, arg(TAG_U, size.val));
        }

        let mut tmp = vec![BeamOpArg::default(); arity];
        let mut i = 3;
        while i < arity {
            tmp[i - 2] = rest.get(st, i - 2);
            // make_arityval_unchecked: the arity in the header word above the tag bits.
            tmp[i - 3] = arg(TAG_V, rest.get(st, i - 3).val << 6);
            i += 2;
        }

        // Sort the values to make them useful for a binary or sentinel search.
        sort_select_vals(&mut tmp, n);

        let mut j = 3;
        let mut i = 3;
        while i < arity {
            let o = st.ops.op_mut(op);
            o.set_a(j + n, tmp[i - 2]);
            o.set_a(j, tmp[i - 3]);
            j += 1;
            i += 2;
        }
        Some(op)
    }

    pub(crate) fn select_val(
        st: &mut LoaderState,
        src: BeamOpArg,
        fail: BeamOpArg,
        size: BeamOpArg,
        rest: RestArgs,
    ) -> Option<OpId> {
        let arity = size.val as usize + 3;
        let n = size.val as usize / 2;

        let op = st.new_op(0, 0);

        // Use linear search for small search spaces.
        {
            let o = st.ops.op_mut(op);
            if n <= 10 {
                o.op = GENOP_I_SELECT_VAL_LINS_3;
            } else {
                o.op = GENOP_I_SELECT_VAL_BINS_3;
            }
            o.arity = 3;
        }
        debug_assert!(st.ops.op(op).uses_def_args());
        st.ops.op_mut(op).spill(arity, 0);
        {
            let o = st.ops.op_mut(op);
            o.set_a(0, src);
            o.set_a(1, fail);
            // Variable argument count
            o.set_a(2, arg(TAG_U, size.val));
        }

        let mut tmp = vec![BeamOpArg::default(); size.val as usize];
        for (i, slot) in tmp.iter_mut().enumerate() {
            *slot = rest.get(st, i);
        }

        // Sort the values to make them useful for a binary or sentinel search.
        sort_select_vals(&mut tmp, n);

        let mut j = 3;
        let mut i = 3;
        while i < arity {
            let o = st.ops.op_mut(op);
            o.set_a(j, tmp[i - 3]);
            o.set_a(j + n, tmp[i - 2]);
            j += 1;
            i += 2;
        }
        Some(op)
    }

    pub(crate) fn skip_utf16(
        st: &mut LoaderState,
        fail: BeamOpArg,
        ms: BeamOpArg,
        flags: BeamOpArg,
    ) -> Option<OpId> {
        let mut flags = flags;
        flags.val = fix_native_endian(flags.val);
        let op = st.new_op(GENOP_I_BS_SKIP_UTF16_3, 3);
        let o = st.ops.op_mut(op);
        o.set_a(0, ms);
        o.set_a(1, fail);
        o.set_a(2, flags);
        Some(op)
    }

    pub(crate) fn split_values(
        st: &mut LoaderState,
        src: BeamOpArg,
        type_fail: BeamOpArg,
        fail: BeamOpArg,
        size: BeamOpArg,
        rest: RestArgs,
    ) -> Option<OpId> {
        debug_assert!(size.val >= 2 && size.val.is_multiple_of(2));

        let is_integer = st.new_op(GENOP_IS_INTEGER_2, 2);
        {
            let o = st.ops.op_mut(is_integer);
            o.set_a(0, type_fail);
            o.set_a(1, src);
        }

        // The C code gives each select_val `3 + Size.val` operands and then raises `arity` by two
        // per value, so the arity ends above the allocation; the capacity covers it.
        let capacity = 3 + 2 * size.val as usize;
        let op1 = st.new_op(GENOP_SELECT_VAL_3, 3);
        st.ops.op_mut(op1).spill(capacity, 0);
        {
            let o = st.ops.op_mut(op1);
            o.arity = 3 + size.val as usize;
            o.set_a(0, src);
            // We use [] instead of a failure label to indicate a fallthrough to next instruction
            // if none of the values match. That way, we don't have to create a new label
            // dynamically, which would be tricky in BeamAsm.
            o.set_a(1, arg(TAG_N, 0));
            o.set_a(2, arg(TAG_U, 0));
        }

        let op2 = st.new_op(GENOP_SELECT_VAL_3, 3);
        st.ops.op_mut(op2).spill(capacity, 0);
        {
            let o = st.ops.op_mut(op2);
            o.arity = 3 + size.val as usize;
            o.set_a(0, src);
            o.set_a(1, fail);
            o.set_a(2, arg(TAG_U, 0));
        }

        // Split the list.
        debug_assert!(size.ty == TAG_U);
        let mut i = 0;
        while i < size.val as usize {
            let value = rest.get(st, i);
            let label = rest.get(st, i + 1);
            let op = if value.ty == TAG_Q { op2 } else { op1 };
            let o = st.ops.op_mut(op);
            let dst = 3 + o.a(2).val as usize;
            debug_assert!(label.ty == TAG_F);
            o.set_a(dst, value);
            o.set_a(dst + 1, label);
            o.arity += 2;
            let mut count = o.a(2);
            count.val += 2;
            o.set_a(2, count);
            i += 2;
        }
        debug_assert!(st.ops.op(op1).a(2).val > 0);
        debug_assert!(st.ops.op(op2).a(2).val > 0);

        // Order the instruction sequence appropriately.
        let head = if type_fail.val == fail.val {
            // select_val Src [] S ... (small numbers)
            // is_integer Fail S
            // select_val Src Fail S ... (bignums)
            st.ops.op_mut(op1).next = Some(is_integer);
            st.ops.op_mut(is_integer).next = Some(op2);
            op1
        } else {
            // is_integer TypeFail S
            // select_val Src [] S ... (small numbers)
            // select_val Src Fail S ... (bignums)
            st.ops.op_mut(is_integer).next = Some(op1);
            st.ops.op_mut(op1).next = Some(op2);
            is_integer
        };
        st.ops.op_mut(op2).next = None;
        Some(head)
    }
}
