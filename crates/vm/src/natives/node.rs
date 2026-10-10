//! Halt and non-distributed node identity BIFs.

use crate::process::Message;
use crate::{Process, Vm, VmError};
use arinsal_etf::OwnedTerm;
use arinsal_sched::RunCtx;
use arinsal_term::{Term, TermBuilder, global_atoms};
use num_bigint::BigInt;
use std::io::Write;

use crate::node_tables;

/// Halt and node-identity BIFs. `handler` is this table.
pub(crate) const IMPLEMENTED: &[(&str, &str, u8)] = &[
    ("erlang", "halt", 2),
    ("erlang", "node", 0),
    ("erlang", "node", 1),
    ("erlang", "is_alive", 0),
    ("erlang", "nodes", 0),
    ("erlang", "nodes", 1),
    ("erlang", "nodes", 2),
    ("erlang", "setnode", 2),
    ("erlang", "monitor_node", 2),
    ("erlang", "monitor_node", 3),
];

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn recognizes(module: &str, function: &str, arity: u8) -> bool {
    super::listed(IMPLEMENTED, module, function, arity)
}

type Handler =
    fn(&mut Vm, &mut Process, &mut RunCtx<'_, Message>, &[Term]) -> Result<Term, VmError>;

pub(crate) fn handler(module: &str, function: &str, arity: u8) -> Option<Handler> {
    match (module, function, arity) {
        ("erlang", "halt", 2) => Some(call_halt2),
        ("erlang", "node", 0) => Some(call_node0),
        ("erlang", "node", 1) => Some(call_node1),
        ("erlang", "is_alive", 0) => Some(call_is_alive0),
        ("erlang", "nodes", 0) => Some(call_nodes0),
        ("erlang", "nodes", 1) => Some(call_nodes1),
        ("erlang", "nodes", 2) => Some(call_nodes2),
        ("erlang", "setnode", 2) => Some(call_setnode2),
        ("erlang", "monitor_node", 2) => Some(call_monitor_node2),
        ("erlang", "monitor_node", 3) => Some(call_monitor_node3),
        _ => None,
    }
}

fn call_halt2(
    _vm: &mut Vm,
    process: &mut Process,
    _ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    halt(process, args[0], args[1])
}

fn call_node0(
    _vm: &mut Vm,
    _process: &mut Process,
    _ctx: &mut RunCtx<'_, Message>,
    _args: &[Term],
) -> Result<Term, VmError> {
    Ok(local_node_term())
}

fn call_is_alive0(
    _vm: &mut Vm,
    _process: &mut Process,
    _ctx: &mut RunCtx<'_, Message>,
    _args: &[Term],
) -> Result<Term, VmError> {
    Ok(boolean(node_tables::lock().alive))
}

fn call_node1(
    _vm: &mut Vm,
    _process: &mut Process,
    _ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    node(args[0])
}

fn call_nodes0(
    _vm: &mut Vm,
    process: &mut Process,
    _ctx: &mut RunCtx<'_, Message>,
    _args: &[Term],
) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/dist.c:6279 (nodes/0 → visible), OTP-29.1.1.
    nodes(process, atom("visible"), None)
}

fn call_nodes1(
    _vm: &mut Vm,
    process: &mut Process,
    _ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    nodes(process, args[0], None)
}

fn call_nodes2(
    _vm: &mut Vm,
    process: &mut Process,
    _ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    nodes(process, args[0], Some(args[1]))
}

fn call_setnode2(
    _vm: &mut Vm,
    _process: &mut Process,
    _ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/dist.c:4978 (setnode_2), OTP-29.1.1.
    let OwnedTerm::Atom(name) = &owned(args[0])? else {
        return Err(badarg());
    };
    let creation_value = owned(args[1])?;
    let creation = match &creation_value {
        OwnedTerm::Int(value) if (0..=u32::MAX as i64).contains(value) => *value as u32,
        OwnedTerm::BigInt(value)
            if value.sign() != num_bigint::Sign::Minus && value <= &BigInt::from(u32::MAX) =>
        {
            value.to_u32_digits().1.first().copied().unwrap_or(0)
        }
        _ => return Err(badarg()),
    };
    if !node_tables::set_this_node(name.clone(), creation) {
        return Err(badarg());
    }
    Ok(atom("true"))
}

fn call_monitor_node2(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    monitor_node(vm, process, ctx, args[0], args[1], None)
}

fn call_monitor_node3(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    monitor_node(vm, process, ctx, args[0], args[1], Some(args[2]))
}

pub(super) fn call(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    module: &str,
    function: &str,
    args: &[Term],
) -> Option<Result<Term, VmError>> {
    handler(module, function, args.len() as u8).map(|handle| handle(vm, process, ctx, args))
}

pub(crate) fn node(term: Term) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/dist.c:6217 (node/1), OTP-29.1.1.
    let Some(identity) = term.identity() else {
        return Err(badarg());
    };
    let name = match identity {
        arinsal_term::Identity::Pid { node, .. }
        | arinsal_term::Identity::Port { node, .. }
        | arinsal_term::Identity::Ref { node, .. } => node,
    };
    let local_name = node_tables::lock().local_name.clone();
    if name == arinsal_term::atoms::NONAME && local_name != "nonode@nohost" {
        Ok(Term::atom(global_atoms().intern(&local_name).unwrap()))
    } else {
        Ok(Term::atom(name))
    }
}

fn nodes(process: &mut Process, types: Term, options: Option<Term>) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/dist.c:6279 (nodes), OTP-29.1.1.
    let types = owned(types)?;
    let type_names = match &types {
        OwnedTerm::Nil => Some(Vec::new()),
        OwnedTerm::Atom(name) => Some(vec![name.as_str()]),
        OwnedTerm::List { elems, tail } if **tail == OwnedTerm::Nil => elems
            .iter()
            .map(|term| match term {
                OwnedTerm::Atom(name) => Some(name.as_str()),
                _ => None,
            })
            .collect::<Option<Vec<_>>>(),
        _ => None,
    };
    let Some(type_names) = type_names else {
        return Err(badarg());
    };
    if type_names
        .iter()
        .any(|name| !matches!(*name, "visible" | "hidden" | "known" | "connected" | "this"))
    {
        return Err(badarg());
    }
    let mut want_visible = false;
    let mut want_hidden = false;
    let mut want_known = false;
    let mut want_this = false;
    for name in type_names {
        match name {
            "visible" => want_visible = true,
            "hidden" => want_hidden = true,
            "known" => want_known = true,
            "connected" => {
                want_visible = true;
                want_hidden = true;
            }
            "this" => want_this = true,
            _ => unreachable!(),
        }
    }
    if want_known {
        want_visible = true;
        want_hidden = true;
        want_this = true;
    }
    let mut connection_id = false;
    let mut node_type = false;
    if let Some(options) = options {
        let options = owned(options)?;
        let OwnedTerm::Map(entries) = &options else {
            return Err(badarg());
        };
        for (key, value) in entries {
            match (key, value) {
                (OwnedTerm::Atom(name), OwnedTerm::Atom(value))
                    if name == "connection_id" && (value == "true" || value == "false") =>
                {
                    connection_id = value == "true";
                }
                (OwnedTerm::Atom(name), OwnedTerm::Atom(value))
                    if name == "node_type" && (value == "true" || value == "false") =>
                {
                    node_type = value == "true";
                }
                _ => return Err(badarg()),
            }
        }
    }
    let tables = node_tables::lock();
    let mut entries = Vec::new();
    if want_this {
        entries.push((tables.local_name.clone(), node_tables::NodeKind::This, None));
    }
    for entry in tables.entries.values() {
        if entry.name == tables.local_name {
            continue;
        }
        if !entry.connected {
            if want_known {
                entries.push((entry.name.clone(), node_tables::NodeKind::Known, None));
            }
            continue;
        }
        let kind = if entry.visible {
            node_tables::NodeKind::Visible
        } else {
            node_tables::NodeKind::Hidden
        };
        if (kind == node_tables::NodeKind::Visible && want_visible)
            || (kind == node_tables::NodeKind::Hidden && want_hidden)
        {
            entries.push((entry.name.clone(), kind, Some(entry.connection_id)));
        }
    }
    drop(tables);
    if want_known {
        for node in arinsal_term::Node::live_nodes() {
            let Some(name) = global_atoms().text(node.name) else {
                continue;
            };
            if name != "nonode@nohost" && !entries.iter().any(|(known, _, _)| known == name) {
                entries.push((name.to_owned(), node_tables::NodeKind::Known, None));
            }
        }
    }
    if entries.is_empty() {
        return Ok(Term::NIL);
    }
    {
        let mut heap = crate::FragmentingHeap(&mut process.heap);
        let mut builder = TermBuilder::new(&mut heap);
        let mut result = Vec::with_capacity(entries.len());
        for (name, kind, cid) in entries {
            let node = Term::atom(global_atoms().intern(&name).unwrap());
            if options.is_none() {
                result.push(node);
                continue;
            }
            let mut pairs = Vec::new();
            if connection_id {
                pairs.push((
                    atom("connection_id"),
                    cid.map(|value| {
                        Term::small(i64::from(value)).unwrap_or_else(|| atom("undefined"))
                    })
                    .unwrap_or_else(|| atom("undefined")),
                ));
            }
            if node_type {
                let value = match kind {
                    node_tables::NodeKind::This => "this",
                    node_tables::NodeKind::Visible => "visible",
                    node_tables::NodeKind::Hidden => "hidden",
                    node_tables::NodeKind::Known => "known",
                };
                pairs.push((atom("node_type"), atom(value)));
            }
            let info = builder.flatmap_from_pairs(&pairs).map_err(|_| badarg())?;
            result.push(builder.tuple(&[node, info]).map_err(|_| badarg())?);
        }
        builder.list_from_iter(result).map_err(|_| badarg())
    }
}

fn monitor_node(
    _vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, Message>,
    node: Term,
    enabled: Term,
    options: Option<Term>,
) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/dist.c:6468 (monitor_node), OTP-29.1.1.
    let OwnedTerm::Atom(name) = &owned(node)? else {
        return Err(badarg());
    };
    let enabled_term = owned(enabled)?;
    let enabled = match &enabled_term {
        OwnedTerm::Atom(value) if value == "true" => true,
        OwnedTerm::Atom(value) if value == "false" => false,
        _ => return Err(badarg()),
    };
    monitor_options(options)?;
    let mut tables = node_tables::lock();
    if name != "nonode@nohost" && !tables.alive {
        return Err(error("notalive"));
    }
    let immediate = tables.monitor(ctx.pid(), name.clone(), enabled);
    drop(tables);
    if immediate {
        let mut heap = crate::FragmentingHeap(&mut process.heap);
        let mut builder = TermBuilder::new(&mut heap);
        let node = Term::atom(global_atoms().intern(name).unwrap());
        let down = builder
            .tuple(&[atom("nodedown"), node])
            .map_err(|_| badarg())?;
        ctx.send(ctx.pid(), Message::copy_from(down)?)
            .map_err(|error| VmError::Unsupported(format!("nodedown delivery: {error}")))?;
    }
    Ok(atom("true"))
}

fn monitor_options(options: Option<Term>) -> Result<(), VmError> {
    let Some(options) = options else {
        return Ok(());
    };
    let options = owned(options)?;
    let OwnedTerm::List { elems, tail } = &options else {
        return Err(badarg());
    };
    if **tail != OwnedTerm::Nil {
        return Err(badarg());
    }
    for option in elems {
        let OwnedTerm::Atom(option) = option else {
            return Err(badarg());
        };
        match option.as_str() {
            "allow_passive_connect" => {}
            _ => return Err(badarg()),
        }
    }
    Ok(())
}

fn local_node_term() -> Term {
    let tables = node_tables::lock();
    let (name, _creation) = tables.local_identity();
    Term::atom(global_atoms().intern(name).unwrap())
}

fn atom(name: &str) -> Term {
    Term::atom(global_atoms().intern(name).unwrap())
}

fn boolean(value: bool) -> Term {
    atom(if value { "true" } else { "false" })
}

fn error(reason: &str) -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(atom(reason)))
}

fn halt(process: &mut Process, code: Term, options: Term) -> Result<Term, VmError> {
    // Port of erts/emulator/beam/bif.c:4309 (halt/2), OTP-29.1.1.
    let (flush, flush_timeout) = halt_options(options)?;
    let code = owned(code)?;
    let mut message = None;
    let status = match &code {
        OwnedTerm::Int(value) if *value >= 0 => (*value as u64 & i32::MAX as u64) as i32,
        OwnedTerm::BigInt(value) if value.sign() != num_bigint::Sign::Minus => {
            mask_exit_code(value)
        }
        OwnedTerm::Atom(name) if name == "abort" => {
            flush_stdio();
            std::process::abort();
        }
        OwnedTerm::List { elems, tail } if **tail == OwnedTerm::Nil => {
            let mut text = String::new();
            for item in elems {
                let OwnedTerm::Int(value) = item else {
                    return Err(badarg());
                };
                let Ok(value) = u32::try_from(*value) else {
                    return Err(badarg());
                };
                let Some(character) = char::from_u32(value) else {
                    return Err(badarg());
                };
                text.push(character);
                if text.chars().count() > 1023 {
                    return Err(badarg());
                }
            }
            message = Some(text);
            1
        }
        _ => return Err(badarg()),
    };

    arinsal_sched::begin_halt();
    if flush && flush_timeout == Some(0) && message.is_none() {
        super::nif::execute_on_halt();
        std::process::exit(255);
    }

    // ERTS flushes ports before exiting; the OS streams are the only output
    // channels exposed by this runtime, so flush them before the process exit.
    let _ = process;
    flush_stdio();
    if flush {
        super::nif::execute_on_halt();
    }
    if let Some(text) = message {
        let _ = write!(
            std::io::stderr().lock(),
            "{text}\r\n\r\nCrash dump is being written to: erl_crash.dump...done\r\n"
        );
        flush_stdio();
        std::process::exit(1);
    }
    std::process::exit(status);
}

fn halt_options(options: Term) -> Result<(bool, Option<u32>), VmError> {
    let options = owned(options)?;
    let (elems, tail) = match &options {
        OwnedTerm::Nil => return Ok((true, None)),
        OwnedTerm::List { elems, tail } => (elems, tail),
        _ => return Err(badopt()),
    };
    if **tail != OwnedTerm::Nil {
        return Err(badopt());
    }
    let mut flush = true;
    let mut flush_timeout = None;
    for option in elems {
        let OwnedTerm::Tuple(parts) = option else {
            return Err(badopt());
        };
        if parts.len() != 2 {
            return Err(badopt());
        }
        match (&parts[0], &parts[1]) {
            (OwnedTerm::Atom(name), OwnedTerm::Atom(value))
                if name == "flush" && value == "true" =>
            {
                flush = true
            }
            (OwnedTerm::Atom(name), OwnedTerm::Atom(value))
                if name == "flush" && value == "false" =>
            {
                flush = false
            }
            (OwnedTerm::Atom(name), OwnedTerm::Int(value))
                if name == "flush_timeout" && (0..=u32::MAX as i64).contains(value) =>
            {
                flush_timeout = Some(*value as u32)
            }
            (OwnedTerm::Atom(name), OwnedTerm::BigInt(value))
                if name == "flush_timeout"
                    && value.sign() != num_bigint::Sign::Minus
                    && value <= &BigInt::from(u32::MAX) =>
            {
                flush_timeout = Some(value.to_u32_digits().1.first().copied().unwrap_or(0))
            }
            _ => return Err(badopt()),
        }
    }
    Ok((flush, flush_timeout))
}

fn mask_exit_code(value: &BigInt) -> i32 {
    let (_, bytes) = value.to_bytes_le();
    let low = bytes.first().copied().unwrap_or(0) as u32;
    let high = bytes.get(1).copied().unwrap_or(0) as u32;
    ((low | (high << 8)) & i32::MAX as u32) as i32
}

fn owned(term: Term) -> Result<OwnedTerm, VmError> {
    arinsal_term::to_owned(term).map_err(|_| badarg())
}

fn flush_stdio() {
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
}

fn badarg() -> VmError {
    let reason = Term::atom(global_atoms().intern("badarg").unwrap());
    VmError::Trap(crate::exceptions::Trap::error(reason))
}

fn badopt() -> VmError {
    // `halt/2` reports an argument error with the `badopt` error-info cause.
    // Trap dispatch currently retains only the reason term in this native path.
    badarg()
}

#[cfg(test)]
mod tests {
    use crate::Vm;
    use arinsal_difftest::{CallResult, RefErl};

    const SOURCE: &str = r#"
-module(node_native_diff).
-export([run/0]).
run() ->
    {safe(fun() -> node() end), safe(fun() -> node(self()) end), safe(fun() -> node(make_ref()) end), safe(fun() -> port_node() end),
     safe(fun() -> nodes() end), safe(fun() -> nodes(visible) end), safe(fun() -> nodes(known) end),
     safe(fun() -> nodes([], #{}) end), safe(fun() -> nodes(this, #{}) end),
     safe(fun() -> nodes(this, #{node_type => true}) end),
     safe(fun() -> nodes(this, #{connection_id => true}) end),
     safe(fun() -> nodes(visible, #{connection_id => true}) end), safe(fun() -> erlang:is_alive() end), safe(fun() -> erlang:get_cookie() end), safe(fun() -> erlang:get_cookie(node()) end),
     badarg(fun() -> nodes(foo) end),
     badarg(fun() -> nodes([foo]) end),
     badarg(fun() -> nodes(visible, #{bad => true}) end),
     badarg(fun() -> erlang:halt(-1) end),
     badarg(fun() -> erlang:halt(3, [{unknown, true}]) end),
     badarg(fun() -> erlang:set_cookie(node(), abc) end),
     badarg(fun() -> node(foo) end)}.
port_node() -> P = open_port({spawn, "true"}, []), N = node(P), port_close(P), N.
safe(F) -> try F() catch error:badarg -> badarg end.
badarg(F) -> try F() of _ -> unexpected catch error:badarg -> badarg end.
"#;

    #[test]
    fn node_distribution_bifs_match_otp_29_on_scheduler() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping node BIF differential test");
            return;
        };
        let beam = reference
            .compile_named("node_native_diff", SOURCE, &[])
            .unwrap();
        reference.load("node_native_diff", &beam).unwrap();
        let expected = reference.call("node_native_diff", "run", &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm
            .eval_scheduled("node_native_diff", "run", &[], 2, None)
            .unwrap();
        assert_eq!(expected, CallResult::Ok(actual.term));
    }
}
