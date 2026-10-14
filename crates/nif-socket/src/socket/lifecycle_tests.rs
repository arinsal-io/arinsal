use super::*;
use crate::{BlockingReactor, TEST_REACTOR_LOCK, set_reactor};
use std::time::Duration;

fn pid(id: u32) -> O {
    O::Pid {
        node: "nonode@nohost".into(),
        id,
        serial: 0,
        creation: 0,
    }
}

fn op_ref(id: u32) -> O {
    O::Ref {
        node: "nonode@nohost".into(),
        creation: 0,
        ids: vec![id],
    }
}

fn reactor_for(caller: u32) -> (std::sync::MutexGuard<'static, ()>, Arc<BlockingReactor>) {
    let lock = TEST_REACTOR_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let reactor = Arc::new(BlockingReactor::default());
    reactor.set_caller(pid(caller));
    set_reactor(Some(reactor.clone()));
    (lock, reactor)
}

fn call(op: &str, args: &[O]) -> O {
    dispatch(op, args).unwrap_or_else(|error| panic!("{op} {args:?}: {error:?}"))
}

fn raises(op: &str, args: &[O]) -> O {
    assert!(dispatch(op, args).is_err(), "{op} did not raise");
    crate::RAISED
        .with(|raised| raised.borrow_mut().take())
        .expect("a raised reason")
}

fn ok_value(value: &O) -> O {
    match value {
        O::Tuple(parts) if parts[0] == atom("ok") => parts[1].clone(),
        other => panic!("expected {{ok, _}}: {other:?}"),
    }
}

fn open(domain: &str, kind: &str, protocol: i64) -> O {
    ok_value(&call(
        "nif_open",
        &[atom(domain), atom(kind), O::Int(protocol), O::Map(vec![])],
    ))
}

fn address(port: i64) -> O {
    map(&[
        ("family", atom("inet")),
        (
            "addr",
            O::tuple(vec![O::Int(127), O::Int(0), O::Int(0), O::Int(1)]),
        ),
        ("port", O::Int(port)),
    ])
}

fn listener() -> (O, i64) {
    let sock = open("inet", "stream", 6);
    assert_eq!(call("nif_bind", &[sock.clone(), address(0)]), atom("ok"));
    assert_eq!(call("nif_listen", &[sock.clone(), O::Int(8)]), atom("ok"));
    let bound = ok_value(&call("nif_sockname", std::slice::from_ref(&sock)));
    (sock, number(field(&bound, "port").unwrap()).unwrap())
}

fn getopt_otp(sock: &O, opt: i64) -> O {
    call("nif_getopt", &[sock.clone(), atom("otp"), O::Int(opt)])
}

fn setopt_otp(sock: &O, opt: i64, value: O) -> O {
    call(
        "nif_setopt",
        &[sock.clone(), atom("otp"), O::Int(opt), value, O::Int(0)],
    )
}

fn states(sock: &O) -> (O, O) {
    let info = call("nif_info", std::slice::from_ref(sock));
    (
        field(&info, "rstates").unwrap().clone(),
        field(&info, "wstates").unwrap().clone(),
    )
}

fn sent_to(reactor: &BlockingReactor, who: &O) -> Vec<O> {
    reactor
        .sent()
        .into_iter()
        .filter(|(pid, _)| pid == who)
        .map(|(_, message)| message)
        .collect()
}

#[test]
fn close_then_finalize_follow_the_close_protocol() {
    let (_lock, reactor) = reactor_for(5);
    let sock = open("inet", "stream", 6);
    assert_eq!(
        raises("nif_finalize_close", std::slice::from_ref(&sock)),
        invalid("state")
    );
    assert_eq!(call("nif_close", std::slice::from_ref(&sock)), atom("ok"));
    assert_eq!(
        call("nif_close", std::slice::from_ref(&sock)),
        error("closed")
    );
    assert_eq!(
        getopt_otp(&sock, 1008),
        error("closed"),
        "a closing socket is not open"
    );
    reactor.set_caller(pid(6));
    assert_eq!(
        raises("nif_finalize_close", std::slice::from_ref(&sock)),
        invalid("state")
    );
    reactor.set_caller(pid(5));
    assert_eq!(
        call("nif_finalize_close", std::slice::from_ref(&sock)),
        atom("ok")
    );
    assert_eq!(
        call("nif_finalize_close", std::slice::from_ref(&sock)),
        error("closed")
    );
    assert_eq!(
        states(&sock).0,
        O::list(vec![atom("closing"), atom("closed")])
    );
    set_reactor(None);
}

#[test]
fn close_aborts_the_current_and_the_waiting_acceptors() {
    let (_lock, reactor) = reactor_for(5);
    let (sock, _port) = listener();
    assert_eq!(
        call("nif_accept", &[sock.clone(), op_ref(1)]),
        atom("select")
    );
    reactor.set_caller(pid(6));
    assert_eq!(
        call("nif_accept", &[sock.clone(), op_ref(2)]),
        atom("select")
    );
    assert_eq!(
        states(&sock).0,
        O::list(vec![
            atom("bound"),
            atom("listening"),
            atom("accepting"),
            atom("selected"),
        ])
    );
    reactor.set_caller(pid(5));
    assert_eq!(call("nif_close", std::slice::from_ref(&sock)), atom("ok"));
    let closed = atom("closed");
    assert_eq!(
        sent_to(&reactor, &pid(5)),
        vec![crate::abort_message(&sock, &op_ref(1), &closed)]
    );
    assert_eq!(
        sent_to(&reactor, &pid(6)),
        vec![crate::abort_message(&sock, &op_ref(2), &closed)]
    );
    let info = call("nif_info", std::slice::from_ref(&sock));
    assert_eq!(field(&info, "num_acceptors"), Some(&O::Int(0)));
    assert!(reactor.monitored().iter().all(|(who, _)| who == &pid(5)));
    set_reactor(None);
}

#[test]
fn a_scheduled_stop_sends_the_close_message_before_finalize() {
    let (_lock, reactor) = reactor_for(5);
    let (sock, _port) = listener();
    assert_eq!(
        call("nif_accept", &[sock.clone(), op_ref(1)]),
        atom("select")
    );
    reactor.set_scheduled_stop(true);
    let close_ref = ok_value(&call("nif_close", std::slice::from_ref(&sock)));
    assert!(matches!(close_ref, O::Ref { .. }));
    assert_eq!(
        sent_to(&reactor, &pid(5)),
        vec![crate::abort_message(&sock, &op_ref(1), &atom("closed"))],
        "the acceptor whose select was cancelled is told"
    );
    assert_eq!(
        raises("nif_finalize_close", std::slice::from_ref(&sock)),
        invalid("state"),
        "the stop callback has not run"
    );
    crate::stop(&sock);
    let messages = sent_to(&reactor, &pid(5));
    assert_eq!(
        messages.last(),
        Some(&O::tuple(vec![
            atom("$socket"),
            pair(atom("$socket"), sock.clone()),
            atom("close"),
            close_ref,
        ]))
    );
    assert_eq!(
        call("nif_finalize_close", std::slice::from_ref(&sock)),
        atom("ok")
    );
    set_reactor(None);
}

#[test]
fn a_stop_without_a_closer_closes_the_descriptor() {
    let (_lock, reactor) = reactor_for(5);
    let sock = open("inet", "stream", 6);
    crate::stop(&sock);
    assert_eq!(getopt_otp(&sock, 1008), error("closed"));
    assert_eq!(states(&sock).0, O::list(vec![atom("closed")]));
    drop(reactor);
    set_reactor(None);
}

#[test]
fn the_owner_exiting_closes_the_socket() {
    let (_lock, reactor) = reactor_for(5);
    let sock = open("inet", "stream", 6);
    assert_eq!(reactor.monitored().len(), 1);
    assert!(matches!(getopt_otp(&sock, 1008), O::Tuple(_)));
    reactor.exit(&pid(5));
    assert_eq!(getopt_otp(&sock, 1008), error("closed"));
    assert_eq!(
        states(&sock).0,
        O::list(vec![atom("closing"), atom("closed")])
    );
    assert_eq!(
        call("nif_close", std::slice::from_ref(&sock)),
        error("closed")
    );
    set_reactor(None);
}

#[test]
fn controlling_process_moves_the_monitor_to_the_new_owner() {
    let (_lock, reactor) = reactor_for(5);
    let sock = open("inet", "stream", 6);
    reactor.set_caller(pid(6));
    assert_eq!(
        setopt_otp(&sock, 1003, pid(7)),
        error_invalid("not_owner"),
        "only the owner hands the socket over"
    );
    assert_eq!(
        setopt_otp(&sock, 1009, atom("meta")),
        error_invalid("not_owner")
    );
    reactor.set_caller(pid(5));
    assert_eq!(setopt_otp(&sock, 1003, atom("not_a_pid")), invalid("value"));
    assert_eq!(setopt_otp(&sock, 1003, pid(7)), atom("ok"));
    assert_eq!(
        reactor
            .monitored()
            .iter()
            .map(|(who, _)| who.clone())
            .collect::<Vec<_>>(),
        vec![pid(7)]
    );
    assert_eq!(getopt_otp(&sock, 1003), ok(pid(7)));
    assert_eq!(setopt_otp(&sock, 1003, pid(5)), error_invalid("not_owner"));
    reactor.exit(&pid(5));
    assert!(matches!(getopt_otp(&sock, 1008), O::Tuple(_)), "still open");
    reactor.exit(&pid(7));
    assert_eq!(getopt_otp(&sock, 1008), error("closed"));
    set_reactor(None);
}

#[test]
fn controlling_process_to_a_dead_process_closes_the_socket() {
    let (_lock, reactor) = reactor_for(5);
    let sock = open("inet", "stream", 6);
    reactor.set_dead(pid(9));
    assert_eq!(setopt_otp(&sock, 1003, pid(9)), atom("ok"));
    assert_eq!(getopt_otp(&sock, 1008), error("closed"));
    assert_eq!(
        states(&sock).0,
        O::list(vec![atom("closing"), atom("closed")])
    );
    set_reactor(None);
}

#[test]
fn a_waiting_acceptor_that_exits_is_replaced_by_the_next() {
    let (_lock, reactor) = reactor_for(4);
    let (sock, port) = listener();
    reactor.set_caller(pid(5));
    assert_eq!(
        call("nif_accept", &[sock.clone(), op_ref(1)]),
        atom("select")
    );
    reactor.set_caller(pid(6));
    assert_eq!(
        call("nif_accept", &[sock.clone(), op_ref(2)]),
        atom("select")
    );
    reactor.set_caller(pid(7));
    assert_eq!(
        call("nif_accept", &[sock.clone(), op_ref(3)]),
        atom("select")
    );
    let num_acceptors = |sock: &O| {
        field(
            &call("nif_info", std::slice::from_ref(sock)),
            "num_acceptors",
        )
        .cloned()
        .unwrap()
    };
    assert_eq!(num_acceptors(&sock), O::Int(3));
    reactor.exit(&pid(6));
    assert_eq!(
        num_acceptors(&sock),
        O::Int(2),
        "a queued acceptor is dropped"
    );
    reactor.exit(&pid(5));
    assert_eq!(num_acceptors(&sock), O::Int(1));
    reactor.set_caller(pid(8));
    let client = open("inet", "stream", 6);
    let _ = call("nif_connect", &[client, op_ref(9), address(port)]);
    let mut ready = Vec::new();
    while let Some(selection) = reactor.wait(Duration::from_millis(300)) {
        ready.push(selection);
    }
    assert!(ready.contains(&(pid(7), op_ref(3))), "{ready:?}");
    assert!(
        !ready
            .iter()
            .any(|(who, _)| who == &pid(5) || who == &pid(6))
    );
    reactor.exit(&pid(7));
    assert_eq!(num_acceptors(&sock), O::Int(0));
    let (rstates, _) = states(&sock);
    assert!(!format!("{rstates:?}").contains("accepting"));
    set_reactor(None);
}

#[test]
fn a_closer_that_exits_before_finalize_closes_the_descriptor() {
    let (_lock, reactor) = reactor_for(5);
    let sock = open("inet", "stream", 6);
    reactor.set_caller(pid(6));
    assert_eq!(call("nif_close", std::slice::from_ref(&sock)), atom("ok"));
    assert_eq!(reactor.monitored().len(), 2, "the owner and the closer");
    reactor.exit(&pid(6));
    assert_eq!(
        states(&sock).0,
        O::list(vec![atom("closing"), atom("closed")])
    );
    reactor.set_caller(pid(5));
    assert_eq!(
        call("nif_finalize_close", std::slice::from_ref(&sock)),
        error("closed")
    );
    set_reactor(None);
}

#[test]
fn an_owner_that_closes_does_not_monitor_itself_twice() {
    let (_lock, reactor) = reactor_for(5);
    let sock = open("inet", "stream", 6);
    assert_eq!(call("nif_close", std::slice::from_ref(&sock)), atom("ok"));
    assert_eq!(reactor.monitored().len(), 1);
    assert_eq!(
        call("nif_finalize_close", std::slice::from_ref(&sock)),
        atom("ok")
    );
    assert!(
        reactor.monitored().is_empty(),
        "finalize drops the monitors"
    );
    set_reactor(None);
}

#[test]
fn cancel_results_follow_the_requestors() {
    let (_lock, reactor) = reactor_for(5);
    let (sock, _port) = listener();
    assert_eq!(
        call("nif_cancel", &[sock.clone(), atom("accept"), op_ref(1)]),
        atom("not_found")
    );
    assert_eq!(
        call("nif_accept", &[sock.clone(), op_ref(1)]),
        atom("select")
    );
    reactor.set_caller(pid(6));
    assert_eq!(
        call("nif_accept", &[sock.clone(), op_ref(2)]),
        atom("select")
    );
    assert_eq!(
        call("nif_cancel", &[sock.clone(), atom("accept"), op_ref(2)]),
        atom("ok"),
        "a queued acceptor is unqueued"
    );
    reactor.set_caller(pid(7));
    assert_eq!(
        call("nif_cancel", &[sock.clone(), atom("accept"), op_ref(1)]),
        atom("not_found"),
        "only the acceptor itself can cancel"
    );
    reactor.set_caller(pid(5));
    assert_eq!(
        call("nif_cancel", &[sock.clone(), atom("accept"), op_ref(1)]),
        atom("ok")
    );
    assert_eq!(
        call("nif_cancel", &[sock.clone(), atom("recv"), op_ref(1)]),
        atom("not_found")
    );
    assert_eq!(
        call("nif_cancel", &[sock.clone(), atom("send"), op_ref(1)]),
        atom("not_found")
    );
    assert!(
        dispatch("nif_cancel", &[sock.clone(), atom("bogus"), op_ref(1)]).is_err(),
        "an unknown operation is badarg"
    );
    assert!(dispatch("nif_cancel", &[sock.clone(), atom("recv"), atom("x")]).is_err());
    assert_eq!(call("nif_close", std::slice::from_ref(&sock)), atom("ok"));
    assert_eq!(
        call("nif_cancel", &[sock.clone(), atom("recv"), op_ref(1)]),
        error("closed")
    );
    assert_eq!(
        call("nif_cancel", &[sock, atom("bogus"), op_ref(1)]),
        error("closed")
    );
    set_reactor(None);
}

#[test]
fn the_registry_hears_about_opened_and_closed_sockets() {
    let (_lock, reactor) = reactor_for(5);
    load_info(&map(&[("registry", pid(99))]));
    let sock = open("inet", "stream", 6);
    let message = |tag: &str| {
        O::tuple(vec![
            atom("$socket"),
            atom(tag),
            pair(atom("$socket"), sock.clone()),
        ])
    };
    assert_eq!(sent_to(&reactor, &pid(99)), vec![message("add")]);
    assert_eq!(call("nif_close", std::slice::from_ref(&sock)), atom("ok"));
    assert_eq!(
        call("nif_finalize_close", std::slice::from_ref(&sock)),
        atom("ok")
    );
    assert_eq!(
        sent_to(&reactor, &pid(99)),
        vec![message("add"), message("del")]
    );
    let unregistered = open("inet", "stream", 6);
    assert_eq!(
        setopt_otp(&unregistered, 1010, atom("false")),
        invalid("value"),
        "the registry can only be turned on"
    );
    *REGISTRY_PID.lock().unwrap() = None;
    set_reactor(None);
}

#[test]
fn use_registry_turned_on_after_open_sends_the_add_message() {
    let (_lock, reactor) = reactor_for(5);
    load_info(&map(&[("registry", pid(99))]));
    let sock = ok_value(&call(
        "nif_open",
        &[
            atom("inet"),
            atom("stream"),
            O::Int(6),
            map(&[("use_registry", atom("false"))]),
        ],
    ));
    assert_eq!(getopt_otp(&sock, 1010), ok(atom("false")));
    assert!(sent_to(&reactor, &pid(99)).is_empty());
    assert_eq!(setopt_otp(&sock, 1010, atom("true")), atom("ok"));
    assert_eq!(getopt_otp(&sock, 1010), ok(atom("true")));
    assert_eq!(sent_to(&reactor, &pid(99)).len(), 1);
    *REGISTRY_PID.lock().unwrap() = None;
    set_reactor(None);
}

#[test]
fn otp_options_have_the_erts_defaults_and_value_checks() {
    let (_lock, _reactor) = reactor_for(5);
    let sock = open("inet", "stream", 6);
    for (opt, default) in [
        (1001, atom("false")),
        (1002, atom("false")),
        (1004, O::Int(8192)),
        (1006, O::Int(1024)),
        (1007, O::Int(1024)),
        (1009, atom("undefined")),
        (1011, atom("false")),
        (1999, atom("inet")),
    ] {
        assert_eq!(getopt_otp(&sock, opt), ok(default), "option {opt}");
    }
    assert_eq!(getopt_otp(&sock, 1003), ok(pid(5)));
    assert_eq!(getopt_otp(&sock, 1010), ok(atom("true")));
    for (value, expected) in [
        (O::Int(4096), O::Int(4096)),
        (atom("default"), O::Int(8192)),
        (pair(O::Int(3), O::Int(100)), pair(O::Int(3), O::Int(100))),
        (
            pair(O::Int(3), atom("default")),
            pair(O::Int(3), O::Int(8192)),
        ),
    ] {
        assert_eq!(setopt_otp(&sock, 1004, value), atom("ok"));
        assert_eq!(getopt_otp(&sock, 1004), ok(expected));
    }
    for invalid_value in [
        O::Int(0),
        O::Int(-1),
        atom("foo"),
        pair(O::Int(0), O::Int(10)),
        pair(O::Int(2), O::Int(0)),
        O::tuple(vec![O::Int(1), O::Int(2), O::Int(3)]),
    ] {
        assert_eq!(setopt_otp(&sock, 1004, invalid_value), invalid("value"));
    }
    assert_eq!(setopt_otp(&sock, 1006, O::Int(0)), invalid("value"));
    assert_eq!(setopt_otp(&sock, 1007, atom("bad")), invalid("value"));
    assert_eq!(setopt_otp(&sock, 1002, O::Int(1)), invalid("value"));
    assert_eq!(setopt_otp(&sock, 1011, atom("true")), atom("ok"));
    assert_eq!(getopt_otp(&sock, 1011), ok(atom("true")));
    assert_eq!(setopt_otp(&sock, 1009, atom("hello")), atom("ok"));
    assert_eq!(getopt_otp(&sock, 1009), ok(atom("hello")));
    assert_eq!(
        raises(
            "nif_setopt",
            &[
                sock.clone(),
                atom("otp"),
                O::Int(1008),
                O::Int(1),
                O::Int(0)
            ]
        ),
        pair(
            atom("invalid"),
            pair(atom("otp_socket_option"), O::Int(1008))
        )
    );
    assert_eq!(
        raises("nif_getopt", &[sock.clone(), atom("otp"), O::Int(4242)]),
        pair(
            atom("invalid"),
            pair(atom("otp_socket_option"), O::Int(4242))
        )
    );
    assert!(
        dispatch(
            "nif_setopt",
            &[
                sock.clone(),
                atom("otp"),
                O::Int(1001),
                atom("true"),
                O::Int(1)
            ]
        )
        .is_err(),
        "a native value for an otp option is badarg"
    );
    assert_eq!(call("nif_close", std::slice::from_ref(&sock)), atom("ok"));
    for opt in [1001, 1002, 1003, 1004, 1006, 1007, 1008, 1009, 1011, 1999] {
        assert_eq!(getopt_otp(&sock, opt), error("closed"), "option {opt}");
    }
    assert_eq!(setopt_otp(&sock, 1001, atom("true")), error("closed"));
    assert_eq!(getopt_otp(&sock, 1010), ok(atom("true")), "no closed check");
    set_reactor(None);
}

#[test]
fn accepted_sockets_inherit_the_buffer_options_but_not_meta() {
    let (_lock, reactor) = reactor_for(5);
    let (listener, port) = listener();
    assert_eq!(
        setopt_otp(&listener, 1004, pair(O::Int(2), O::Int(4096))),
        atom("ok")
    );
    assert_eq!(setopt_otp(&listener, 1006, O::Int(33)), atom("ok"));
    assert_eq!(setopt_otp(&listener, 1009, atom("meta")), atom("ok"));
    assert_eq!(setopt_otp(&listener, 1011, atom("true")), atom("ok"));
    let client = open("inet", "stream", 6);
    let _ = call("nif_connect", &[client, op_ref(1), address(port)]);
    let accepted = (0..200)
        .find_map(|_| {
            let result = call("nif_accept", &[listener.clone(), op_ref(2)]);
            if result == atom("select") {
                std::thread::sleep(Duration::from_millis(5));
                None
            } else {
                Some(ok_value(&result))
            }
        })
        .expect("accepted");
    assert_eq!(
        getopt_otp(&accepted, 1004),
        ok(pair(O::Int(2), O::Int(4096)))
    );
    assert_eq!(getopt_otp(&accepted, 1006), ok(O::Int(33)));
    assert_eq!(getopt_otp(&accepted, 1009), ok(atom("undefined")));
    assert_eq!(getopt_otp(&accepted, 1011), ok(atom("false")));
    assert_eq!(getopt_otp(&accepted, 1003), ok(pid(5)));
    assert!(reactor.monitored().len() >= 3);
    set_reactor(None);
}

#[test]
fn socket_info_counts_requestors_and_states() {
    let (_lock, _reactor) = reactor_for(5);
    let sock = open("inet", "stream", 6);
    let info = call("nif_info", std::slice::from_ref(&sock));
    assert_eq!(field(&info, "owner"), Some(&pid(5)));
    assert_eq!(field(&info, "ctype"), Some(&atom("normal")));
    assert_eq!(field(&info, "rstates"), Some(&O::Nil));
    assert_eq!(call("nif_bind", &[sock.clone(), address(0)]), atom("ok"));
    assert_eq!(states(&sock).0, O::list(vec![atom("bound")]));
    let global = call("nif_info", &[]);
    let counters = field(&global, "counters").unwrap();
    assert!(number(field(counters, "num_sockets").unwrap()).unwrap() >= 1);
    set_reactor(None);
}

#[test]
fn global_counters_follow_open_and_close() {
    let (_lock, _reactor) = reactor_for(5);
    let count = |key: &str| {
        let global = call("nif_info", &[]);
        number(field(field(&global, "counters").unwrap(), key).unwrap()).unwrap()
    };
    let (sockets, streams, tcp) = (
        count("num_sockets"),
        count("num_tstreams"),
        count("num_ptcp"),
    );
    let sock = open("inet", "stream", 6);
    assert_eq!(count("num_sockets"), sockets + 1);
    assert_eq!(count("num_tstreams"), streams + 1);
    assert_eq!(count("num_ptcp"), tcp + 1);
    assert_eq!(call("nif_close", std::slice::from_ref(&sock)), atom("ok"));
    assert_eq!(
        call("nif_finalize_close", std::slice::from_ref(&sock)),
        atom("ok")
    );
    assert_eq!(count("num_sockets"), sockets);
    assert_eq!(count("num_ptcp"), tcp);
    set_reactor(None);
}

#[test]
fn last_reference_closes_an_open_descriptor_and_drops_the_monitors() {
    let (_lock, reactor) = reactor_for(5);
    let sock = open("inet", "stream", 6);
    assert_eq!(reactor.monitored().len(), 1);
    assert!(handle(&sock).is_ok());
    crate::socket::release_created(0);
    assert!(reactor.monitored().is_empty());
    assert!(handle(&sock).is_err());
    set_reactor(None);
}

#[test]
fn a_selected_socket_lives_until_its_stop_callback_releases_it() {
    let (_lock, reactor) = reactor_for(6);
    let (sock, _port) = listener();
    assert_eq!(
        call("nif_accept", &[sock.clone(), op_ref(1)]),
        atom("select")
    );
    crate::socket::release_created(0);
    assert!(handle(&sock).is_ok(), "the selection holds the resource");
    assert_eq!(reactor.monitored().len(), 2);
    let closed = call("nif_close", std::slice::from_ref(&sock));
    assert!(matches!(closed, O::Atom(_) | O::Tuple(_)));
    assert!(handle(&sock).is_err(), "the stop callback released it");
    assert!(reactor.monitored().is_empty());
    set_reactor(None);
}

#[test]
fn a_selected_socket_with_a_scheduled_stop_lives_until_the_callback_runs() {
    let (_lock, reactor) = reactor_for(7);
    reactor.set_scheduled_stop(true);
    let (sock, _port) = listener();
    assert_eq!(
        call("nif_accept", &[sock.clone(), op_ref(1)]),
        atom("select")
    );
    crate::socket::release_created(0);
    let closed = call("nif_close", std::slice::from_ref(&sock));
    assert!(
        matches!(closed, O::Tuple(_)),
        "a scheduled stop returns a close ref"
    );
    assert!(handle(&sock).is_ok());
    crate::stop(&sock);
    assert!(handle(&sock).is_err());
    set_reactor(None);
}

#[test]
fn errno_atoms_cover_the_erts_table() {
    for (code, text) in [
        (libc::ECONNABORTED, "econnaborted"),
        (libc::ENETDOWN, "enetdown"),
        (libc::EHOSTDOWN, "ehostdown"),
        (libc::EOPNOTSUPP, "eopnotsupp"),
        (libc::EMFILE, "emfile"),
        (libc::ENOENT, "enoent"),
        (libc::ECONNREFUSED, "econnrefused"),
    ] {
        assert_eq!(errno(code), error(text));
    }
    assert_eq!(errno(9999), error("errno_9999"));
}

#[test]
fn socket_options_use_the_option_encoding() {
    let (_lock, _reactor) = reactor_for(5);
    let sock = open("inet", "stream", 6);
    let set = |level: i32, opt: i32, value: O| {
        call(
            "nif_setopt",
            &[
                sock.clone(),
                O::Int(level.into()),
                O::Int(opt.into()),
                value,
                O::Int(0),
            ],
        )
    };
    let get = |level: i32, opt: i32| {
        call(
            "nif_getopt",
            &[sock.clone(), O::Int(level.into()), O::Int(opt.into())],
        )
    };
    assert_eq!(set(libc::IPPROTO_IP, libc::IP_TTL, O::Int(33)), atom("ok"));
    assert_eq!(get(libc::IPPROTO_IP, libc::IP_TTL), ok(O::Int(33)));
    assert_eq!(
        set(libc::SOL_SOCKET, libc::SO_REUSEADDR, O::Int(1)),
        invalid("value"),
        "a boolean option takes a boolean"
    );
    assert_eq!(
        set(libc::SOL_SOCKET, libc::SO_RCVBUF, atom("true")),
        invalid("value"),
        "an integer option takes an integer"
    );
    assert_eq!(
        set(libc::SOL_SOCKET, libc::SO_TYPE, atom("stream")),
        invalid("socket_option")
    );
    assert_eq!(get(libc::SOL_SOCKET, libc::SO_TYPE), ok(atom("stream")));
    assert_eq!(
        set(
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            map(&[("onoff", atom("true")), ("linger", O::Int(-1))])
        ),
        invalid("value")
    );
    assert_eq!(
        set(libc::SOL_SOCKET, libc::SO_LINGER, atom("abort")),
        atom("ok")
    );
    assert_eq!(
        get(libc::SOL_SOCKET, libc::SO_LINGER),
        ok(map(&[("onoff", atom("true")), ("linger", O::Int(0))]))
    );
    assert_eq!(
        set(libc::IPPROTO_IP, libc::IP_TOS, atom("lowdelay")),
        atom("ok")
    );
    let tos = get(libc::IPPROTO_IP, libc::IP_TOS);
    let O::Tuple(parts) = &tos else {
        panic!("{tos:?}")
    };
    assert_eq!(field(&parts[1], "native"), Some(&O::Int(16)));
    assert_eq!(
        field(&parts[1], "tos"),
        Some(&map(&[
            ("precedence", atom("routine")),
            ("tos", atom("lowdelay"))
        ]))
    );
    assert_eq!(field(&parts[1], "dscp"), Some(&O::Int(4)));
    set_reactor(None);
}

#[test]
fn commands_validate_their_data() {
    assert_eq!(
        raises(
            "nif_command",
            &[map(&[("command", atom("debug")), ("data", O::Int(1))])]
        ),
        pair(atom("invalid"), pair(atom("data"), O::Int(1)))
    );
    assert_eq!(
        raises(
            "nif_command",
            &[map(&[("command", atom("bogus")), ("data", atom("true"))])]
        ),
        pair(atom("invalid"), pair(atom("command"), atom("bogus")))
    );
}
