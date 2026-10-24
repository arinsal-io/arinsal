//! End of input on spawn and fd ports: messages, exit status and descriptor release
//! against the reference emulator.
use arinsal_difftest::{CallOptions, CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::{ProcessHeap, from_owned};
use arinsal_vm::Vm;
use std::sync::Mutex;

/// The descriptor counts are process wide, so the scenarios run one at a time.
static SERIAL: Mutex<()> = Mutex::new(());

const SOURCE: &str = r#"
-module(port_eof_close_diff).
-export([messages/0, fd_growth_eof/0, fd_growth_exit/0, fd_cycle/2, fd_cycles/1]).

sh(Opts, Script) ->
    open_port({spawn_executable, "/bin/sh"}, [{args, ["-c", Script]} | Opts]).

flush() ->
    receive M -> [M | flush()] after 500 -> [] end.

alive(P) -> erlang:port_info(P) =/= undefined.

norm(P, {P, X}) -> {port, X};
norm(P, {'EXIT', P, R}) -> {exit_port, R};
norm(_, M) -> M.

scenario(Name, Opts, Script) ->
    process_flag(trap_exit, true),
    P = sh(Opts, Script),
    Msgs = [norm(P, M) || M <- flush()],
    Alive = alive(P),
    try port_close(P) catch error:badarg -> ok end,
    flush(),
    {Name, Msgs, Alive}.

messages() ->
    [scenario(eof_only, [binary, eof], "exec 1>&-; sleep 2"),
     scenario(no_eof_option, [binary], "exec 1>&-; sleep 2"),
     scenario(eof_data, [binary, eof], "printf abc; exec 1>&-; sleep 2"),
     scenario(eof_in, [binary, eof, in], "exec 1>&-; sleep 2"),
     scenario(eof_status_late, [binary, eof, exit_status], "exec 1>&-; sleep 0.3; exit 3"),
     scenario(status_no_eof_late, [binary, exit_status], "exec 1>&-; sleep 0.3; exit 3"),
     scenario(eof_status_early, [binary, eof, exit_status], "printf abc; exit 4"),
     scenario(status_no_eof_early, [binary, exit_status], "printf abc; exit 4"),
     scenario(status_signaled, [binary, eof, exit_status], "kill -9 $$"),
     scenario(in_status, [binary, in, exit_status], "printf x; exit 5"),
     scenario(out_status, [binary, out, exit_status], "exit 5"),
     scenario(packet_partial_eof, [binary, eof, {packet, 2}], "printf '\\000\\005ab'; exec 1>&-; sleep 2"),
     scenario(packet_partial, [binary, {packet, 2}], "printf '\\000\\005ab'; exec 1>&-; sleep 2"),
     scenario(line_partial_eof, [binary, eof, {line, 100}], "printf 'abc'; exec 1>&-; sleep 2"),
     scenario(line_partial, [binary, {line, 100}], "printf 'abc'; exec 1>&-; sleep 2"),
     scenario(stream_list, [stream], "printf hi; exec 1>&-; sleep 2")].

fds() ->
    {ok, L} = prim_file:list_dir("/dev/fd"),
    length(L).

settled(Before, Slack, 0) ->
    {leak, fds() - Before - Slack};
settled(Before, Slack, N) ->
    case fds() - Before =< Slack of
        true -> ok;
        false -> receive after 100 -> ok end, settled(Before, Slack, N - 1)
    end.

repeat(0, _) -> ok;
repeat(N, Fun) -> Fun(), repeat(N - 1, Fun).

grow(Fun) ->
    process_flag(trap_exit, true),
    Fun(),
    Before = fds(),
    repeat(1000, Fun),
    settled(Before, 8, 100).

fd_growth_eof() ->
    grow(fun() ->
        P = sh([binary, eof], "exec 1>&-"),
        receive {P, eof} -> ok after 10000 -> error(no_eof) end,
        true = port_close(P)
    end).

fd_growth_exit() ->
    grow(fun() ->
        P = sh([binary], "exec 1>&-"),
        receive {'EXIT', P, normal} -> ok after 10000 -> error(no_exit) end
    end).

fd_cycle(ReadFd, WriteFd) ->
    P = open_port({fd, ReadFd, WriteFd}, [eof]),
    receive {P, eof} -> ok after 10000 -> error(no_eof) end,
    true = port_close(P),
    ok.

fd_cycles([]) -> ok;
fd_cycles([{ReadFd, WriteFd} | Rest]) ->
    ok = fd_cycle(ReadFd, WriteFd),
    fd_cycles(Rest).
"#;

fn compare(function: &str) {
    let _guard = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping port eof differential test");
        return;
    };
    let beam = reference
        .compile_named("port_eof_close_diff", SOURCE, &[])
        .unwrap();
    reference.load("port_eof_close_diff", &beam).unwrap();
    let options = CallOptions {
        timeout_ms: Some(300_000),
        ..CallOptions::default()
    };
    let expected = reference
        .call_opts("port_eof_close_diff", function, &[], &options)
        .result;
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("port_eof_close_diff", function, &[], 2, None)
        .unwrap_or_else(|error| panic!("{function}: {error:?}"));
    assert_eq!(expected, CallResult::Ok(actual.term), "{function}");
}

#[test]
fn eof_messages_exit_status_and_port_life_match_otp() {
    compare("messages");
}

#[test]
fn spawn_port_with_eof_option_releases_the_input_descriptor() {
    compare("fd_growth_eof");
}

#[test]
fn spawn_port_closed_by_eof_releases_every_descriptor() {
    compare("fd_growth_exit");
}

fn open_fds() -> usize {
    std::fs::read_dir("/dev/fd").unwrap().count()
}

fn pipe() -> (i32, i32) {
    let mut fds = [0; 2];
    // SAFETY: pipe initializes both slots with fresh descriptors on success.
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    assert_eq!(rc, 0);
    (fds[0], fds[1])
}

fn close(fd: i32) {
    // SAFETY: the caller owns `fd` and does not use it again.
    unsafe { libc::close(fd) };
}

#[test]
fn fd_port_releases_the_input_descriptor_at_eof() {
    let _guard = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping fd port eof test");
        return;
    };
    let beam = reference
        .compile_named("port_eof_close_diff", SOURCE, &[])
        .unwrap();
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let before = open_fds();
    let mut cycle_args = Vec::with_capacity(1000);
    let mut descriptors = Vec::with_capacity(3000);
    for _ in 0..1000 {
        let (input_read, input_write) = pipe();
        let (output_read, output_write) = pipe();
        close(input_write);
        cycle_args.push(OwnedTerm::Tuple(vec![
            OwnedTerm::Int(i64::from(input_read)),
            OwnedTerm::Int(i64::from(output_write)),
        ]));
        descriptors.extend([input_read, output_read, output_write]);
    }
    let input = OwnedTerm::List {
        elems: cycle_args,
        tail: Box::new(OwnedTerm::Nil),
    };
    let mut heap = ProcessHeap::with_words(10_000);
    let argument = from_owned(&input, &mut heap).expect("build fd cycles");
    let result = vm.eval_scheduled("port_eof_close_diff", "fd_cycles", &[argument], 1, None);
    for fd in descriptors {
        close(fd);
    }
    result.expect("fd port cycles");
    let mut after = open_fds();
    for _ in 0..50 {
        if after <= before + 8 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
        after = open_fds();
    }
    assert!(
        after <= before + 8,
        "descriptors grew from {before} to {after} over 1000 fd port cycles"
    );
}
