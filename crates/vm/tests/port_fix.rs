use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const SOURCE: &str = r#"
-module(port_fix).
-export([owner_exit/0, busy_nosuspend/0, busy_suspend/0, signal_toggle/0,
         fd_close/0, fd_hold/2, force/0]).

owner_exit() ->
    process_flag(trap_exit, true),
    Parent = self(),
    Owner = spawn(fun() ->
        P = open_port({spawn_executable, "/bin/sleep"}, [{args, ["30"]}]),
        Parent ! {ready, P},
        receive stop -> ok end
    end),
    receive
        {ready, P} ->
            Ref = erlang:monitor(port, P),
            true = link(P),
            Owner ! stop,
            Down = receive {'DOWN', Ref, port, P, normal} -> down after 1000 -> nodown end,
            Exit = receive {'EXIT', P, normal} -> exited after 1000 -> noexit end,
            Info = erlang:port_info(P),
            {Down, Exit, Info}
    after 1000 -> timeout
    end.

busy_nosuspend() ->
    process_flag(trap_exit, true),
    P = open_port({spawn_executable, "/bin/sleep"},
        [{args, ["30"]}, {busy_limits_port, {1, 64}}, {busy_limits_msgq, {1, 4}},
         {parallelism, true}, out]),
    Chunk = <<0:(4096*8)>>,
    Result = fill(P, Chunk),
    kill_port(P),
    Result.

busy_suspend() ->
    process_flag(trap_exit, true),
    P = open_port({spawn_executable, "/bin/sleep"},
        [{args, ["30"]}, {busy_limits_port, {1, 64}}, {parallelism, true}, out]),
    Chunk = <<0:(4096*8)>>,
    N = fill(P, Chunk),
    Parent = self(),
    spawn(fun() ->
        Res = try port_command(P, Chunk) catch error:R -> {error, R} end,
        Parent ! {res, Res}
    end),
    Early = receive {res, R} -> {early, R} after 200 -> suspended end,
    kill_port(P),
    Later = receive {res, R2} -> R2 after 2000 -> timeout end,
    {N > 0, Early, Later}.

force() ->
    P = open_port({spawn, "cat"}, []),
    R = try port_command(P, <<"x">>, [force]) catch error:E -> {error, E} end,
    true = port_close(P),
    R.

fd_close() ->
    P = open_port({fd, 0, 2}, []),
    try port_close(P) catch error:badarg -> true end.

fd_hold(ReadFd, WriteFd) ->
    P = open_port({fd, ReadFd, WriteFd}, [eof]),
    port_close(P).

signal_toggle() ->
    case whereis(erl_signal_server) of
        undefined -> register(erl_signal_server, self());
        Pid when Pid =:= self() -> true;
        _Other ->
            unregister(erl_signal_server),
            register(erl_signal_server, self())
    end,
    try
        lists:map(fun(_) ->
            ok = os:set_signal(sigusr1, handle),
            A = ping(),
            ok = os:set_signal(sigusr1, ignore),
            B = ping(),
            ok = os:set_signal(sigusr1, default),
            ok = os:set_signal(sigusr1, handle),
            C = ping(),
            {A, B, C}
        end, [1, 2, 3])
    after
        catch os:set_signal(sigusr1, ignore),
        catch unregister(erl_signal_server)
    end.

fill(P, Chunk) ->
    fill(P, Chunk, 0).
%% A `false` that is still `false` after the driver has had time to run means
%% the pipe is full. A single `false` can clear before the next command.
fill(_P, _Chunk, N) when N > 80 ->
    never;
fill(P, Chunk, N) ->
    case port_command(P, Chunk, [nosuspend]) of
        true -> fill(P, Chunk, N + 1);
        false ->
            receive after 50 -> ok end,
            case port_command(P, Chunk, [nosuspend]) of
                false -> {false, N > 0};
                true -> fill(P, Chunk, N + 1)
            end
    end.

ping() ->
    receive {notify, sigusr1} -> ok after 0 -> ok end,
    P = open_port({spawn_executable, "/bin/kill"},
        [{args, ["-USR1", os:getpid()]}, exit_status]),
    Result = receive {notify, sigusr1} -> delivered after 1500 -> ignored end,
    receive {P, {exit_status, _}} -> ok after 1000 -> ok end,
    catch port_close(P),
    Result.

kill_port(P) ->
    Os = proplists:get_value(os_pid, erlang:port_info(P)),
    K = open_port({spawn_executable, "/bin/kill"},
        [{args, ["-9", integer_to_list(Os)]}, exit_status]),
    receive {K, {exit_status, _}} -> ok after 2000 -> ok end.
"#;

fn run(reference: &RefErl, beam: &[u8], function: &str) -> (CallResult, OwnedTerm) {
    let expected = reference.call("port_fix", function, &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(beam).unwrap();
    let actual = vm
        .eval_scheduled("port_fix", function, &[], 2, None)
        .unwrap_or_else(|error| panic!("{function}: {error:?}"));
    (expected, actual.term)
}

#[test]
fn owner_exit_closes_ports_synchronously() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping owner-exit differential test");
        return;
    };
    let beam = reference.compile_named("port_fix", SOURCE, &[]).unwrap();
    reference.load("port_fix", &beam).unwrap();
    let (expected, actual) = run(&reference, &beam, "owner_exit");
    assert_eq!(expected, CallResult::Ok(actual));
}

#[test]
fn busy_port_nosuspend_is_false_and_otherwise_suspends() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping busy-port differential test");
        return;
    };
    let beam = reference.compile_named("port_fix", SOURCE, &[]).unwrap();
    reference.load("port_fix", &beam).unwrap();
    for function in ["busy_nosuspend", "busy_suspend", "force"] {
        let (expected, actual) = run(&reference, &beam, function);
        assert_eq!(expected, CallResult::Ok(actual), "{function}");
    }
}

#[test]
fn signal_toggle_three_times_matches_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping signal-toggle differential test");
        return;
    };
    let beam = reference.compile_named("port_fix", SOURCE, &[]).unwrap();
    reference.load("port_fix", &beam).unwrap();
    let (expected, actual) = run(&reference, &beam, "signal_toggle");
    assert_eq!(expected, CallResult::Ok(actual));
}

#[test]
fn closing_fd_port_unblocks_a_blocked_read() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping fd-port differential test");
        return;
    };
    let beam = reference.compile_named("port_fix", SOURCE, &[]).unwrap();
    reference.load("port_fix", &beam).unwrap();
    let (expected, actual) = run(&reference, &beam, "fd_close");
    assert_eq!(expected, CallResult::Ok(actual));

    let mut fds = [0; 2];
    // SAFETY: pipe initializes both slots with fresh descriptors on success.
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    assert_eq!(rc, 0);
    // SAFETY: both descriptors were just created by pipe and are not aliased.
    let (read, mut write) = unsafe {
        (
            OwnedFd::from_raw_fd(fds[0]),
            FileWriter(OwnedFd::from_raw_fd(fds[1])),
        )
    };
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let args = [
        arinsal_term::Term::small(i64::from(read.as_raw_fd())).unwrap(),
        arinsal_term::Term::small(i64::from(write.0.as_raw_fd())).unwrap(),
    ];
    vm.eval_scheduled("port_fix", "fd_hold", &args, 1, None)
        .expect("fd port close");
    // The worker must have stopped selecting the duplicated input fd.
    std::thread::sleep(std::time::Duration::from_millis(100));
    write.write_all(&[0x5a]).unwrap();
    set_nonblock(read.as_raw_fd());
    let mut buf = [0u8; 1];
    // SAFETY: `read` is still the open pipe end; the port closed only its duplicate.
    let n = unsafe { libc::read(read.as_raw_fd(), buf.as_mut_ptr().cast(), 1) };
    assert_eq!(
        n, 1,
        "close must unblock the port worker so it does not consume this byte"
    );
    assert_eq!(buf[0], 0x5a);
}

struct FileWriter(OwnedFd);
impl Write for FileWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // SAFETY: the owned pipe end is still open.
        let n = unsafe { libc::write(self.0.as_raw_fd(), buf.as_ptr().cast(), buf.len()) };
        if n < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn set_nonblock(fd: i32) {
    // SAFETY: fcntl only changes flags on the caller's pipe end.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }
}
