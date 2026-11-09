use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(ram_file_compat).
-export([driver_open/0, full_ops/0, mode_errors/0, growth/0, large_offsets/0, hold/0, churn/0]).

driver_open() ->
    case catch open_port({spawn_driver, "ram_file_drv"}, []) of
        Port when is_port(Port) ->
            Command = catch erlang:port_command(Port, <<1, 3:32, "abc">>),
            Reply = receive {Port, {data, Data}} -> {data, Data} after 1000 -> timeout end,
            ReadCommand = catch erlang:port_command(Port, <<2, 3:32>>),
            ReadReply = receive {Port, {data, ReadData}} -> {data, ReadData} after 1000 -> timeout end,
            Close = catch erlang:port_close(Port),
            {opened, Command, Reply, ReadCommand, ReadReply, Close};
        Error -> {open_failed, Error}
    end.

full_ops() ->
    Data = <<"abc">>,
    {ok, File} = ram_file:open(Data, [read, write, binary]),
    {ok, 3} = ram_file:get_size(File),
    {ok, Data} = ram_file:pread(File, 0, 3),
    {ok, <<>>} = ram_file:pread(File, 3, 0),
    eof = ram_file:pread(File, 3, 1),
    ok = ram_file:pwrite(File, 6, <<"Z">>),
    {ok, 7} = ram_file:get_size(File),
    {ok, <<"abc", 0, 0, 0, "Z">>} = ram_file:get_file(File),
    {ok, 0} = ram_file:position(File, bof),
    {ok, <<"abc", 0, 0, 0, "Z">>} = ram_file:read(File, 7),
    eof = ram_file:read(File, 1),
    {ok, 0} = ram_file:position(File, {eof, -7}),
    ok = ram_file:write(File, <<"x">>),
    {ok, 1} = ram_file:position(File, cur),
    ok = ram_file:sync(File),
    ok = ram_file:datasync(File),
    ok = ram_file:advise(File, 0, 1, normal),
    ok = ram_file:advise(File, 0, 1, random),
    ok = ram_file:advise(File, 0, 1, sequential),
    ok = ram_file:advise(File, 0, 1, will_need),
    ok = ram_file:advise(File, 0, 1, dont_need),
    ok = ram_file:advise(File, 0, 1, no_reuse),
    ok = ram_file:allocate(File, 0, 1),
    ok = ram_file:truncate(File),
    {ok, 1} = ram_file:get_size(File),
    {ok, <<"x">>} = ram_file:get_file(File),
    {ok, 0} = ram_file:position(File, 0),
    ok = ram_file:truncate(File),
    {ok, 0} = ram_file:get_size(File),
    {ok, <<>>} = ram_file:get_file(File),
    ok = ram_file:close(File),
    ok.

mode_errors() ->
    {ok, ReadOnly} = ram_file:open(<<"r">>, [read]),
    {error, ebadf} = ram_file:write(ReadOnly, <<"x">>),
    {error, eacces} = ram_file:truncate(ReadOnly),
    ok = ram_file:sync(ReadOnly),
    ok = ram_file:datasync(ReadOnly),
    {ok, "r"} = ram_file:read(ReadOnly, 1),
    ok = ram_file:close(ReadOnly),
    {ok, WriteOnly} = ram_file:open([], [write]),
    {error, ebadf} = ram_file:read(WriteOnly, 1),
    {error, ebadf} = ram_file:pread(WriteOnly, 0, 1),
    ok = ram_file:close(WriteOnly),
    ok.

growth() ->
    {ok, File} = ram_file:open([], [read, write, binary]),
    Data = binary:copy(<<16#5a>>, 4097),
    ok = ram_file:write(File, Data),
    {ok, 4097} = ram_file:get_size(File),
    {ok, Data} = ram_file:pread(File, 0, 4097),
    {ok, 4097} = ram_file:position(File, cur),
    ok = ram_file:close(File),
    ok.

hold() ->
    {ok, File} = ram_file:open(<<"held">>, [read, write, binary]),
    Deadline = erlang:monotonic_time(millisecond) + 1500,
    ok = hold_loop(File, Deadline),
    ok = ram_file:close(File),
    ok.

hold_loop(File, Deadline) ->
    case erlang:monotonic_time(millisecond) >= Deadline of
        true ->
            ok;
        false ->
            {ok, <<"held">>} = ram_file:pread(File, 0, 4),
            ok = ram_file:pwrite(File, 4, <<"!">>),
            {ok, <<"held!">>} = ram_file:pread(File, 0, 5),
            receive after 5 -> ok end,
            hold_loop(File, Deadline)
    end.

churn() ->
    churn(40).

churn(0) ->
    ok;
churn(Rounds) ->
    ok = growth(),
    ok = mode_errors(),
    churn(Rounds - 1).

large_offsets() ->
    {ok, File} = ram_file:open(<<"abc">>, [read, write, binary]),
    Max = (1 bsl 31) - 1,
    {ok, Max} = ram_file:position(File, {bof, Max}),
    {ok, <<>>} = ram_file:read(File, 0),
    eof = ram_file:read(File, 1),
    eof = ram_file:pread(File, Max, 1),
    {ok, <<>>} = ram_file:pread(File, Max, 0),
    {error, einval} = ram_file:position(File, {bof, 1 bsl 31}),
    ok = ram_file:close(File),
    ok.
"#;

fn compare(function: &str) {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping ram_file differential test");
        return;
    };
    let beam = reference
        .compile_named("ram_file_compat", SOURCE, &[])
        .expect("compile ram_file_compat");
    reference
        .load("ram_file_compat", &beam)
        .expect("load ram_file_compat");
    let expected = reference.call("ram_file_compat", function, &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load Arinsal module");
    let actual = vm
        .eval_scheduled("ram_file_compat", function, &[], 2, None)
        .unwrap_or_else(|error| panic!("Arinsal {function}: {error}"));
    similar_asserts::assert_eq!(expected, CallResult::Ok(actual.term), "{function}");
}

#[test]
fn static_driver_open_and_commands_match_erts() {
    compare("driver_open");
}

#[test]
fn file_operations_match_erts() {
    compare("full_ops");
}

#[test]
fn access_mode_errors_match_erts() {
    compare("mode_errors");
}

#[test]
fn growth_matches_erts() {
    compare("growth");
}

#[test]
fn large_offsets_match_erts() {
    compare("large_offsets");
}

#[test]
fn ports_of_concurrent_vms_are_independent() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping ram_file differential test");
        return;
    };
    let beam = reference
        .compile_named("ram_file_compat", SOURCE, &[])
        .expect("compile ram_file_compat");
    let run = |function: &'static str| {
        let beam = beam.clone();
        std::thread::spawn(move || {
            let mut vm = Vm::new([]);
            vm.load_bytes(&beam).expect("load Arinsal module");
            vm.eval_scheduled("ram_file_compat", function, &[], 2, None)
                .map(|result| result.term)
        })
    };
    let holder = run("hold");
    let churners: Vec<_> = (0..3).map(|_| run("churn")).collect();
    for (name, thread) in
        std::iter::once(("hold", holder)).chain(churners.into_iter().map(|t| ("churn", t)))
    {
        let term = thread
            .join()
            .expect("Vm thread")
            .unwrap_or_else(|error| panic!("Arinsal {name}: {error}"));
        similar_asserts::assert_eq!(OwnedTerm::Atom("ok".into()), term, "{name}");
    }
}
