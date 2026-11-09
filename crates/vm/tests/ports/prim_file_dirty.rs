//! prim_file writes against erl 29.1.1: iovec writes of large binaries, iolists of many
//! sub-binaries and pwrite at offsets, and the dirty IO scheduling erts declares for the
//! prim_file NIFs (erts/emulator/nifs/common/prim_file_nif.c:177-219).

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::Term;
use arinsal_vm::Vm;

const SOURCE: &str = r##"
-module(prim_file_dirty).
-export([run/1]).

dir(Tag) ->
    Base = case os:getenv("TMPDIR") of false -> "/tmp"; T -> T end,
    D = filename:join(Base, "prim_file_dirty_" ++ os:getpid() ++ "_" ++ atom_to_list(Tag)),
    case prim_file:make_dir(D) of ok -> ok; {error, eexist} -> ok end,
    D.

%% A refc binary of `Bytes` bytes whose content shows any misplaced segment.
big(Bytes) ->
    Pattern = list_to_binary([I rem 251 || I <- lists:seq(1, 1021)]),
    binary:part(binary:copy(Pattern, Bytes div 1021 + 1), 0, Bytes).

cleanup(D, Files) ->
    [prim_file:delete(filename:join(D, F)) || F <- Files],
    prim_file:del_dir(D).

run(0) ->
    %% file:write_file/3 [raw] of a 32 MiB binary.
    D = dir(write_file),
    F = filename:join(D, "big"),
    Big = big(32 * 1024 * 1024),
    Write = file:write_file(F, Big, [raw]),
    {ok, Back} = prim_file:read_file(F),
    cleanup(D, ["big"]),
    {Write, byte_size(Back), Back =:= Big};

run(1) ->
    %% An iolist of many sub-binaries (more than the 64 cells one write_nif call takes),
    %% heap binaries, characters and an unaligned sub-binary; then pwrite at offsets.
    D = dir(iolist),
    F = filename:join(D, "parts"),
    Big = big(4 * 1024 * 1024),
    <<_:3, Unaligned:4096/binary, _/bitstring>> = Big,
    Subs = [binary:part(Big, I * 4099, 4099) || I <- lists:seq(0, 299)],
    IoList = [Subs, <<"small">>, [Unaligned, $x, "chars"] | Subs],
    {ok, Fd} = file:open(F, [raw, binary, read, write]),
    W1 = file:write(Fd, IoList),
    {ok, Pos} = file:position(Fd, cur),
    W2 = file:pwrite(Fd, 10, [<<"P">>, Subs]),
    W3 = file:pwrite(Fd, [{0, <<"head">>}, {Pos + 100, IoList}, {3 * Pos, Big}]),
    {ok, Size} = file:position(Fd, eof),
    {ok, Read} = file:pread(Fd, 10, 4100),
    ok = file:close(Fd),
    {ok, All} = prim_file:read_file(F),
    cleanup(D, ["parts"]),
    {W1, W2, W3, Pos =:= iolist_size(IoList), Size,
     Read =:= iolist_to_binary([<<"P">>, hd(Subs)]), erlang:md5(All)};

run(2) ->
    %% Long writes run on a dirty IO scheduler: an observer on a normal scheduler sees the
    %% writer executing dirty while it keeps running itself.
    D = dir(dirty),
    F = filename:join(D, "dirty"),
    Big = big(64 * 1024 * 1024),
    Parent = self(),
    Writer = spawn_link(fun() ->
        {ok, Fd} = file:open(F, [raw, binary, write]),
        Results = [file:pwrite(Fd, 0, Big) || _ <- lists:seq(1, 8)],
        ok = file:close(Fd),
        Parent ! {done, self(), Results}
    end),
    {Results, DirtySeen, Polls} = observe(Writer, false, 0),
    cleanup(D, ["dirty"]),
    {Results, DirtySeen, Polls > 0}.

observe(Writer, DirtySeen, Polls) ->
    Dirty = erts_internal:is_process_executing_dirty(Writer),
    receive
        {done, Writer, Results} -> {Results, DirtySeen orelse Dirty, Polls}
    after 0 -> observe(Writer, DirtySeen orelse Dirty, Polls + 1)
    end.
"##;

fn assert_scenario(reference: &RefErl, scenario: i64) -> OwnedTerm {
    let beam = reference
        .compile_named("prim_file_dirty", SOURCE, &[])
        .expect("compile prim_file_dirty");
    reference
        .load("prim_file_dirty", &beam)
        .expect("load into erl");
    let expected = reference.call("prim_file_dirty", "run", &[OwnedTerm::Int(scenario)]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load into arinsal");
    let actual = vm
        .eval_scheduled(
            "prim_file_dirty",
            "run",
            &[Term::small(scenario).unwrap()],
            2,
            None,
        )
        .unwrap_or_else(|error| panic!("scenario {scenario}: {error}"));
    assert_eq!(
        expected,
        CallResult::Ok(actual.term.clone()),
        "scenario {scenario}"
    );
    actual.term
}

fn reference(name: &str) -> Option<RefErl> {
    match RefErl::start() {
        Ok(reference) => Some(reference),
        Err(_) => {
            eprintln!("erl unavailable; skipping {name}");
            None
        }
    }
}

#[test]
fn prim_file_write_file_large_binary_matches_otp() {
    let Some(reference) = reference("prim_file_write_file_large_binary_matches_otp") else {
        return;
    };
    let term = assert_scenario(&reference, 0);
    assert_eq!(
        term,
        OwnedTerm::Tuple(vec![
            OwnedTerm::atom("ok"),
            OwnedTerm::Int(32 * 1024 * 1024),
            OwnedTerm::atom("true"),
        ])
    );
}

#[test]
fn prim_file_iolist_and_pwrite_match_otp() {
    let Some(reference) = reference("prim_file_iolist_and_pwrite_match_otp") else {
        return;
    };
    assert_scenario(&reference, 1);
}

#[test]
fn prim_file_writes_run_on_dirty_io_as_otp() {
    let Some(reference) = reference("prim_file_writes_run_on_dirty_io_as_otp") else {
        return;
    };
    let term = assert_scenario(&reference, 2);
    let OwnedTerm::Tuple(ref fields) = term else {
        panic!("scenario 2 result")
    };
    assert_eq!(fields[1], OwnedTerm::atom("true"), "writer seen dirty");
}
