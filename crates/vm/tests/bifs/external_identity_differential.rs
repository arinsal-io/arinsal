//! External pids, ports and references (ExternalThing with a node table entry) against OTP:
//! term order, equality, phash/phash2, node/1, the ETF round trip, nodes(known) and the node
//! table entries the identities keep alive.
use arinsal_difftest::{CallResult, RefErl};
use similar_asserts::assert_eq;

const MODULE: &str = "external_identity_differential";
const SOURCE: &str = r#"
-module(external_identity_differential).
-export([run/0]).

atom_ext(A) -> B = atom_to_binary(A), <<119, (byte_size(B)), B/binary>>.
pid(N, C, I, S) -> binary_to_term(<<131, 88, (atom_ext(N))/binary, I:32, S:32, C:32>>).
port(N, C, I) -> binary_to_term(<<131, 120, (atom_ext(N))/binary, I:64, C:32>>).
ref(N, C, Ids) ->
    binary_to_term(<<131, 90, (length(Ids)):16, (atom_ext(N))/binary, C:32,
                     << <<X:32>> || X <- Ids >>/binary>>).

ids() ->
    A = 'ext_a@127.0.0.1', B = 'ext_b@127.0.0.1',
    [pid(A, 1, 5, 0), pid(A, 2, 5, 0), pid(B, 1, 5, 0), pid(A, 1, 6, 1), pid(A, 1, 4, 2),
     pid(A, 16#FFFFFFFF, 1, 1), pid(B, 1, 5, 0),
     port(A, 1, 7), port(B, 3, 1 bsl 40), port(A, 2, 7),
     ref(A, 1, [1, 2, 3]), ref(A, 1, [1, 2]), ref(B, 1, [9, 8, 7, 6, 5]),
     ref(A, 2, [1, 2, 3]), ref(A, 1, [3, 2, 1, 0, 0])].

run() ->
    L = ids(),
    Local = [self(), make_ref(), hd(erlang:ports() ++ [self()])],
    All = L ++ Local,
    Sorted = [index_of(X, All) || X <- lists:sort(All)],
    Eq = [[{X == Y, X =:= Y, X < Y} || Y <- L] || X <- L],
    Hash = [{erlang:phash2(X), erlang:phash2(X, 1000), erlang:phash(X, 1 bsl 32)} || X <- L],
    Nodes = [node(X) || X <- L],
    Etf = [{term_to_binary(X), binary_to_term(term_to_binary(X)) =:= X,
            term_to_binary(X, [{minor_version, 1}])} || X <- L],
    Known = [N || N <- ['ext_a@127.0.0.1', 'ext_b@127.0.0.1'], lists:member(N, nodes(known))],
    Map = maps:from_list([{X, I} || {X, I} <- lists:zip(L, lists:seq(1, length(L)))]),
    MapKeys = [index_of(K, All) || K <- maps:keys(Map)],
    {Sorted, Eq, Hash, Nodes, Etf, Known, MapKeys, lists:usort(L) =:= lists:usort(lists:reverse(L))}.

index_of(X, L) -> index_of(X, L, 1).
index_of(X, [Y | _], I) when X =:= Y -> I;
index_of(X, [_ | T], I) -> index_of(X, T, I + 1).
"#;

#[test]
fn external_identities_match_otp() {
    let reference = RefErl::start().expect("OTP 29.1.1 reference");
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile fixture");
    reference.load(MODULE, &beam).unwrap();
    let expected = reference.call(MODULE, "run", &[]);
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).unwrap();
    let actual = match vm.eval_scheduled(MODULE, "run", &[], 1) {
        Ok(result) => CallResult::Ok(result.term),
        Err(error) => CallResult::TransportError(error.to_string()),
    };
    assert_eq!(actual, expected);
}

#[test]
fn node_table_keeps_one_entry_while_identities_live() {
    let name = arinsal_term::global_atoms()
        .intern("ext_table@127.0.0.1")
        .unwrap();
    let mut heap = arinsal_term::ProcessHeap::with_words(64);
    let node = arinsal_term::Node::new(name, 3);
    let pid = arinsal_term::TermBuilder::new(&mut heap)
        .external_pid(arinsal_term::Node::new(name, 3), 1, 0)
        .unwrap();
    assert_eq!(node.refc(), 2);
    let mut copy_heap = arinsal_term::ProcessHeap::with_words(64);
    let _copy = arinsal_term::copy_term(pid, &mut copy_heap).unwrap();
    assert_eq!(node.refc(), 3);
    drop(copy_heap);
    drop(heap);
    assert_eq!(node.refc(), 1);
    drop(node);
    assert!(!arinsal_term::node_table_entries().contains(&(name, 3)));
}
