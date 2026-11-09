use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;
use similar_asserts::assert_eq;
use std::path::Path;
use std::process::Command;

const SOURCE: &str = r#"
-module(etf_external_error_info_diff).
-export([badopt/0]).
badopt() ->
    try binary_to_term(term_to_binary(ok), [bad]) of
        Value -> Value
    catch
        error:Reason:Stack ->
            [{_, _, _, Info} | _] = Stack,
            Cause = maps:get(cause, proplists:get_value(error_info, Info, #{}), none),
            {Reason, Cause}
    end.
"#;

#[test]
fn binary_to_term_badopt_error_info_matches_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping binary_to_term error_info differential test");
        return;
    };
    let beam = reference
        .compile_named("etf_external_error_info_diff", SOURCE, &[])
        .unwrap();
    reference
        .load("etf_external_error_info_diff", &beam)
        .unwrap();
    let expected = reference.call("etf_external_error_info_diff", "badopt", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("etf_external_error_info_diff", "badopt", &[], 1, Some(73))
        .unwrap()
        .term;
    let CallResult::Ok(expected) = expected else {
        panic!("reference call failed: {expected:?}");
    };
    assert_eq!(
        actual,
        OwnedTerm::Tuple(vec![OwnedTerm::atom("badarg"), OwnedTerm::atom("badopt")])
    );
    assert_eq!(actual, expected);
}

#[test]
fn external_size_local_identities_match_term_to_binary_on_named_node() {
    let eval = r#"Terms=[self(),make_ref(),hd(erlang:ports())],
        Opts=[[],[{minor_version,1}],[local],[compressed,{minor_version,1}]],
        Results=[[{erlang:external_size(T,O),
                    byte_size(term_to_binary(T,lists:delete(compressed,O)))}
                   || O<-Opts] || T<-Terms],
        io:format("EXT_SIZE ~p~n",[Results]), halt()."#;
    let flags = [
        "-noshell",
        "-noinput",
        "-sname",
        "ext_size_node_diff",
        "-kernel",
        "inet_dist_use_interface",
        "{127,0,0,1}",
        "-eval",
        eval,
    ];
    let run = |program: &Path| {
        let output = Command::new("timeout")
            .args(["--kill-after=3", "90"])
            .arg(program)
            .args(flags)
            .output()
            .unwrap_or_else(|error| panic!("run {}: {error}", program.display()));
        assert!(
            output.status.success(),
            "{} failed: {}\n{}",
            program.display(),
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        );
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .find(|line| line.starts_with("EXT_SIZE "))
            .unwrap_or_else(|| panic!("{} omitted EXT_SIZE output", program.display()))
            .to_owned()
    };
    let expected = run(Path::new("erl"));
    let arinsal = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/arinsal");
    assert!(arinsal.is_file(), "build arinsal-cli before this test");
    let actual = run(&arinsal);
    assert_eq!(actual, expected);
}
