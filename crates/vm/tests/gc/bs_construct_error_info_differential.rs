//! `bs_create_bin` error frames keep their saved error_info terms on the process heap.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::Term;
use std::process::Command;

const CHILD: &str = "ARINSAL_BS_ERROR_INFO_CHILD";
const MODULE: &str = "bs_construct_error_info_differential";
const SOURCE: &str = r#"
-module(bs_construct_error_info_differential).
-export([run/1]).
id(X) -> X.
run(Bits) ->
    try
        Bin = <<(id(<<0:Bits>>))/binary>>,
        _ = byte_size(Bin),
        erlang:error(should_fail)
    catch
        Class:Reason:Stack ->
            Frames = [Frame || Frame = {M, _, _, _} <- Stack,
                               M =:= bs_construct_error_info_differential],
            {Class, Reason, Frames}
    end.
"#;

#[test]
fn bit_sized_binary_construct_errors_match_otp() {
    if let Some(beam_path) = std::env::var_os(CHILD) {
        let bits: i64 = std::env::var("ARINSAL_BS_ERROR_INFO_BITS")
            .expect("child bit size")
            .parse()
            .expect("integer bit size");
        let mut vm = crate::common::node();
        crate::common::load_fresh(&mut vm, &std::fs::read(beam_path).expect("test BEAM"));
        let actual = vm
            .eval_scheduled(
                MODULE,
                "run",
                &[Term::small(bits).expect("small bit size")],
                1,
            )
            .unwrap_or_else(|error| panic!("run/1 with {bits} bits: {error}"));
        println!("RESULT:{:?}", actual.term);
        arinsal_vm::erts_exit(0);
    }

    let reference = RefErl::start().expect("OTP 29.1.1 is required for this test");
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile bitstring error module");
    reference
        .load(MODULE, &beam)
        .expect("load test module in OTP");
    let directory =
        std::env::temp_dir().join(format!("arinsal-bs-error-info-{}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("create test directory");
    let beam_path = directory.join(format!("{MODULE}.beam"));
    std::fs::write(&beam_path, beam).expect("write test BEAM");

    for bits in [1, 7, 1111, 100_000] {
        let expected = reference.call(MODULE, "run", &[OwnedTerm::Int(bits)]);
        let CallResult::Ok(expected) = expected else {
            panic!("OTP run/1 with {bits} bits failed: {expected:?}");
        };
        let output = Command::new(std::env::current_exe().expect("test executable"))
            .args(["bit_sized_binary_construct_errors_match_otp", "--nocapture"])
            .env(CHILD, &beam_path)
            .env("ARINSAL_BS_ERROR_INFO_BITS", bits.to_string())
            .output()
            .expect("run BeamAsm child");
        assert!(
            output.status.success(),
            "BeamAsm child failed for {bits} bits: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        let actual = stdout
            .lines()
            .find_map(|line| line.strip_prefix("RESULT:"))
            .unwrap_or_else(|| panic!("missing child result: {stdout}"));
        similar_asserts::assert_eq!(format!("{expected:?}"), actual, "bits={bits}");
    }
    let _ = std::fs::remove_dir_all(directory);
}
