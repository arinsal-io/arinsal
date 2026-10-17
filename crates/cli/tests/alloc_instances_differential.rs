//! `erlang:system_info({allocator, A})` reports as many instances as OTP 29.1.1 for the same
//! scheduler and dirty allocator instance flags.

use similar_asserts::assert_eq;
use std::process::Command;

const PROBE: &str = "As = erlang:system_info(alloc_util_allocators), \
    io:format(\"~s~n\", [string:join([atom_to_list(A) ++ \":\" ++ \
    integer_to_list(length([I || I = {instance, _, _} <- erlang:system_info({allocator, A})])) \
    || A <- As], \",\")]), halt().";

fn run(runtime: &str, flags: &[&str]) -> String {
    let mut command = if runtime == "erl" {
        arinsal_difftest::reference::erl().expect("reference OTP emulator")
    } else {
        let mut command = Command::new("timeout");
        command.arg("30").arg(env!("CARGO_BIN_EXE_arinsal"));
        command
    };
    let output = command
        .arg("-noshell")
        .args(flags)
        .args(["-eval", PROBE])
        .env("ERL_AFLAGS", "")
        .env("ERL_FLAGS", "")
        .env("ERL_ZFLAGS", "")
        .env("ERL_OTP29_FLAGS", "")
        .env("ERL_CRASH_DUMP", "/dev/null")
        .output()
        .expect("run probe");
    assert!(
        output.status.success(),
        "{runtime} {flags:?} exited {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("UTF-8 probe output")
}

fn compare(flags: &[&str]) {
    assert_eq!(run("arinsal", flags), run("erl", flags), "flags {flags:?}");
}

#[test]
fn one_scheduler_has_one_instance_per_scheduler_plus_global() {
    compare(&["+S", "1"]);
}

#[test]
fn four_schedulers() {
    compare(&["+S", "4"]);
}

#[test]
fn default_scheduler_count() {
    compare(&[]);
}

#[test]
fn dirty_allocator_instances_add_to_the_count() {
    compare(&["+S", "4:2", "+Mdai", "2"]);
    compare(&["+S", "3", "+SDcpu", "2", "+Mdai", "max"]);
}

#[test]
fn dirty_allocator_instances_are_limited_to_the_dirty_cpu_schedulers() {
    compare(&["+S", "2", "+SDcpu", "2", "+Mdai", "100"]);
}
