use arinsal_difftest::RefErl;
use arinsal_etf::OwnedTerm;
use std::path::Path;
use std::process::Command;

#[test]
fn standard_io_port_is_registered_and_orders_below_binary() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping ports differential test");
        return;
    };
    let module = "binary_ports_compat";
    let beam = reference
        .compile_named(
            module,
            "-module(binary_ports_compat). -export([run/0]). run() -> P = hd(erlang:ports()), {is_port(P), <<1>> > P}.",
            &[],
        )
        .expect("compile ports probe");
    let expected = reference
        .eval("P = hd(erlang:ports()), {is_port(P), <<1>> > P}")
        .unwrap();
    let mut vm = crate::common::node();
    crate::common::load_fresh(&mut vm, &beam);
    let actual = vm.eval_scheduled(module, "run", &[], 1).unwrap().term;
    similar_asserts::assert_eq!(expected, OwnedTerm::Tuple(vec![OwnedTerm::atom("true"); 2]));
    similar_asserts::assert_eq!(actual, expected);
}

fn compare_boot_ports(eval: &str, label: &str) {
    let arinsal = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/arinsal");
    assert!(arinsal.is_file(), "build arinsal-cli before this test");
    let run = |program: &Path| {
        let output = Command::new("timeout")
            .args(["--kill-after=3", "90"])
            .arg(program)
            .args(["-noshell", "-noinput", "-eval", eval])
            .output()
            .unwrap_or_else(|error| panic!("run {}: {error}", program.display()));
        assert!(
            output.status.success(),
            "{} {label} failed:\nstdout: {}\nstderr: {}",
            program.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .find(|line| line.starts_with("PTAB_PORTS "))
            .unwrap_or_else(|| panic!("{} omitted PTAB_PORTS output", program.display()))
            .to_owned()
    };
    let expected = run(Path::new("erl"));
    let actual = run(&arinsal);
    similar_asserts::assert_eq!(actual, expected, "{label}");
}

#[test]
fn ports_at_boot_match_erts() {
    if Command::new("erl").arg("-version").output().is_err() {
        eprintln!("erl unavailable; skipping boot ports differential test");
        return;
    }
    compare_boot_ports(
        "io:format(\"PTAB_PORTS ~p~n\", [erlang:ports()]), halt().",
        "ports/0 at boot",
    );
}

#[test]
fn ports_with_open_port_match_erts() {
    if Command::new("erl").arg("-version").output().is_err() {
        eprintln!("erl unavailable; skipping open ports differential test");
        return;
    }
    compare_boot_ports(
        "P = open_port({spawn, \"cat\"}, [stream]), L = erlang:ports(), io:format(\"PTAB_PORTS ~p~n\", [{lists:member(P, L), L}]), port_close(P), halt().",
        "ports/0 with an open port",
    );
}

#[test]
fn forker_port_info_matches_erts() {
    if Command::new("erl").arg("-version").output().is_err() {
        eprintln!("erl unavailable; skipping forker port differential test");
        return;
    }
    compare_boot_ports(
        "F = hd(erlang:ports()), io:format(\"PTAB_PORTS ~p~n\", [{erlang:port_info(F), [erlang:port_info(F, I) || I <- [queue_size, locking, parallelism, monitors, monitored_by, registered_name]]}]), halt().",
        "port_info of the forker port",
    );
}

#[test]
fn exit_status_through_forker_sigchld_matches_erts() {
    if Command::new("erl").arg("-version").output().is_err() {
        eprintln!("erl unavailable; skipping exit_status differential test");
        return;
    }
    compare_boot_ports(
        "process_flag(trap_exit, true), \
         R = fun(Cmd) -> P = open_port({spawn, Cmd}, [exit_status]), \
             (fun L(Acc) -> receive {P, {exit_status, S}} -> lists:reverse([S | Acc]); {P, {data, D}} -> L([D | Acc]) after 20000 -> timeout end end)([]) end, \
         Out = [R(C) || C <- [\"sh -c 'echo hi; exit 3'\", \"sh -c 'kill -9 $$'\", \"true\"]], \
         io:format(\"PTAB_PORTS ~p~n\", [{Out, hd(erlang:ports())}]), halt().",
        "exit_status reported through the forker's SigChld",
    );
}

#[test]
fn port_info_memory_and_locking_match_erts() {
    if Command::new("erl").arg("-version").output().is_err() {
        eprintln!("erl unavailable; skipping port_info memory differential test");
        return;
    }
    compare_boot_ports(
        "P = open_port({spawn, \"cat\"}, []), M1 = erlang:port_info(P, memory), \
         R = erlang:monitor(port, P), M2 = erlang:port_info(P, memory), \
         erlang:demonitor(R), M3 = erlang:port_info(P, memory), \
         unlink(P), M4 = erlang:port_info(P, memory), \
         F = hd(erlang:ports()), \
         io:format(\"PTAB_PORTS ~p~n\", [[M1, M2, M3, M4, erlang:port_info(F, memory), \
             erlang:port_info(F, locking), erlang:port_info(P, locking)]]), \
         port_close(P), halt().",
        "port_info memory and locking",
    );
}
